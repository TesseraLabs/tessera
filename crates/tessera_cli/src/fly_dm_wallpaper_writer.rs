//! Wallpaper writer: bakes the resolved host identity into a banner over
//! the fly-dm login-screen background image.
//!
//! Rationale: on Astra МКЦ-3 (production ATM) the `fly-modern` theme
//! hard-codes "Усиленный уровень защищенности" into the headline place
//! from `fly-dm_greet_modern.mo`; the `GreetString` xdmcp setting is
//! ignored. The only reliable surface for showing `host_id` to the
//! operator is the JPG/PNG file pointed at by
//! `/etc/X11/fly-dm/fly-modern/settings.ini` `[background].path`.
//!
//! This module never edits `settings.ini` (operator / ansible owns that
//! file). It only generates the image file at
//! `[fly_dm_greeter].wallpaper_target`, preserving the original as
//! `wallpaper_backup` on first run so subsequent regenerations always
//! start from a pristine source even if an apt upgrade restored the
//! stock image.

// Пиксельная математика рендера: координаты и каналы ограничены размерами
// изображения (< 2^23), потери точности/знака здесь невозможны по построению.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::manual_midpoint
)]

use std::fs;
use std::io;
use std::path::PathBuf;

use ab_glyph::{point, Font, FontArc, PxScale, ScaleFont};
use image::{DynamicImage, ImageBuffer, Rgba};

use tessera_core::config::validated::{FlyDmGreeterSection, Gravity};
use tessera_core::host_identity::ResolvedHostId;

/// Errors produced by [`update`]. The daemon log-and-continues on any of
/// these — a broken wallpaper must not block authentication.
#[derive(Debug, thiserror::Error)]
pub enum WriterError {
    /// I/O failure against a concrete path.
    #[error("io error on {path}: {source}")]
    Io {
        /// Path involved (best effort).
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// `image` could not decode the source file.
    #[error("image decode failed for {path}: {source}")]
    ImageDecode {
        /// Path of the offending file.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: image::ImageError,
    },
    /// `image` could not encode the output file.
    #[error("image encode failed for {path}: {source}")]
    ImageEncode {
        /// Path of the offending file.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: image::ImageError,
    },
    /// `ab_glyph` could not parse the configured font.
    #[error("font load failed for {path}: {reason}")]
    FontLoad {
        /// Path of the offending font file.
        path: PathBuf,
        /// Human-readable cause.
        reason: String,
    },
}

impl WriterError {
    fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Outcome of a single [`update`] invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// `update_wallpaper = false` — no FS work attempted.
    Disabled,
    /// Neither `wallpaper_backup` nor `wallpaper_target` exists: we have
    /// no source image to start from. Silent skip — the host probably
    /// does not run fly-dm at all (server / sshd-only).
    NoBackupSourceNoTarget,
    /// File was (re)written. `backed_up = true` iff a backup was just
    /// created (first run on a previously-stock host).
    Wrote {
        /// True iff this call copied target → backup.
        backed_up: bool,
    },
}

/// Run the wallpaper update according to `cfg`.
///
/// Semantics:
/// 1. `update_wallpaper = false` → [`UpdateOutcome::Disabled`].
/// 2. Neither backup nor target exists → [`UpdateOutcome::NoBackupSourceNoTarget`].
/// 3. Otherwise: if no backup exists, copy `wallpaper_target` →
///    `wallpaper_backup`. Then open backup, render text overlay,
///    atomically write the result to `wallpaper_target`.
pub fn update(
    cfg: &FlyDmGreeterSection,
    resolved: &ResolvedHostId,
) -> Result<UpdateOutcome, WriterError> {
    if !cfg.update_wallpaper {
        return Ok(UpdateOutcome::Disabled);
    }

    let backup_exists = cfg.wallpaper_backup.exists();
    let target_exists = cfg.wallpaper_target.exists();
    let mut backed_up_now = false;
    if !backup_exists {
        if !target_exists {
            return Ok(UpdateOutcome::NoBackupSourceNoTarget);
        }
        if let Some(parent) = cfg.wallpaper_backup.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| WriterError::io(parent.to_path_buf(), e))?;
            }
        }
        fs::copy(&cfg.wallpaper_target, &cfg.wallpaper_backup)
            .map_err(|e| WriterError::io(cfg.wallpaper_backup.clone(), e))?;
        backed_up_now = true;
    }

    let img = image::open(&cfg.wallpaper_backup).map_err(|e| WriterError::ImageDecode {
        path: cfg.wallpaper_backup.clone(),
        source: e,
    })?;

    let font_bytes =
        fs::read(&cfg.wallpaper_font).map_err(|e| WriterError::io(cfg.wallpaper_font.clone(), e))?;
    let font = FontArc::try_from_vec(font_bytes).map_err(|e| WriterError::FontLoad {
        path: cfg.wallpaper_font.clone(),
        reason: e.to_string(),
    })?;

    let template = if is_russian_locale() {
        &cfg.template_ru
    } else {
        &cfg.template_en
    };
    let text = substitute(template, resolved, &local_hostname());

    let mut rgba = img.to_rgba8();
    draw_text(
        &mut rgba,
        &font,
        cfg.wallpaper_font_size as f32,
        &text,
        cfg.wallpaper_gravity,
        cfg.wallpaper_offset_x,
        cfg.wallpaper_offset_y,
        cfg.wallpaper_text_color,
    );

    let dyn_img = DynamicImage::ImageRgba8(rgba);
    let target_parent = cfg.wallpaper_target.parent().ok_or_else(|| {
        WriterError::io(
            cfg.wallpaper_target.clone(),
            io::Error::new(io::ErrorKind::InvalidInput, "no parent dir"),
        )
    })?;
    if !target_parent.as_os_str().is_empty() && !target_parent.exists() {
        fs::create_dir_all(target_parent)
            .map_err(|e| WriterError::io(target_parent.to_path_buf(), e))?;
    }
    let tmp = target_parent.join(format!(
        ".tessera_wallpaper.{}.tmp.jpg",
        std::process::id()
    ));
    // Force JPEG output regardless of target extension by writing to a .jpg
    // tmp file; the rename below moves it onto the configured target path.
    dyn_img
        .save(&tmp)
        .map_err(|e| WriterError::ImageEncode {
            path: tmp.clone(),
            source: e,
        })?;
    fs::rename(&tmp, &cfg.wallpaper_target)
        .map_err(|e| WriterError::io(cfg.wallpaper_target.clone(), e))?;

    Ok(UpdateOutcome::Wrote {
        backed_up: backed_up_now,
    })
}

fn is_russian_locale() -> bool {
    let lang = std::env::var("LC_MESSAGES")
        .or_else(|_| std::env::var("LANG"))
        .unwrap_or_default();
    lang.to_lowercase().starts_with("ru")
}

fn local_hostname() -> String {
    // Prefer the kernel-reported hostname via /proc (Linux) or fall back
    // to /etc/hostname. We deliberately avoid `libc::gethostname` here
    // because the crate denies `unsafe_code`; both files are tiny and
    // synchronously readable on every supported deployment target.
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(s) = fs::read_to_string(path) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
}

fn substitute(template: &str, resolved: &ResolvedHostId, hostname: &str) -> String {
    let host_id_short = resolved.hash_prefix();
    let source = resolved.source_kind.to_string();
    template
        .replace("{host_id_short}", host_id_short)
        .replace("{source}", &source)
        .replace("%n", hostname)
}

#[allow(clippy::too_many_arguments)]
fn draw_text(
    img: &mut ImageBuffer<Rgba<u8>, Vec<u8>>,
    font: &FontArc,
    size: f32,
    text: &str,
    gravity: Gravity,
    offset_x: i32,
    offset_y: i32,
    color: [u8; 4],
) {
    let scale = PxScale::from(size);
    let scaled = font.as_scaled(scale);
    let glyphs: Vec<_> = text.chars().map(|c| scaled.scaled_glyph(c)).collect();

    let mut text_width = 0.0f32;
    let mut last: Option<ab_glyph::GlyphId> = None;
    for g in &glyphs {
        if let Some(prev) = last {
            text_width += scaled.kern(prev, g.id);
        }
        text_width += scaled.h_advance(g.id);
        last = Some(g.id);
    }
    let ascent = scaled.ascent();
    let descent = scaled.descent();
    let text_height = ascent - descent;

    let (img_w, img_h) = (img.width(), img.height());
    let (anchor_x, anchor_y) = match gravity {
        Gravity::North => ((img_w as f32 - text_width) / 2.0, ascent),
        Gravity::South => ((img_w as f32 - text_width) / 2.0, img_h as f32 - descent.abs()),
        Gravity::East => (img_w as f32 - text_width, (img_h as f32 + text_height) / 2.0),
        Gravity::West => (0.0, (img_h as f32 + text_height) / 2.0),
        Gravity::Center => (
            (img_w as f32 - text_width) / 2.0,
            (img_h as f32 + text_height) / 2.0,
        ),
    };
    let start_x = anchor_x + offset_x as f32;
    // For south gravity, positive offset_y moves text up (away from edge),
    // matching ImageMagick `-gravity south -annotate +X+Y` behaviour where
    // Y is the inset from the bottom edge.
    let start_y = match gravity {
        Gravity::South | Gravity::East | Gravity::West | Gravity::Center => {
            anchor_y - offset_y as f32
        }
        Gravity::North => anchor_y + offset_y as f32,
    };

    let mut cursor_x = start_x;
    let mut last: Option<ab_glyph::GlyphId> = None;
    for g in glyphs {
        let id = g.id;
        if let Some(prev) = last {
            cursor_x += scaled.kern(prev, id);
        }
        last = Some(id);
        let advance = scaled.h_advance(id);

        let mut positioned = g;
        positioned.position = point(cursor_x, start_y);
        if let Some(outlined) = font.outline_glyph(positioned) {
            let bb = outlined.px_bounds();
            outlined.draw(|x, y, v| {
                let px = bb.min.x as i32 + x as i32;
                let py = bb.min.y as i32 + y as i32;
                if px >= 0 && py >= 0 && (px as u32) < img_w && (py as u32) < img_h {
                    let alpha_f = v * (color[3] as f32 / 255.0);
                    let alpha = (alpha_f.clamp(0.0, 1.0) * 255.0) as u8;
                    if alpha > 0 {
                        let pixel = img.get_pixel_mut(px as u32, py as u32);
                        let inv = 255 - alpha as u16;
                        let a = alpha as u16;
                        pixel[0] = ((color[0] as u16 * a + pixel[0] as u16 * inv) / 255) as u8;
                        pixel[1] = ((color[1] as u16 * a + pixel[1] as u16 * inv) / 255) as u8;
                        pixel[2] = ((color[2] as u16 * a + pixel[2] as u16 * inv) / 255) as u8;
                        pixel[3] = 255;
                    }
                }
            });
        }
        cursor_x += advance;
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgba};
    use tessera_core::host_identity::HostIdSourceKind;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    // DejaVu Sans Bold ships with Astra and most dev workstations; tests
    // try a list of candidate paths and fall back to skipping the test
    // when no TTF is found locally so CI on a minimal box does not break.
    fn find_test_font() -> Option<PathBuf> {
        let candidates = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
            "/System/Library/Fonts/Geneva.ttf",
        ];
        candidates
            .iter()
            .map(PathBuf::from)
            .find(|p| p.exists())
    }

    fn fixture_resolved(kind: HostIdSourceKind, hash_hex: &str) -> ResolvedHostId {
        ResolvedHostId {
            source_kind: kind,
            raw: "raw-value".to_string(),
            normalized: "raw-value".to_string(),
            hash_hex: hash_hex.to_string(),
        }
    }

    fn make_cfg(target: PathBuf, backup: PathBuf, font: PathBuf, enabled: bool) -> FlyDmGreeterSection {
        FlyDmGreeterSection {
            update_wallpaper: enabled,
            wallpaper_target: target,
            wallpaper_backup: backup,
            wallpaper_font: font,
            wallpaper_font_size: 16,
            wallpaper_text_color: [0, 0, 0, 255],
            wallpaper_gravity: Gravity::South,
            wallpaper_offset_x: 0,
            wallpaper_offset_y: 4,
            template_ru: "Банкомат %n host_id={host_id_short} ({source})".to_string(),
            template_en: "ATM %n host_id={host_id_short} ({source})".to_string(),
        }
    }

    fn write_white_jpeg(path: &Path, w: u32, h: u32) {
        let buf: ImageBuffer<Rgba<u8>, Vec<u8>> =
            ImageBuffer::from_pixel(w, h, Rgba([255, 255, 255, 255]));
        DynamicImage::ImageRgba8(buf).save(path).expect("save");
    }

    #[test]
    fn substitute_replaces_host_id_short_source_n() {
        let r = fixture_resolved(HostIdSourceKind::DmiBoardSerial, "abc12345deadbeef");
        let out = substitute(
            "ATM %n host_id={host_id_short} ({source})",
            &r,
            "astra184",
        );
        assert_eq!(out, "ATM astra184 host_id=abc12345 (dmi_board_serial)");
    }

    #[test]
    fn update_disabled_returns_disabled_and_does_not_write() {
        let tmp = tempdir().expect("tempdir");
        let target = tmp.path().join("wp.jpg");
        let backup = tmp.path().join("wp.orig.jpg");
        let font = PathBuf::from("/nonexistent/font.ttf");
        let cfg = make_cfg(target.clone(), backup.clone(), font, false);
        let r = fixture_resolved(HostIdSourceKind::Hostname, "abcdefgh");
        let outcome = update(&cfg, &r).expect("ok");
        assert_eq!(outcome, UpdateOutcome::Disabled);
        assert!(!target.exists());
        assert!(!backup.exists());
    }

    #[test]
    fn update_no_source_when_neither_backup_nor_target_exists() {
        let tmp = tempdir().expect("tempdir");
        let target = tmp.path().join("wp.jpg");
        let backup = tmp.path().join("wp.orig.jpg");
        let font = PathBuf::from("/nonexistent/font.ttf");
        let cfg = make_cfg(target.clone(), backup.clone(), font, true);
        let r = fixture_resolved(HostIdSourceKind::Hostname, "abcdefgh");
        let outcome = update(&cfg, &r).expect("ok");
        assert_eq!(outcome, UpdateOutcome::NoBackupSourceNoTarget);
        assert!(!target.exists());
        assert!(!backup.exists());
    }

    #[test]
    fn update_first_run_creates_backup_from_target_and_writes_new_target() {
        let Some(font) = find_test_font() else {
            eprintln!("skipping: no test font on this host");
            return;
        };
        let tmp = tempdir().expect("tempdir");
        let target = tmp.path().join("wp.jpg");
        let backup = tmp.path().join("backup/wp.orig.jpg");
        write_white_jpeg(&target, 200, 80);
        let cfg = make_cfg(target.clone(), backup.clone(), font, true);
        let r = fixture_resolved(HostIdSourceKind::DmiBoardSerial, "abc12345deadbeef");
        let outcome = update(&cfg, &r).expect("ok");
        assert_eq!(outcome, UpdateOutcome::Wrote { backed_up: true });
        assert!(backup.exists(), "backup must be created");
        assert!(target.exists());
        // Re-decode the new target to confirm it is a valid image.
        let _ = image::open(&target).expect("re-decode target");
    }

    #[test]
    fn update_subsequent_run_keeps_backup_intact_and_rewrites_target() {
        let Some(font) = find_test_font() else {
            eprintln!("skipping: no test font on this host");
            return;
        };
        let tmp = tempdir().expect("tempdir");
        let target = tmp.path().join("wp.jpg");
        let backup = tmp.path().join("wp.orig.jpg");
        write_white_jpeg(&target, 200, 80);
        let cfg = make_cfg(target.clone(), backup.clone(), font, true);
        let r = fixture_resolved(HostIdSourceKind::DmiBoardSerial, "abc12345deadbeef");

        let o1 = update(&cfg, &r).expect("first run");
        assert_eq!(o1, UpdateOutcome::Wrote { backed_up: true });
        let backup_after_first = fs::read(&backup).expect("read backup");

        // Pretend apt upgrade trampled the target — overwrite with a
        // different image.
        write_white_jpeg(&target, 200, 80);
        // Re-run: backup must NOT change; target must be regenerated.
        let o2 = update(&cfg, &r).expect("second run");
        assert_eq!(o2, UpdateOutcome::Wrote { backed_up: false });
        let backup_after_second = fs::read(&backup).expect("read backup");
        assert_eq!(
            backup_after_first, backup_after_second,
            "backup must be byte-identical across runs"
        );
    }

    #[test]
    fn draw_text_writes_some_dark_pixels_at_south_gravity() {
        let Some(font_path) = find_test_font() else {
            eprintln!("skipping: no test font on this host");
            return;
        };
        let bytes = fs::read(&font_path).expect("read font");
        let font = FontArc::try_from_vec(bytes).expect("parse font");
        let mut img: ImageBuffer<Rgba<u8>, Vec<u8>> =
            ImageBuffer::from_pixel(200, 80, Rgba([255, 255, 255, 255]));
        draw_text(
            &mut img,
            &font,
            24.0,
            "HOST=abcd1234",
            Gravity::South,
            0,
            4,
            [0, 0, 0, 255],
        );
        let dark = img
            .pixels()
            .filter(|p| p[0] < 200 && p[1] < 200 && p[2] < 200)
            .count();
        assert!(dark > 10, "expected some dark text pixels, got {dark}");
    }
}
