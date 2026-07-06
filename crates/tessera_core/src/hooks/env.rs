//! Pre-fork environment vector builder.
//!
//! Builds the `envp` argument for `execve` in the **parent** before `fork`,
//! so the child path stays allocation-free. The executor freezes a static
//! whitelist (PATH/HOME/USER/LOGNAME/LANG), then injects every documented
//! `TESSERA_*` variable from [`HookVars`], then renders user-supplied
//! per-hook `env` templates (which may override whitelist keys).

use std::collections::BTreeMap;
use std::ffi::CString;

use crate::hooks::placeholder::TemplatePart;
use crate::hooks::result::HookError;
use crate::hooks::user::UserInfo;
use crate::hooks::validator::HookConfig;
use crate::hooks::vars::HookVars;

/// Default `PATH` for hook children. No `/usr/local/*` to keep the surface
/// small and predictable.
pub const DEFAULT_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// Build the `envp` vector for `execve`.
///
/// `run_as_user = None` means the child runs as root and `HOME=/root`,
/// `USER=root`, `LOGNAME=root`. With `Some(&UserInfo)` the home/user are
/// taken from the lookup result.
///
/// # Errors
///
/// * [`HookError::UnresolvedVar`] — a per-hook env template references a
///   placeholder that is `None` in `vars`.
/// * [`HookError::ChildSetup`] — an env value contains a NUL byte (rejected
///   by `CString::new`) or a template-render produced something invalid.
pub fn build_env_vector(
    hook: &HookConfig,
    vars: &HookVars,
    run_as_user: Option<&UserInfo>,
) -> Result<Vec<CString>, HookError> {
    let mut env: BTreeMap<String, String> = BTreeMap::new();

    // 1. Static whitelist.
    let (user_name, home) = match run_as_user {
        Some(u) => (u.name.clone(), u.home.to_string_lossy().into_owned()),
        None => ("root".to_string(), "/root".to_string()),
    };
    env.insert("PATH".into(), DEFAULT_PATH.into());
    env.insert("HOME".into(), home);
    env.insert("USER".into(), user_name.clone());
    env.insert("LOGNAME".into(), user_name);
    env.insert("LANG".into(), "C.UTF-8".into());

    // 2. TESSERA_* — empty string for None so hooks can rely on the
    //    keys being present.
    env.insert("TESSERA_STAGE".into(), hook.stage.to_string());
    env.insert(
        "TESSERA_USER".into(),
        vars.pam_user.clone().unwrap_or_default(),
    );
    env.insert(
        "TESSERA_SERVICE".into(),
        vars.pam_service.clone().unwrap_or_default(),
    );
    env.insert(
        "TESSERA_HOST_ID".into(),
        vars.host_id.clone().unwrap_or_default(),
    );
    env.insert(
        "TESSERA_HOST_ID_HASH".into(),
        vars.host_id_hash.clone().unwrap_or_default(),
    );
    env.insert(
        "TESSERA_HOST_ID_SOURCE".into(),
        vars.host_id_source.clone().unwrap_or_default(),
    );
    env.insert(
        "TESSERA_CERT_CN".into(),
        vars.cert_cn.clone().unwrap_or_default(),
    );
    env.insert(
        "TESSERA_CERT_SERIAL".into(),
        vars.cert_serial.clone().unwrap_or_default(),
    );
    env.insert(
        "TESSERA_USB_SERIAL".into(),
        vars.usb_serial.clone().unwrap_or_default(),
    );
    env.insert(
        "TESSERA_USB_VID_PID".into(),
        vars.usb_vid_pid.clone().unwrap_or_default(),
    );
    env.insert(
        "TESSERA_SESSION_ID".into(),
        vars.session_id.clone().unwrap_or_default(),
    );

    // 3. Custom env from hook config (may override whitelist).
    for (key, template) in &hook.env {
        let mut rendered = String::new();
        for part in template.parts() {
            match part {
                TemplatePart::Literal(s) => rendered.push_str(s),
                TemplatePart::Var(v) => match vars.resolve(*v) {
                    Some(s) => rendered.push_str(s),
                    None => return Err(HookError::UnresolvedVar { var: *v }),
                },
            }
        }
        env.insert(key.clone(), rendered);
    }

    // 4. Sanitise + encode `KEY=VALUE` as CString. Reject any value that
    //    contains control characters that could split the env entry across
    //    multiple lines (P1-L) — newlines, carriage returns, or other
    //    sub-0x20 control bytes (excluding tab 0x09 we still reject for
    //    safety; hooks should not legitimately need it inside env values).
    let mut out = Vec::with_capacity(env.len());
    for (k, v) in env {
        if let Some(reason) = forbidden_control_reason(&v) {
            return Err(HookError::EnvValueRejected {
                var: k.clone(),
                reason,
            });
        }
        let raw = format!("{k}={v}");
        let c = CString::new(raw).map_err(|_| HookError::ChildSetup {
            message: "env value contains NUL byte".into(),
        })?;
        out.push(c);
    }
    Ok(out)
}

/// Return `Some(reason)` if `v` contains a control character we refuse to
/// pass into the child env vector. Newline / CR are the headline risks
/// (env injection across `KEY=VALUE` lines); other sub-0x20 bytes are
/// rejected defensively.
fn forbidden_control_reason(v: &str) -> Option<&'static str> {
    for &b in v.as_bytes() {
        match b {
            b'\n' => return Some("contains newline (0x0A)"),
            b'\r' => return Some("contains carriage return (0x0D)"),
            // 0x00 is rejected later by CString::new, but it is also a
            // control byte; flag here for a cleaner error.
            0 => return Some("contains NUL byte"),
            // Reject every other C0 control byte (incl. tab 0x09).
            x if x < 0x20 => return Some("contains control byte (< 0x20)"),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::hooks::placeholder::Template;
    use crate::hooks::stage::HookStage;
    use crate::hooks::validator::{OnFailure, RunAs};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;

    fn dummy_hook(stage: HookStage, env: BTreeMap<String, Template>) -> HookConfig {
        HookConfig {
            stage,
            command: vec!["/bin/true".into()],
            timeout: Duration::from_secs(5),
            on_failure: OnFailure::Abort,
            run_as: RunAs::Root,
            env,
        }
    }

    fn collect(env: &[CString]) -> Vec<String> {
        env.iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect()
    }

    fn entry<'a>(env: &'a [String], key: &str) -> Option<&'a str> {
        env.iter().find_map(|s| s.strip_prefix(&format!("{key}=")))
    }

    #[test]
    fn whitelist_present_for_root() {
        let hook = dummy_hook(HookStage::PreAuth, BTreeMap::new());
        let vars = HookVars::empty().with_pam_user("u").with_pam_service("s");
        let envv = build_env_vector(&hook, &vars, None).expect("build env");
        let envv = collect(&envv);
        assert_eq!(entry(&envv, "PATH"), Some(DEFAULT_PATH));
        assert_eq!(entry(&envv, "HOME"), Some("/root"));
        assert_eq!(entry(&envv, "USER"), Some("root"));
        assert_eq!(entry(&envv, "LOGNAME"), Some("root"));
        assert_eq!(entry(&envv, "LANG"), Some("C.UTF-8"));
    }

    #[test]
    fn whitelist_uses_user_home_when_run_as_user() {
        let hook = dummy_hook(HookStage::SessionOpen, BTreeMap::new());
        let user = UserInfo {
            name: "alice".into(),
            uid: 1001,
            gid: 1001,
            groups: vec![1001],
            home: PathBuf::from("/home/alice"),
        };
        let vars = HookVars::empty().with_pam_user("alice");
        let envv = build_env_vector(&hook, &vars, Some(&user)).expect("build env");
        let envv = collect(&envv);
        assert_eq!(entry(&envv, "HOME"), Some("/home/alice"));
        assert_eq!(entry(&envv, "USER"), Some("alice"));
        assert_eq!(entry(&envv, "LOGNAME"), Some("alice"));
    }

    #[test]
    fn tessera_set_for_some_and_empty_for_none() {
        let hook = dummy_hook(HookStage::PostAuthSuccess, BTreeMap::new());
        let vars = HookVars::empty()
            .with_pam_user("alice")
            .with_pam_service("login")
            .with_host_id("hid")
            .with_cert_cn("CN");
        let envv = build_env_vector(&hook, &vars, None).expect("build env");
        let envv = collect(&envv);
        assert_eq!(entry(&envv, "TESSERA_USER"), Some("alice"));
        assert_eq!(entry(&envv, "TESSERA_SERVICE"), Some("login"));
        assert_eq!(entry(&envv, "TESSERA_HOST_ID"), Some("hid"));
        assert_eq!(entry(&envv, "TESSERA_CERT_CN"), Some("CN"));
        assert_eq!(entry(&envv, "TESSERA_HOST_ID_HASH"), Some(""));
        assert_eq!(entry(&envv, "TESSERA_HOST_ID_SOURCE"), Some(""));
        assert_eq!(entry(&envv, "TESSERA_CERT_SERIAL"), Some(""));
        assert_eq!(entry(&envv, "TESSERA_USB_SERIAL"), Some(""));
        assert_eq!(entry(&envv, "TESSERA_USB_VID_PID"), Some(""));
        assert_eq!(entry(&envv, "TESSERA_SESSION_ID"), Some(""));
        assert_eq!(entry(&envv, "TESSERA_STAGE"), Some("post_auth_success"));
    }

    #[test]
    fn custom_env_renders_template() {
        let mut env = BTreeMap::new();
        env.insert("MY_USER".into(), Template::parse("u=${pam_user}").unwrap());
        let hook = dummy_hook(HookStage::PreAuth, env);
        let vars = HookVars::empty().with_pam_user("bob");
        let envv = build_env_vector(&hook, &vars, None).expect("build env");
        let envv = collect(&envv);
        assert_eq!(entry(&envv, "MY_USER"), Some("u=bob"));
    }

    #[test]
    fn custom_env_overrides_whitelist() {
        let mut env = BTreeMap::new();
        env.insert("PATH".into(), Template::parse("/usr/local/bin").unwrap());
        let hook = dummy_hook(HookStage::PreAuth, env);
        let vars = HookVars::empty().with_pam_user("u").with_pam_service("s");
        let envv = build_env_vector(&hook, &vars, None).expect("build env");
        let envv = collect(&envv);
        assert_eq!(entry(&envv, "PATH"), Some("/usr/local/bin"));
        // Make sure no duplicate PATH= entry.
        let count = envv.iter().filter(|s| s.starts_with("PATH=")).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn unresolved_var_returns_error() {
        let mut env = BTreeMap::new();
        // post_auth_success allows cert_cn, but if vars.cert_cn is None we
        // fail at runtime.
        env.insert("X".into(), Template::parse("cn=${cert_cn}").unwrap());
        let hook = dummy_hook(HookStage::PostAuthSuccess, env);
        let vars = HookVars::empty().with_pam_user("u");
        let r = build_env_vector(&hook, &vars, None);
        assert!(matches!(
            r,
            Err(HookError::UnresolvedVar {
                var: crate::hooks::PlaceholderVar::CertCn
            })
        ));
    }

    #[test]
    fn newline_in_cert_cn_is_rejected() {
        // P1-L: a CN that smuggles a newline must be rejected before the
        // env vector is finalised — otherwise it would inject extra
        // `KEY=VALUE` lines into the child process.
        let hook = dummy_hook(HookStage::PostAuthSuccess, BTreeMap::new());
        let vars = HookVars::empty()
            .with_pam_user("u")
            .with_cert_cn("alice\nFOO=evil");
        let r = build_env_vector(&hook, &vars, None);
        assert!(
            matches!(
                r,
                Err(HookError::EnvValueRejected { ref var, .. }) if var == "TESSERA_CERT_CN"
            ),
            "got {r:?}"
        );
    }

    #[test]
    fn carriage_return_in_custom_env_is_rejected() {
        let mut env = BTreeMap::new();
        env.insert("MY_VAR".into(), Template::parse("line1\rline2").unwrap());
        let hook = dummy_hook(HookStage::PreAuth, env);
        let vars = HookVars::empty().with_pam_user("u");
        let r = build_env_vector(&hook, &vars, None);
        assert!(
            matches!(
                r,
                Err(HookError::EnvValueRejected { ref var, .. }) if var == "MY_VAR"
            ),
            "got {r:?}"
        );
    }

    #[test]
    fn escape_dollar_sign_in_template_yields_literal() {
        let mut env = BTreeMap::new();
        env.insert("LIT".into(), Template::parse("$$").unwrap());
        let hook = dummy_hook(HookStage::PreAuth, env);
        let vars = HookVars::empty().with_pam_user("u");
        let envv = build_env_vector(&hook, &vars, None).expect("build env");
        let envv = collect(&envv);
        assert_eq!(entry(&envv, "LIT"), Some("$"));
    }
}
