//! Hook placeholder templates.

use std::str::FromStr;

use crate::Error;

/// Placeholder variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlaceholderVar {
    /// PAM user.
    PamUser,
    /// PAM service.
    PamService,
    /// Host id.
    HostId,
    /// Host id hash.
    HostIdHash,
    /// Host id source.
    HostIdSource,
    /// Certificate CN.
    CertCn,
    /// Certificate serial.
    CertSerial,
    /// USB serial.
    UsbSerial,
    /// USB VID/PID.
    UsbVidPid,
    /// Session id.
    SessionId,
}

impl FromStr for PlaceholderVar {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pam_user" => Ok(Self::PamUser),
            "pam_service" => Ok(Self::PamService),
            "host_id" => Ok(Self::HostId),
            "host_id_hash" => Ok(Self::HostIdHash),
            "host_id_source" => Ok(Self::HostIdSource),
            "cert_cn" => Ok(Self::CertCn),
            "cert_serial" => Ok(Self::CertSerial),
            "usb_serial" => Ok(Self::UsbSerial),
            "usb_vid_pid" => Ok(Self::UsbVidPid),
            "session_id" => Ok(Self::SessionId),
            _ => Err(Error::ConfigInvalid {
                reason: format!("unknown placeholder: {s}"),
            }),
        }
    }
}

/// Template part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplatePart {
    /// Literal text.
    Literal(String),
    /// Variable.
    Var(PlaceholderVar),
}

/// Parsed template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    parts: Vec<TemplatePart>,
}

impl Template {
    /// Parse a template.
    pub fn parse(input: &str) -> Result<Self, Error> {
        let mut chars = input.chars().peekable();
        let mut literal = String::new();
        let mut parts = Vec::new();
        while let Some(ch) = chars.next() {
            if ch != '$' {
                literal.push(ch);
                continue;
            }
            match chars.peek().copied() {
                Some('$') => {
                    let _ = chars.next();
                    literal.push('$');
                }
                Some('{') => {
                    let _ = chars.next();
                    if !literal.is_empty() {
                        parts.push(TemplatePart::Literal(std::mem::take(&mut literal)));
                    }
                    let mut name = String::new();
                    loop {
                        match chars.next() {
                            Some('}') => break,
                            Some(c) => name.push(c),
                            None => {
                                return Err(Error::ConfigInvalid {
                                    reason: "unclosed placeholder".to_string(),
                                });
                            }
                        }
                    }
                    if name.is_empty() {
                        return Err(Error::ConfigInvalid {
                            reason: "empty placeholder".to_string(),
                        });
                    }
                    parts.push(TemplatePart::Var(name.parse()?));
                }
                _ => literal.push('$'),
            }
        }
        if !literal.is_empty() || parts.is_empty() {
            parts.push(TemplatePart::Literal(literal));
        }
        Ok(Self { parts })
    }

    /// Return parsed parts.
    pub fn parts(&self) -> &[TemplatePart] {
        &self.parts
    }

    /// Render with a resolver.
    pub fn render<F>(&self, resolve: F) -> Result<String, Error>
    where
        F: Fn(&PlaceholderVar) -> Option<String>,
    {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                TemplatePart::Literal(s) => out.push_str(s),
                TemplatePart::Var(v) => {
                    out.push_str(&resolve(v).ok_or_else(|| Error::ConfigInvalid {
                        reason: format!("missing placeholder value: {v:?}"),
                    })?);
                }
            }
        }
        Ok(out)
    }
}
