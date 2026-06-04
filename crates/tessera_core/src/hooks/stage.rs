//! Hook stage enum.

use std::fmt;
use std::str::FromStr;

use crate::Error;

/// Hook execution stage.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookStage {
    /// Pre auth.
    #[default]
    PreAuth,
    /// Post auth success.
    PostAuthSuccess,
    /// Session open.
    SessionOpen,
    /// Session close.
    SessionClose,
    /// USB removed.
    UsbRemoved,
}

impl fmt::Display for HookStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PreAuth => "pre_auth",
            Self::PostAuthSuccess => "post_auth_success",
            Self::SessionOpen => "session_open",
            Self::SessionClose => "session_close",
            Self::UsbRemoved => "usb_removed",
        })
    }
}

impl FromStr for HookStage {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pre_auth" => Ok(Self::PreAuth),
            "post_auth_success" => Ok(Self::PostAuthSuccess),
            "session_open" => Ok(Self::SessionOpen),
            "session_close" => Ok(Self::SessionClose),
            "usb_removed" => Ok(Self::UsbRemoved),
            _ => Err(Error::ConfigInvalid {
                reason: format!("invalid hook stage: {s}"),
            }),
        }
    }
}
