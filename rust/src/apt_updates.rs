// SPDX-License-Identifier: LGPL-3.0-only

use crate::setting;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, env, error::Error, process::Command};

pub(crate) const KEY: &str = "apt_console_update";
type ErrorBox = Box<dyn Error + Send + Sync>;

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct State {
    pub phase: Phase,
    pub installed: BTreeMap<String, String>,
    pub candidates: BTreeMap<String, String>,
    pub checked_at: i64,
    pub step: Option<Step>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Step {
    Verify,
    Download,
    Apply,
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    #[default]
    Idle,
    Queued,
    Checking,
    InstallQueued,
    Installing,
    Available,
    UpToDate,
    Installed,
    Busy,
    Changed,
    Failed,
    Unavailable,
}

impl Phase {
    pub fn pending(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Checking | Self::InstallQueued | Self::Installing
        )
    }
}

impl State {
    pub(crate) fn read(db: &Connection) -> Result<Self, ErrorBox> {
        let stored = setting(db, KEY)?;
        if stored.is_empty() {
            return Ok(Self::default());
        }
        Ok(serde_json::from_str(&stored)?)
    }
}

pub(crate) fn enabled() -> bool {
    cfg!(target_os = "linux")
        && env::var("PXE_APT_CONSOLE_UPDATES").as_deref() == Ok("1")
        && env::var("PXE_SERVICE_MANAGER").as_deref() == Ok("systemd")
}

pub(crate) fn dispatch(db: &Connection, startup: bool) -> Result<bool, ErrorBox> {
    if !enabled() {
        return Ok(false);
    }
    let phase = State::read(db)?.phase;
    if matches!(phase, Phase::Queued | Phase::InstallQueued) || (startup && phase.pending()) {
        let status = Command::new("/usr/bin/systemctl")
            .args(["start", "--no-block", "pxe-tools-apt-update.service"])
            .status()?;
        if !status.success() {
            return Err("Impossible de démarrer le service de mise à jour APT".into());
        }
    }
    // Let the native package lifecycle quiesce the worker before replacing it.
    Ok(matches!(phase, Phase::InstallQueued | Phase::Installing))
}
