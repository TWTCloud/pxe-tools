// SPDX-License-Identifier: LGPL-3.0-only

use crate::{arg, install, param, parse_query, pxe::machine_for_mac, Params};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, Connection};
use std::net::Ipv4Addr;
use subtle::ConstantTimeEq;

pub(super) struct Session<'a> {
    pub machine: i64,
    pub action: i64,
    pub mac: &'a str,
    pub menu: &'static str,
    pub ip: Ipv4Addr,
}

impl Session<'_> {
    pub(super) fn issue(&self, db: &Connection) -> rusqlite::Result<String> {
        let token = crate::random_hex::<32>()
            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
        let message = format!(
            r#"PXE DHCP observed {{"mac":"{}","ip":"{}"}}"#,
            self.mac, self.ip
        );
        let observed: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM machine_events WHERE machine_id=?1
              AND checkpoint='pxe_boot_observed' AND message=?2 AND created_at>=datetime('now','-2 hours'))",
            params![self.machine,message], |row|row.get(0),
        )?;
        db.execute(
            "DELETE FROM boot_sessions WHERE machine_id=?1 AND action_id=?2 AND mac=?3
             AND default_menu=?4 AND selected_menu='agent_callback'",
            params![self.machine, self.action, self.mac, self.menu],
        )?;
        db.execute(
            "INSERT INTO boot_sessions(machine_id, action_id, mac, default_menu, selected_menu, token, client_ip)
             VALUES(?1,?2,?3,?4,'agent_callback',?5,?6)",
            params![self.machine,self.action,self.mac,self.menu,token,observed.then(||self.ip.to_string())],
        )?;
        Ok(token)
    }

    pub(super) fn authorized(&self, db: &Connection, token: &str) -> rusqlite::Result<bool> {
        if !install::valid_token(token) || machine_for_mac(db, self.mac)? != Some(self.machine) {
            return Ok(false);
        }
        let result = db.query_row(
            "SELECT token,client_ip FROM boot_sessions
              WHERE token=?1 AND machine_id=?2 AND action_id=?3 AND mac=?4
              AND default_menu=?5 AND selected_menu='agent_callback'
              AND COALESCE(selected_at,served_at)>=datetime('now','-24 hours')",
            params![token, self.machine, self.action, self.mac, self.menu],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        );
        let (actual, bound_ip) = match result {
            Ok(value) => value,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(false),
            Err(error) => return Err(error),
        };
        if !bool::from(actual.as_bytes().ct_eq(token.as_bytes()))
            || bound_ip.is_some_and(|bound| bound != self.ip.to_string())
        {
            return Ok(false);
        }
        Ok(db.execute(
            "UPDATE boot_sessions SET selected_at=CURRENT_TIMESTAMP WHERE token=?1",
            [token],
        )? == 1)
    }
}

pub(super) struct Input<'a> {
    pub query: Params,
    pub form: Params,
    pub body: &'a [u8],
}
impl<'a> Input<'a> {
    pub(super) fn new(query: &str, body: &'a [u8], is_form: bool) -> Self {
        Self {
            query: parse_query(query.as_bytes()),
            body,
            form: if is_form {
                parse_query(body)
            } else {
                Params::new()
            },
        }
    }
    pub(super) fn get(&self, key: &str) -> &str {
        arg(&self.query, key)
            .or_else(|| arg(&self.form, key))
            .unwrap_or_default()
    }
    pub(super) fn log_line(&self) -> String {
        let mut line = String::from_utf8_lossy(self.body).into_owned();
        if line.is_empty() {
            let base = param(&self.query, "b64");
            if !base.is_empty() {
                let mut raw = base.replace('-', "+").replace('_', "/");
                if matches!(raw.len() % 4, 2 | 3) {
                    raw.push_str(if raw.len() % 4 == 2 { "==" } else { "=" });
                }
                if let Ok(data) = STANDARD.decode(raw) {
                    line = String::from_utf8_lossy(&data).into_owned();
                }
            }
        }
        if line.is_empty() {
            line = param(&self.query, "line").to_owned();
        }
        if !line.is_empty() && !line.ends_with('\n') {
            line.push('\n');
        }
        line
    }
}
