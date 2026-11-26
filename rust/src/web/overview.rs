// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    access::{Account, Permission},
    admin::escape,
    ui::{page, ConsoleSection},
    ErrorBox, Reply,
};
use crate::setting;
use rusqlite::Connection;
use std::{fmt::Write, net::Ipv4Addr};

pub(super) const ROUTE: &str = "/overview";

pub(super) fn show(
    db: &Connection,
    account: &Account,
    bound: Option<Ipv4Addr>,
) -> Result<Reply, ErrorBox> {
    let address = setting(db, "pxe_ip")?;
    let interface = setting(db, "pxe_interface")?;
    let subnet = setting(db, "pxe_subnet")?;
    let enabled = setting(db, "pxe_enabled")?;
    let proxy = setting(db, "dhcp_proxy_enabled")?;
    let active = enabled == "on" || (enabled.is_empty() && !address.is_empty());
    let role = match (active, proxy.as_str()) {
        (false, _) => "Console seule",
        (true, "on") => "PXE avec proxy DHCP",
        (true, _) => "PXE avec DHCP externe",
    };
    let listener = match (active, bound) {
        (true, Some(ip)) if ip.to_string() == address => "Adresse PXE en écoute",
        (false, None) => "Démarrage réseau désactivé",
        _ => "L’écoute actuelle diffère de la configuration enregistrée",
    };
    let mut html = String::from(
        r#"<div class="panel-grid"><section class="panel"><h2>Réseau PXE</h2><dl class="wizard-summary">"#,
    );
    for (key, value) in [
        ("Mode", role),
        ("Interface", interface.as_str()),
        ("Adresse IPv4", address.as_str()),
        ("Sous-réseau", subnet.as_str()),
        ("Écoute HTTP", listener),
    ] {
        write!(html, "<dt>{key}</dt><dd>")?;
        escape(&mut html, if value.is_empty() { "—" } else { value });
        html.push_str("</dd>");
    }
    html.push_str("</dl>");
    if account.admin {
        html.push_str(r#"<p><a href="/settings/network">Modifier le réseau</a></p>"#);
    }
    html.push_str("</section>");
    if account.allows(Permission::DevicesRead) {
        let count: u64 = db.query_row("SELECT COUNT(*) FROM machines", [], |row| row.get(0))?;
        write!(
            html,
            r#"<section class="panel"><h2>Inventaire</h2><p>{count} appareil(s) enregistré(s)</p><a href="/admin/inventaire">Ouvrir l’inventaire</a></section>"#
        )?;
    }
    if account.allows(Permission::ImagesRead) {
        let count: u64 = db.query_row(
            "SELECT COUNT(*) FROM os_images WHERE enabled=1 AND status='downloaded'",
            [],
            |row| row.get(0),
        )?;
        write!(
            html,
            r#"<section class="panel"><h2>Images PXE</h2><p>{count} image(s) active(s) téléchargée(s)</p><a href="/settings/images">Ouvrir les images</a></section>"#
        )?;
    }
    if account.allows(Permission::ActivityRead) {
        let active: u64 = db.query_row(
            "SELECT COUNT(*) FROM actions WHERE status IN ('pending','running')",
            [],
            |row| row.get(0),
        )?;
        write!(
            html,
            r#"<section class="panel"><h2>Activité</h2><p>{active} action(s) en attente ou en cours</p><a href="/activity">Ouvrir l’activité</a></section>"#
        )?;
    }
    html.push_str("</div>");
    Ok(page(ConsoleSection::Overview, "Vue d’ensemble", &html))
}
