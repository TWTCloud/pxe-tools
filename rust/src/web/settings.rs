// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    admin, ansible_settings, plain,
    setup::{page, redirect},
    ErrorBox, Reply,
};
use crate::{connect, setting};
use hyper::{body::Bytes, StatusCode};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use std::{net::Ipv4Addr, path::Path};

#[derive(Clone, Copy)]
pub(super) enum Route {
    General,
    Ansible,
    VaultUnlock,
    Dns,
    Ipxe,
    RebuildGrub,
    RegenerateMok,
    Apply,
}

impl Route {
    pub(super) fn for_path(path: &str) -> Option<Self> {
        Some(match path {
            "/settings" => Self::General,
            ansible_settings::ROUTE => Self::Ansible,
            ansible_settings::VAULT => Self::VaultUnlock,
            "/settings/default-dns" => Self::Dns,
            "/settings/ipxe" => Self::Ipxe,
            "/settings/rebuild-grub" => Self::RebuildGrub,
            "/settings/regenerate-mok" => Self::RegenerateMok,
            "/settings/apply-config" => Self::Apply,
            _ => return None,
        })
    }

    pub(super) fn form_limit(self) -> usize {
        match self {
            Self::Ansible => 16384,
            Self::VaultUnlock => 4096,
            _ => 2048,
        }
    }

    pub(super) fn serve(
        self,
        db: &Connection,
        db_path: &Path,
        form: Option<Bytes>,
    ) -> Result<Reply, ErrorBox> {
        if matches!(self, Self::Ansible | Self::VaultUnlock) {
            return ansible_settings::serve(db, db_path, matches!(self, Self::VaultUnlock), form);
        }
        let Some(form) = form else {
            return match self {
                Self::General => self.general(db),
                Self::Ipxe => self.ipxe(db),
                _ => Ok(plain(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "Method not allowed\n",
                )),
            };
        };
        let input: Vec<_> = form_urlencoded::parse(&form).collect();
        let mut database = connect(db_path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let tx = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let target = match self {
            Self::Ansible | Self::VaultUnlock => unreachable!("handled above"),
            Self::General => {
                let [(key, value)] = input.as_slice() else {
                    return Ok(invalid());
                };
                if key != "discovery_boot_proto" || !matches!(value.as_ref(), "http" | "tftp") {
                    return Ok(invalid());
                }
                super::onboarding::store(&tx, key, value)?;
                "/settings"
            }
            Self::Dns => {
                let mut addresses = Vec::new();
                for (name, value) in input {
                    if !matches!(name.as_ref(), "default_dns" | "default_dns[]") {
                        return Ok(invalid());
                    }
                    let value = value.trim();
                    if value.is_empty() {
                        continue;
                    }
                    let Ok(address) = value.parse::<Ipv4Addr>() else {
                        return Ok(invalid());
                    };
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                }
                super::onboarding::store(&tx, "default_dns", &serde_json::to_string(&addresses)?)?;
                "/settings"
            }
            Self::Ipxe => {
                let value = match input.as_slice() {
                    [] => "off",
                    [(field, value)]
                        if field == "ipxe_enabled" && matches!(value.as_ref(), "on" | "1") =>
                    {
                        "on"
                    }
                    _ => return Ok(invalid()),
                };
                super::onboarding::store(&tx, "ipxe_enabled", value)?;
                enqueue(
                    &tx,
                    &[("bootstrap:render_templates", "Préparation des menus iPXE")],
                    "ipxe_job_ids",
                )?;
                "/settings/ipxe"
            }
            Self::RebuildGrub | Self::RegenerateMok | Self::Apply => {
                let jobs: &[(&str, &str)] = match self {
                    Self::RebuildGrub if input.is_empty() => {
                        &[("bootstrap:rebuild_grub", "Reconstruction du chargeur UEFI")]
                    }
                    Self::RegenerateMok if matches!(input.as_slice(),[(field,value)] if field == "confirm" && value == "yes") => {
                        &[
                            ("bootstrap:regen_mok", "Régénération de la clé Secure Boot"),
                            (
                                "bootstrap:rebuild_grub",
                                "Reconstruction du chargeur UEFI avec la nouvelle clé",
                            ),
                        ]
                    }
                    Self::Apply if input.is_empty() => &[
                        ("bootstrap:build_grub", "Préparation du chargeur UEFI"),
                        (
                            "bootstrap:render_templates",
                            "Préparation des menus et scripts PXE",
                        ),
                        (
                            "bootstrap:restart_dnsmasq",
                            "Application de la configuration réseau PXE",
                        ),
                    ],
                    _ => return Ok(invalid()),
                };
                enqueue(&tx, jobs, "appliance_last_job_ids")?;
                "/settings"
            }
        };
        tx.commit()?;
        Ok(redirect(StatusCode::SEE_OTHER, target))
    }

    fn general(self, db: &Connection) -> Result<Reply, ErrorBox> {
        let mut html = String::from(
            r#"<nav><a href="/admin/devices">Console</a> · <a href="/settings/images">Images</a> · <a href="/admin/certificates">Certificats TLS</a> · <a href="/settings/ipxe">iPXE</a> · <a href="/settings/ansible">Ansible</a></nav>
<section><h2>Découverte réseau</h2>
<form method="post" action="/settings"><label>Protocole
<select name="discovery_boot_proto">"#,
        );
        let protocol = setting(db, "discovery_boot_proto")?;
        if protocol == "tftp" {
            html.push_str(
                r#"<option value="http">HTTP</option><option value="tftp" selected>TFTP</option>"#,
            );
        } else {
            html.push_str(
                r#"<option value="http" selected>HTTP</option><option value="tftp">TFTP</option>"#,
            );
        }
        html.push_str(
            r#"</select></label> <button>Enregistrer</button></form></section>
<section><h2>DNS par défaut</h2><form method="post" action="/settings/default-dns">"#,
        );
        let mut addresses =
            serde_json::from_str::<Vec<String>>(&setting(db, "default_dns")?).unwrap_or_default();
        addresses.resize(addresses.len().max(2) + 1, String::new());
        for address in addresses {
            html.push_str(r#"<p><label>Serveur DNS IPv4 <input name="default_dns[]" value=""#);
            admin::escape(&mut html, &address);
            html.push_str(r#""></label></p>"#);
        }
        html.push_str(r#"<button>Enregistrer les DNS</button></form></section>
<section><h2>Configuration PXE</h2>
<form method="post" action="/settings/apply-config"><button>Appliquer la configuration</button></form>
<form method="post" action="/settings/rebuild-grub"><button>Reconstruire GRUB</button></form>
<form method="post" action="/settings/regenerate-mok"><p>Les clients qui utilisent la clé Secure Boot actuelle devront enrôler la nouvelle clé.</p>
<label><input type="checkbox" name="confirm" value="yes" required> Confirmer le changement de clé</label>
<button>Régénérer la clé MOK</button></form>"#);
        add_jobs(&mut html, db, "appliance_last_job_ids")?;
        html.push_str("</section><section><h2>Appellation des appareils</h2>");
        admin::terminology_form(
            &mut html,
            "/settings/terminology",
            &setting(db, "ui_device_term")?,
        );
        html.push_str("</section>");
        Ok(page("Paramètres PXE", &html))
    }

    fn ipxe(self, db: &Connection) -> Result<Reply, ErrorBox> {
        let checked = if setting(db, "ipxe_enabled")? == "on" {
            " checked"
        } else {
            ""
        };
        let mut html = format!(
            r#"<p><a href="/settings">Paramètres PXE</a></p>
<form method="post" action="/settings/ipxe"><label><input type="checkbox" name="ipxe_enabled"{checked}> Afficher l’entrée iPXE dans les menus de démarrage</label>
<button>Enregistrer</button></form>"#
        );
        add_jobs(&mut html, db, "ipxe_job_ids")?;
        Ok(page("Démarrage iPXE", &html))
    }
}

fn invalid() -> Reply {
    plain(
        StatusCode::UNPROCESSABLE_ENTITY,
        "Valeurs de configuration invalides\n",
    )
}

fn enqueue(db: &Connection, jobs: &[(&str, &str)], tracking: &str) -> Result<(), ErrorBox> {
    let mut ids = Vec::new();
    super::onboarding::store(db, "appliance_request_revision", &crate::random_token()?)?;
    for (kind, label) in jobs {
        db.execute(
            "INSERT INTO init_jobs(job_type,status,message) VALUES(?1,'pending',?2)",
            params![kind, label],
        )?;
        ids.push(db.last_insert_rowid());
    }
    super::onboarding::store(db, tracking, &serde_json::to_string(&ids)?)?;
    Ok(())
}

fn add_jobs(html: &mut String, db: &Connection, tracking: &str) -> Result<(), ErrorBox> {
    use std::fmt::Write;
    let jobs = serde_json::from_str::<Vec<i64>>(&setting(db, tracking)?).unwrap_or_default();
    if jobs.is_empty() {
        return Ok(());
    }
    html.push_str("<ul>");
    for job in jobs.into_iter().filter(|id| *id > 0).take(16) {
        write!(
            html,
            r#"<li><a href="/jobs/{job}">Suivre la tâche {job}</a></li>"#
        )?;
    }
    html.push_str("</ul>");
    Ok(())
}
