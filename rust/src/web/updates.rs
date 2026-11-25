// SPDX-License-Identifier: LGPL-3.0-only

use super::{admin::escape, jobs::json_reply, plain, setup::redirect, ui, ErrorBox, Reply};
use crate::{
    apt_updates::{self, Phase, State, Step},
    connect,
};
use hyper::{body::Bytes, StatusCode};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use serde_json::json;
use std::{env, fmt::Write, path::Path};

pub(super) const ROUTE: &str = "/settings/updates";
pub(super) const STATUS: &str = "/settings/updates/status";

pub(super) fn serve(
    status_only: bool,
    db: &Connection,
    db_path: &Path,
    form: Option<Bytes>,
) -> Result<Reply, ErrorBox> {
    if !apt_updates::enabled() {
        return Ok(plain(
            StatusCode::NOT_FOUND,
            "Mises à jour APT indisponibles\n",
        ));
    }
    if status_only {
        if form.is_some() {
            return Ok(plain(
                StatusCode::METHOD_NOT_ALLOWED,
                "Method not allowed\n",
            ));
        }
        let state = State::read(db)?;
        return status(&state);
    }
    let Some(form) = form else {
        return page(&State::read(db)?);
    };
    let fields: Vec<_> = form_urlencoded::parse(&form).collect();
    let mut database = connect(db_path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut state = State::read(&tx)?;
    match fields.as_slice() {
        [(key, value)] if key == "action" && matches!(value.as_ref(), "check" | "auto") => {
            let now: i64 = tx.query_row("SELECT unixepoch()", [], |row| row.get(0))?;
            if !state.phase.pending() && (value == "check" || now - state.checked_at >= 6 * 3600) {
                state.phase = Phase::Queued;
                state.step = None;
                super::onboarding::store(&tx, apt_updates::KEY, &serde_json::to_string(&state)?)?;
            }
            tx.commit()?;
            if value == "auto" {
                return status(&state);
            }
        }
        [(key, action), (plan_key, plan)]
            if key == "action" && action == "install" && plan_key == "plan" =>
        {
            if state.phase.pending()
                || state.candidates.is_empty()
                || plan.as_ref() != serde_json::to_string(&state.candidates)?
            {
                return Ok(plain(
                    StatusCode::CONFLICT,
                    "La mise à jour a changé. Rechargez la page.\n",
                ));
            }
            state.phase = Phase::InstallQueued;
            state.step = None;
            super::onboarding::store(&tx, apt_updates::KEY, &serde_json::to_string(&state)?)?;
            tx.commit()?;
        }
        _ => {
            return Ok(plain(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Formulaire invalide\n",
            ))
        }
    }
    Ok(redirect(StatusCode::SEE_OTHER, ROUTE))
}

fn status(state: &State) -> Result<Reply, ErrorBox> {
    json_reply(
        StatusCode::OK,
        json!({
            "phase": state.phase,
            "available": !state.candidates.is_empty(),
            "message": progress_message(state),
        }),
    )
}

fn progress_message(state: &State) -> &'static str {
    match state.phase {
        Phase::Queued => "Vérification planifiée…",
        Phase::Checking => "Consultation du dépôt APT signé…",
        Phase::InstallQueued => "Installation planifiée…",
        Phase::Installing => match state.step {
            Some(Step::Download) => "Téléchargement des paquets et préparation des dépendances…",
            Some(Step::Apply) => "Installation des paquets et redémarrage des services…",
            _ => "Vérification de la version sélectionnée…",
        },
        _ => "",
    }
}

fn page(state: &State) -> Result<Reply, ErrorBox> {
    let (title, description, tone) = match state.phase {
        Phase::Idle => (
            "Vérifier les mises à jour",
            "Recherchez la dernière version de PXE Tools et des modules installés.",
            "neutral",
        ),
        Phase::Queued | Phase::Checking => (
            "Vérification en cours",
            "La recherche se fait auprès du dépôt officiel de PXE Tools.",
            "info",
        ),
        Phase::InstallQueued | Phase::Installing => (
            "Installation en cours",
            "La console se reconnecte automatiquement après le redémarrage des services.",
            "info",
        ),
        Phase::Available => (
            "Une mise à jour est disponible",
            "L’installation peut interrompre brièvement l’accès à la console.",
            "info",
        ),
        Phase::UpToDate => (
            "PXE Tools est à jour",
            "Vous utilisez la dernière version proposée pour vos paquets installés.",
            "success",
        ),
        Phase::Installed => (
            "Mise à jour terminée",
            "La console est de nouveau disponible. Les versions installées sont indiquées ci-dessous.",
            "success",
        ),
        Phase::Busy => (
            "Installation reportée",
            "Des opérations PXE sont en cours. Relancez l’installation lorsqu’elles sont terminées.",
            "warning",
        ),
        Phase::Changed => (
            "La version proposée a changé",
            "Vérifiez les versions ci-dessous avant de relancer l’installation.",
            "warning",
        ),
        Phase::Failed => (
            match state.step {
                Some(Step::Download | Step::Apply) => "Échec de l’installation",
                _ => "Mise à jour interrompue",
            },
            match state.step {
                Some(Step::Download) => "La préparation des paquets ou des dépendances a échoué.",
                Some(Step::Apply) => "APT n’a pas terminé l’installation des paquets.",
                _ => "Vérifiez la connexion au dépôt et réessayez.",
            },
            "error",
        ),
        Phase::Unavailable => (
            "Dépôt PXE Tools indisponible",
            "Vérifiez que le dépôt APT officiel et sa clé de signature sont configurés.",
            "error",
        ),
    };
    let phase = serde_json::to_string(&state.phase)?;
    let pending = state.phase.pending();
    let candidate = !state.candidates.is_empty();
    let mut html = format!(
        r#"<section class="panel update-center" aria-labelledby="update-heading" data-update-phase="{}">
<header class="update-status" data-update-tone="{tone}">
<h2 id="update-heading" data-update-title>{title}</h2><p data-update-description>{description}</p>
<div class="update-progress" data-update-progress{}>
<p data-update-message role="status">{}</p><div class="update-loading" role="progressbar" aria-label="Progression de la mise à jour"></div>
</div></header>
<dl class="update-packages">"#,
        phase.trim_matches('"'),
        if pending { "" } else { " hidden" },
        progress_message(state),
    );
    for (package, label) in [
        ("pxe-tools", "PXE Tools"),
        ("pxe-tools-ansible", "Module Ansible"),
    ] {
        let installed = state.installed.get(package).cloned();
        let installed = if package == "pxe-tools" {
            env::var("PXE_APT_PACKAGE_VERSION").ok().or(installed)
        } else {
            installed
        };
        let available = state.candidates.get(package);
        if installed.is_none() && available.is_none() && package != "pxe-tools" {
            continue;
        }
        write!(
            html,
            r#"<div class="update-package"><dt>{label}</dt><dd><div><span>Installée</span> <strong>"#
        )?;
        escape(&mut html, installed.as_deref().unwrap_or("À vérifier"));
        html.push_str("</strong></div>");
        if let Some(version) = available {
            html.push_str("<div><span>Disponible</span> <strong>");
            escape(&mut html, version);
            html.push_str("</strong></div>");
        }
        html.push_str("</dd></div>");
    }
    html.push_str("</dl>");
    if state.phase == Phase::Failed {
        html.push_str(r#"<details class="update-diagnostic"><summary>Consulter les détails sur le serveur</summary>
<p>Sur le serveur PXE Tools, ouvrez le journal de la mise à jour.</p>
<pre><code>sudo journalctl -u pxe-tools-apt-update.service -n 60 --no-pager</code></pre></details>"#);
    }
    html.push_str(r#"<footer class="update-actions">"#);
    if pending {
        write!(
            html,
            r#"<a href="{ROUTE}" data-update-reload>Actualiser l’état</a>"#
        )?;
    } else {
        if candidate {
            write!(
                html,
                r#"<form method="post" action="{ROUTE}" data-update-action="install">
<input type="hidden" name="action" value="install"><input type="hidden" name="plan" value=""#
            )?;
            escape(&mut html, &serde_json::to_string(&state.candidates)?);
            let action = match state.phase {
                Phase::Failed | Phase::Busy => "Relancer l’installation",
                _ => "Installer la mise à jour",
            };
            write!(html, r#""><button>{action}</button></form>"#)?;
        }
        let button_class = if candidate {
            r#" class="button--quiet""#
        } else {
            ""
        };
        write!(
            html,
            r#"<form method="post" action="{ROUTE}" data-update-action="check">
<input type="hidden" name="action" value="check"><button{button_class}>Vérifier les mises à jour</button></form>"#
        )?;
        if let Some(version) = state
            .candidates
            .get("pxe-tools")
            .or_else(|| state.candidates.get("pxe-tools-ansible"))
        {
            let version = version.replace('~', "-");
            html.push_str(r#"<a href="https://github.com/TWTCloud/pxe-tools/releases/tag/v"#);
            escape(&mut html, &version);
            html.push_str(r#"">Notes de version</a>"#);
        }
    }
    html.push_str("</footer></section>");
    Ok(ui::page(ui::ConsoleSection::Updates, "Mises à jour", &html))
}
