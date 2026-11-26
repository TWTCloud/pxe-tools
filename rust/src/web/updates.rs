// SPDX-License-Identifier: LGPL-3.0-only

use super::{admin::escape, jobs::json_reply, plain, setup::redirect, ui, ErrorBox, Reply};
use crate::{
    apt_updates::{self, Phase, State, Step},
    connect,
};
use hyper::{body::Bytes, StatusCode};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use serde_json::json;
use std::{collections::BTreeMap, env, fmt::Write, path::Path};

pub(super) const ROUTE: &str = "/settings/updates";
pub(super) const STATUS: &str = "/settings/updates/status";
const RELEASES: &str = "https://github.com/TWTCloud/pxe-tools/releases";
const PACKAGES: [(&str, &str); 2] = [
    ("pxe-tools", "PXE Tools"),
    ("pxe-tools-ansible", "Module Ansible"),
];

pub(super) fn serve(
    status_only: bool,
    db: &Connection,
    db_path: &Path,
    form: Option<Bytes>,
    wants_json: bool,
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
        return status(StatusCode::OK, &state);
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
            if value == "auto" || wants_json {
                return status(StatusCode::OK, &state);
            }
        }
        [(key, action), (plan_key, plan)]
            if key == "action" && action == "install" && plan_key == "plan" =>
        {
            if state.phase.pending()
                || state.candidates.is_empty()
                || plan.as_ref() != serde_json::to_string(&state.candidates)?
            {
                if wants_json {
                    return status(StatusCode::CONFLICT, &state);
                }
                return Ok(plain(
                    StatusCode::CONFLICT,
                    "La mise à jour a changé. Rechargez la page.\n",
                ));
            }
            state.phase = Phase::InstallQueued;
            state.step = None;
            super::onboarding::store(&tx, apt_updates::KEY, &serde_json::to_string(&state)?)?;
            tx.commit()?;
            if wants_json {
                return status(StatusCode::OK, &state);
            }
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

fn installed_versions(state: &State) -> BTreeMap<String, String> {
    let mut versions = state.installed.clone();
    if let Ok(version) = env::var("PXE_APT_PACKAGE_VERSION") {
        versions.insert("pxe-tools".into(), version);
    }
    versions
}

fn release_notes(state: &State, installed: &BTreeMap<String, String>) -> String {
    state
        .candidates
        .get("pxe-tools")
        .or_else(|| state.candidates.get("pxe-tools-ansible"))
        .or_else(|| installed.get("pxe-tools"))
        .map(|version| format!("{RELEASES}/tag/v{}", version.replace('~', "-")))
        .unwrap_or_else(|| RELEASES.to_owned())
}

fn status(code: StatusCode, state: &State) -> Result<Reply, ErrorBox> {
    let installed = installed_versions(state);
    json_reply(
        code,
        json!({
            "phase": state.phase,
            "available": !state.candidates.is_empty(),
            "message": message(state),
            "release_notes": release_notes(state, &installed),
            "installed": installed,
            "candidates": state.candidates,
            "plan": serde_json::to_string(&state.candidates)?,
        }),
    )
}

fn message(state: &State) -> &'static str {
    match state.phase {
        Phase::Idle => "Recherchez les nouvelles versions pour cette instance.",
        Phase::Queued | Phase::Checking => "Recherche des mises à jour…",
        Phase::InstallQueued => "Préparation de l’installation…",
        Phase::Installing => match state.step {
            Some(Step::Download) => "Téléchargement des paquets…",
            Some(Step::Apply) => "Installation et redémarrage des services…",
            _ => "Vérification de la version à installer…",
        },
        Phase::Available => "Une mise à jour est disponible.",
        Phase::UpToDate => "PXE Tools est à jour.",
        Phase::Installed => "Mise à jour terminée.",
        Phase::Busy => "Des tâches PXE sont en cours. Réessayez lorsqu’elles sont terminées.",
        Phase::Changed => "La version proposée a changé. Vérifiez-la avant de l’installer.",
        Phase::Failed => match state.step {
            Some(Step::Download) => "Le téléchargement des paquets a échoué.",
            Some(Step::Apply) => "L’installation a échoué. Consultez le journal.",
            _ => "Impossible de vérifier les mises à jour. Réessayez.",
        },
        Phase::Unavailable => "Dépôt APT de PXE Tools indisponible. Vérifiez sa configuration.",
    }
}

fn page(state: &State) -> Result<Reply, ErrorBox> {
    let phase = serde_json::to_string(&state.phase)?;
    let pending = state.phase.pending();
    let disabled = if pending { " disabled" } else { "" };
    let installed = installed_versions(state);
    let mut html = format!(
        r#"<section class="panel update-center" aria-labelledby="update-heading" data-update-phase="{}">
<header class="update-status">
<div class="update-header"><h2 id="update-heading">PXE Tools</h2><a data-update-notes href=""#,
        phase.trim_matches('"'),
    );
    escape(&mut html, &release_notes(state, &installed));
    write!(
        html,
        r#"">Notes de version</a></div>
<p class="update-message" data-update-message role="status">{}</p>
<div class="update-loading-slot"><div class="update-loading" role="progressbar" aria-label="Opération en cours" data-update-progress{}></div></div>
</header>
<dl class="update-packages">"#,
        message(state),
        if pending { "" } else { " hidden" },
    )?;
    for (package, label) in PACKAGES {
        let installed = installed.get(package);
        let available = state.candidates.get(package);
        let hidden = if package != "pxe-tools" && installed.is_none() && available.is_none() {
            " hidden"
        } else {
            ""
        };
        write!(
            html,
            r#"<div class="update-package" data-update-package="{package}"{hidden}><dt>{label}</dt>
<dd><div><span>Version installée</span> <strong data-update-installed>"#
        )?;
        escape(&mut html, installed.map_or("À vérifier", String::as_str));
        html.push_str(
            r#"</strong></div><div><span>Version disponible</span> <strong data-update-candidate>"#,
        );
        escape(&mut html, available.map_or("—", String::as_str));
        html.push_str("</strong></div></dd></div>");
    }
    write!(
        html,
        r#"</dl>
<footer class="update-actions">
<form method="post" action="{ROUTE}" data-update-action="check">
<input type="hidden" name="action" value="check"><button class="button--quiet"{disabled}>Vérifier les mises à jour</button></form>
<form method="post" action="{ROUTE}" data-update-action="install"{}>
<input type="hidden" name="action" value="install"><input type="hidden" name="plan" value=""#,
        if state.candidates.is_empty() {
            " hidden"
        } else {
            ""
        },
    )?;
    escape(&mut html, &serde_json::to_string(&state.candidates)?);
    write!(
        html,
        r#""><button{disabled}>Installer la mise à jour</button></form>
</footer>
<details class="update-diagnostic" data-update-diagnostic{}>
<summary>Consulter le journal sur le serveur</summary>
<pre><code>sudo journalctl -u pxe-tools-apt-update.service -n 60 --no-pager</code></pre></details>"#,
        if state.phase == Phase::Failed {
            ""
        } else {
            " hidden"
        },
    )?;
    if pending {
        write!(
            html,
            r#"<noscript><p class="update-diagnostic"><a href="{ROUTE}">Recharger la page pour consulter le résultat</a></p></noscript>"#
        )?;
    }
    html.push_str("</section>");
    Ok(ui::page(ui::ConsoleSection::Updates, "Mises à jour", &html))
}
