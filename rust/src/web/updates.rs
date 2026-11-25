// SPDX-License-Identifier: LGPL-3.0-only

use super::{admin::escape, jobs::json_reply, plain, setup::redirect, ui, ErrorBox, Reply};
use crate::{
    apt_updates::{self, Phase, State},
    connect,
};
use hyper::{body::Bytes, StatusCode};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use serde_json::json;
use std::{env, path::Path};

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
        return json_reply(
            StatusCode::OK,
            json!({"phase": state.phase, "available": !state.candidates.is_empty()}),
        );
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
                super::onboarding::store(&tx, apt_updates::KEY, &serde_json::to_string(&state)?)?;
            }
            tx.commit()?;
            if value == "auto" {
                return json_reply(
                    StatusCode::OK,
                    json!({"phase": state.phase, "available": !state.candidates.is_empty()}),
                );
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

fn page(state: &State) -> Result<Reply, ErrorBox> {
    let (title, description) = match state.phase {
        Phase::Idle => ("Vérification disponible", "La console vérifie les mises à jour à la connexion."),
        Phase::Queued | Phase::Checking => ("Vérification en cours", "PXE Tools consulte le dépôt APT signé."),
        Phase::InstallQueued | Phase::Installing => ("Installation en cours", "La console peut être brièvement indisponible pendant le redémarrage."),
        Phase::Available => ("Mise à jour disponible", "Vous pouvez consulter les notes de version avant de lancer l’installation."),
        Phase::UpToDate => ("PXE Tools est à jour", "Le dépôt APT ne propose pas de version plus récente pour les paquets installés."),
        Phase::Installed => ("Mise à jour installée", "Les nouvelles versions des paquets sont en service."),
        Phase::Busy => ("PXE Tools est occupé", "Attendez la fin des opérations PXE en cours, puis relancez la mise à jour."),
        Phase::Changed => ("Nouvelle version détectée", "Le dépôt a changé depuis la vérification. Vérifiez les versions proposées avant de confirmer."),
        Phase::Failed => ("Vérification ou installation interrompue", "Réessayez après avoir vérifié la connexion, l’état d’APT et le journal du service pxe-tools-apt-update."),
        Phase::Unavailable => ("Dépôt PXE Tools indisponible", "Vérifiez que le dépôt APT officiel est activé et que sa clé est installée."),
    };
    let phase = serde_json::to_string(&state.phase)?;
    let mut html = format!(
        r#"<section class="panel panel--form" data-update-phase="{}">
<h2>{title}</h2><p>{description}</p><dl class="wizard-summary update-versions">
<dt>PXE Tools installé</dt><dd>"#,
        phase.trim_matches('"'),
    );
    escape(
        &mut html,
        &env::var("PXE_APT_PACKAGE_VERSION")
            .ok()
            .or_else(|| state.installed.get("pxe-tools").cloned())
            .unwrap_or_else(|| "À vérifier".into()),
    );
    html.push_str("</dd>");
    if let Some(version) = state.installed.get("pxe-tools-ansible") {
        html.push_str("<dt>Module Ansible installé</dt><dd>");
        escape(&mut html, version);
        html.push_str("</dd>");
    }
    for (package, label) in [
        ("pxe-tools", "PXE Tools disponible"),
        ("pxe-tools-ansible", "Module Ansible disponible"),
    ] {
        if let Some(version) = state.candidates.get(package) {
            html.push_str(&format!("<dt>{label}</dt><dd>"));
            escape(&mut html, version);
            html.push_str("</dd>");
        }
    }
    html.push_str("</dl>");
    if !state.phase.pending() {
        if !state.candidates.is_empty() {
            html.push_str(
                r#"<form class="form-stack" method="post" action="/settings/updates">
<p>PXE Tools et ses services peuvent redémarrer pendant l’installation des paquets affichés.</p>
<label class="check-label"><input type="checkbox" required>Confirmer l’installation</label>
<input type="hidden" name="action" value="install"><input type="hidden" name="plan" value=""#,
            );
            escape(&mut html, &serde_json::to_string(&state.candidates)?);
            html.push_str(r#""><div class="form-actions"><button>Installer la mise à jour</button>
<a class="button button--quiet" href="https://github.com/TWTCloud/pxe-tools/releases">Notes de version</a></div></form>"#);
        }
        html.push_str(r#"<form method="post" action="/settings/updates" class="maintenance-form"><button class="button--quiet" name="action" value="check">Vérifier les mises à jour</button></form>"#);
    } else {
        html.push_str(r#"<p><a href="/settings/updates">Actualiser l’état</a></p>"#);
    }
    html.push_str("</section>");
    Ok(ui::page(ui::ConsoleSection::Updates, "Mises à jour", &html))
}
