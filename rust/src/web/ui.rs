// SPDX-License-Identifier: LGPL-3.0-only

use super::{admin::escape, bytes, Reply};
use hyper::{header, Response, StatusCode};
use std::fmt::Write;

const BRAND: &str = r#"<span class="brand"><img src="/console-assets/mark.svg" width="32" height="32" alt="">PXE Tools</span>"#;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Section {
    Devices,
    Activity,
    Jobs,
    Presets,
    Images,
    Settings,
    Certificates,
}

const NAVIGATION: [(&str, &[(&str, &str, Section)]); 2] = [
    (
        "Opérations",
        &[
            ("/admin/devices", "Inventaire", Section::Devices),
            ("/activity", "Activité", Section::Activity),
            ("/jobs", "Tâches", Section::Jobs),
        ],
    ),
    (
        "Configuration",
        &[
            ("/presets", "Modèles d’installation", Section::Presets),
            ("/settings/images", "Images PXE", Section::Images),
            ("/settings", "Paramètres PXE", Section::Settings),
            (
                "/admin/certificates",
                "Certificats TLS",
                Section::Certificates,
            ),
        ],
    ),
];

pub(super) fn page(section: Section, title: &str, content: &str) -> Reply {
    let mut layout = String::from(
        r##"<a class="skip-link" href="#main">Aller au contenu</a><header class="masthead"><a class="brand-link" href="/admin/devices">"##,
    );
    layout.push_str(BRAND);
    layout.push_str(r#"</a><span class="masthead-label">Console d’administration</span>"#);
    if matches!(
        std::env::var("AUTH_MODE").unwrap_or_default().as_str(),
        "" | "local"
    ) {
        layout.push_str(r#"<form method="post" action="/logout"><button class="button button--quiet">Se déconnecter</button></form>"#);
    }
    layout.push_str(
        r#"</header><div class="workspace"><nav class="rail" aria-label="Navigation principale">"#,
    );
    for (group, links) in NAVIGATION {
        write!(layout, r#"<div class="rail-group"><p>{group}</p>"#).expect("write to String");
        for &(path, name, item) in links {
            let current = if item == section {
                r#" aria-current="page""#
            } else {
                ""
            };
            write!(layout, r#"<a href="{path}"{current}>{name}</a>"#).expect("write to String");
        }
        layout.push_str("</div>");
    }
    layout.push_str(r#"</nav><main id="main" class="console-main"><h1>"#);
    escape(&mut layout, title);
    layout.push_str("</h1>");
    layout.push_str(content);
    layout.push_str("</main></div>");
    document("console", title, &layout, StatusCode::OK)
}

pub(super) fn guest(title: &str, content: &str, status: StatusCode) -> Reply {
    let mut layout = format!(
        r#"<div class="auth-layout">
<header class="auth-brand">{BRAND}</header>
<div class="auth-image"><p>Inventaire et<br>déploiement réseau</p></div>
<main class="auth-main"><div class="auth-content"><h1>"#
    );
    escape(&mut layout, title);
    layout.push_str("</h1>");
    layout.push_str(content);
    layout.push_str("</div></main></div>");
    document("guest", title, &layout, status)
}

fn document(class: &str, title: &str, layout: &str, status: StatusCode) -> Reply {
    let mut html = String::from(
        r#"<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>"#,
    );
    escape(&mut html, title);
    write!(
        html,
        r#" · PXE Tools</title><link rel="icon" href="/console-assets/mark.svg">
<link rel="stylesheet" href="/console-assets/style.css"></head><body class="{class}">{layout}</body></html>"#
    )
    .expect("write to String");
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        )
        .body(bytes(html))
        .expect("valid console page")
}

pub(super) fn asset(path: &str, head: bool) -> Option<Reply> {
    let (kind, data): (&str, &'static [u8]) = match path {
        "/console-assets/style.css" => ("text/css; charset=utf-8", include_bytes!("ui/style.css")),
        "/console-assets/mark.svg" => (
            "image/svg+xml",
            include_bytes!("../../../app/public/favicon.svg"),
        ),
        "/console-assets/mona.woff2" => (
            "font/woff2",
            include_bytes!("../../../app/public/fonts/mona-sans-latin-wght-normal.woff2"),
        ),
        "/console-assets/server-room.webp" => ("image/webp", include_bytes!("ui/server-room.webp")),
        _ => return None,
    };
    Some(
        Response::builder()
            .header(header::CONTENT_TYPE, kind)
            .header(header::CONTENT_LENGTH, data.len())
            .header(
                header::CACHE_CONTROL,
                "public, max-age=3600, must-revalidate",
            )
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
            .body(bytes(if head { &[] } else { data }))
            .expect("valid console asset"),
    )
}
