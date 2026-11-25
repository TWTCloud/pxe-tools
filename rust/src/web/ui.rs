// SPDX-License-Identifier: LGPL-3.0-only

use super::{admin::escape, bytes, Reply};
use base64::{engine::general_purpose::STANDARD, Engine};
use hyper::{header, Response, StatusCode};
use sha2::{Digest, Sha256};
use std::{fmt::Write, sync::LazyLock};

const MARK: &str = "/console-assets/mark.svg?v=2";
const NAVIGATION_SCRIPT: &str = include_str!("ui/navigation.js");
const POLICY: &str = "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
static CONSOLE_POLICY: LazyLock<String> = LazyLock::new(|| {
    let digest = STANDARD.encode(Sha256::digest(NAVIGATION_SCRIPT.as_bytes()));
    format!("{POLICY}; script-src 'sha256-{digest}'")
});

const MENU: &str = "M4 6h16M4 12h16M4 18h16";
const CLOSE: &str = "m6 6 12 12M18 6 6 18";
const LOGOUT: &str = r#"<form method="post" action="/logout"><button class="button button--quiet">Se déconnecter</button></form>"#;

fn brand() -> String {
    format!(
        r#"<span class="brand"><img src="{MARK}" width="32" height="32" alt="">PXE Tools</span>"#
    )
}

fn icon(path: &str) -> String {
    format!(
        r#"<svg class="nav-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="{path}"/></svg>"#
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ConsoleSection {
    Devices,
    Activity,
    Jobs,
    Presets,
    Images,
    Settings,
    Certificates,
}

type NavLink = (&'static str, &'static str, ConsoleSection, &'static str);

const NAVIGATION: [(&str, &[NavLink]); 2] = [
    (
        "Opérations",
        &[
            (
                "/admin/devices",
                "Inventaire",
                ConsoleSection::Devices,
                "M3 4h18v12H3zM8 20h8m-4-4v4",
            ),
            (
                "/activity",
                "Activité",
                ConsoleSection::Activity,
                "M3 12h4l3-6 4 12 3-6h4",
            ),
            (
                "/jobs",
                "Tâches",
                ConsoleSection::Jobs,
                "M9 5h11M9 12h11M9 19h11m-17-14h1m-1 7h1m-1 7h1",
            ),
        ],
    ),
    (
        "Configuration",
        &[
            (
                "/presets",
                "Modèles d’installation",
                ConsoleSection::Presets,
                "M5 3h10l4 4v14H5zM14 3v5h5M8 12h8m-8 4h8",
            ),
            (
                "/settings/images",
                "Images PXE",
                ConsoleSection::Images,
                "m12 3 9 5-9 5-9-5zm-9 9 9 5 9-5m-18 4 9 5 9-5",
            ),
            (
                "/settings",
                "Paramètres PXE",
                ConsoleSection::Settings,
                "M4 6h5m4 0h7M4 12h11m4 0h1M4 18h2m4 0h10M9 4v4m6 2v4m-9 2v4",
            ),
            (
                "/admin/certificates",
                "Certificats TLS",
                ConsoleSection::Certificates,
                "m12 3 8 3v5c0 5-3 8-8 10-5-2-8-5-8-10V6zm-3 9 2 2 4-4",
            ),
        ],
    ),
];

pub(super) fn page(section: ConsoleSection, title: &str, content: &str) -> Reply {
    let logout = matches!(
        std::env::var("AUTH_MODE").unwrap_or_default().as_str(),
        "" | "local"
    );
    let brand = brand();
    let mut layout = String::from(
        r##"<a class="skip-link" href="#main">Aller au contenu</a><header class="masthead">"##,
    );
    write!(
        layout,
        r#"<a class="brand-link" href="/admin/devices">{brand}</a><span class="masthead-label">Console d’administration</span>
<button type="button" class="button button--quiet mobile-toggle" aria-haspopup="dialog" aria-controls="mobile-navigation" aria-expanded="false">{} Menu</button>"#,
        icon(MENU),
    )
    .expect("write to String");
    if logout {
        layout.push_str(LOGOUT);
    }
    let mut navigation = String::new();
    for (group, links) in NAVIGATION {
        write!(navigation, r#"<div class="rail-group"><p>{group}</p>"#).expect("write to String");
        for &(path, name, item, glyph) in links {
            let current = if item == section {
                r#" aria-current="page""#
            } else {
                ""
            };
            write!(
                navigation,
                r#"<a href="{path}"{current}>{}<span>{name}</span></a>"#,
                icon(glyph)
            )
            .expect("write to String");
        }
        navigation.push_str("</div>");
    }
    write!(
        layout,
        r#"</header><dialog id="mobile-navigation" class="mobile-drawer" aria-label="Navigation PXE Tools">
<div class="drawer-body"><div class="drawer-header">{brand}<form method="dialog"><button type="submit" class="button button--quiet drawer-close" aria-label="Fermer le menu" autofocus>{}</button></form></div>
<nav class="rail" aria-label="Navigation principale">{navigation}</nav>"#,
        icon(CLOSE)
    )
    .expect("write to String");
    if logout {
        write!(layout, r#"<footer class="drawer-footer">{LOGOUT}</footer>"#)
            .expect("write to String");
    }
    write!(
        layout,
        r#"</div></dialog><div class="workspace"><nav class="rail" aria-label="Navigation principale">{navigation}</nav><main id="main" class="console-main" tabindex="-1"><h1>"#
    )
    .expect("write to String");
    escape(&mut layout, title);
    layout.push_str("</h1>");
    layout.push_str(content);
    layout.push_str("</main></div>");
    document("console", title, &layout, StatusCode::OK)
}

pub(super) fn guest(title: &str, content: &str, status: StatusCode) -> Reply {
    let mut layout = format!(
        r#"<div class="auth-layout">
<header class="auth-brand">{}</header>
<div class="auth-image"><p>Inventaire et<br>déploiement réseau</p></div>
<main class="auth-main"><div class="auth-content"><h1>"#,
        brand()
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
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><title>"#,
    );
    escape(&mut html, title);
    write!(
        html,
        r#" · PXE Tools</title><link rel="icon" type="image/svg+xml" href="{MARK}">
<link rel="stylesheet" href="/console-assets/style.css?v=5"></head><body class="{class}">{layout}"#
    )
    .expect("write to String");
    let policy = if class == "console" {
        write!(html, "<script>{NAVIGATION_SCRIPT}</script>").expect("write to String");
        CONSOLE_POLICY.as_str()
    } else {
        POLICY
    };
    html.push_str("</body></html>");
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        // A restrictive no-referrer policy also suppresses the Origin of
        // browser form submissions checked by the console.
        .header(header::REFERRER_POLICY, "same-origin")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header("Content-Security-Policy", policy)
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
