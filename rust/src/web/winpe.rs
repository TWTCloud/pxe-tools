// SPDX-License-Identifier: LGPL-3.0-only

use super::{bytes, plain, ErrorBox, Reply};
use hyper::{Response, StatusCode};
use std::net::{IpAddr, Ipv4Addr};

pub(super) const PREFIX: &str = "/pxe/windows/";
pub(super) const BOOT: &str = "/pxe/windows/boot.ipxe";

pub(super) fn configured_client() -> Result<Option<Ipv4Addr>, ErrorBox> {
    let Some(value) = std::env::var_os("PXE_WINPE_CLIENT_IP").filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let client: Ipv4Addr = value
        .to_str()
        .ok_or("Invalid WinPE client IPv4 address")?
        .parse()?;
    if client.is_unspecified()
        || client.is_loopback()
        || client.is_multicast()
        || client.is_broadcast()
    {
        return Err("Invalid WinPE client IPv4 address".into());
    }
    Ok(Some(client))
}

pub(super) fn allowed(client: Option<Ipv4Addr>, peer: IpAddr) -> bool {
    matches!(peer, IpAddr::V4(peer) if client == Some(peer))
}

pub(super) fn menu(server: Ipv4Addr, port: u16) -> Reply {
    let origin = origin(server, port);
    response(format!(
        r#"#!ipxe
iseq ${{platform}} efi || goto debian
iseq ${{buildarch}} x86_64 || goto debian
chain {origin}{BOOT} || goto debian
:debian
chain {origin}/boot.ipxe?menu=debian || exit
"#
    ))
}

pub(super) fn script(server: Ipv4Addr, port: u16) -> Reply {
    let origin = origin(server, port);
    response(format!(
        r#"#!ipxe
iseq ${{platform}} efi || goto refused
iseq ${{buildarch}} x86_64 || goto refused
set base {origin}{PREFIX}
kernel ${{base}}wimboot || goto refused
initrd --name BCD ${{base}}BCD || goto refused
initrd --name boot.sdi ${{base}}boot.sdi || goto refused
initrd --name boot.wim ${{base}}boot.wim || goto refused
boot || goto refused
:refused
echo WinPE requiert un amorcage UEFI x86-64 et les fichiers du banc.
exit
"#
    ))
}

fn origin(server: Ipv4Addr, port: u16) -> String {
    if port == 80 {
        format!("http://{server}")
    } else {
        format!("http://{server}:{port}")
    }
}

fn response(body: String) -> Reply {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("Cache-Control", "no-store")
        .body(bytes(body))
        .unwrap_or_else(|_| {
            plain(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to render WinPE boot\n",
            )
        })
}
