// SPDX-License-Identifier: LGPL-3.0-only

use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fs::File,
    io::{self, Read},
    net::Ipv4Addr,
    path::Path,
};

type RenderResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
const TEMPLATE_LIMIT: u64 = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    pxe_ip: Ipv4Addr,
    token: String,
    mac: String,
}

#[derive(Serialize)]
struct Postboot {
    script: String,
    service: String,
}

pub fn render(directory: &Path) -> RenderResult<()> {
    let mut input = Vec::new();
    io::stdin().take(4097).read_to_end(&mut input)?;
    if input.len() > 4096 || !directory.is_absolute() {
        return Err("Invalid postboot request".into());
    }
    let ctx: Context = serde_json::from_slice(&input).map_err(|_| "Invalid postboot context")?;
    let mac = crate::pxe::normalize_mac(&ctx.mac).ok_or("Invalid postboot MAC")?;
    if ctx.token.is_empty()
        || ctx.token.len() > 256
        || !ctx
            .token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
        || ctx.pxe_ip.is_unspecified()
        || ctx.pxe_ip.is_multicast()
        || ctx.pxe_ip.is_broadcast()
    {
        return Err("Invalid postboot parameters".into());
    }
    let address = ctx.pxe_ip.to_string();
    let render_file = |name| -> RenderResult<String> {
        let mut template = String::new();
        File::open(directory.join(name))?
            .take(TEMPLATE_LIMIT + 1)
            .read_to_string(&mut template)?;
        if template.len() as u64 > TEMPLATE_LIMIT {
            return Err("Oversized postboot template".into());
        }
        interpolate(&template, &address, &ctx.token, &mac)
    };
    let rendered = Postboot {
        script: render_file("postboot.sh.j2")?,
        service: render_file("pxe-postboot.service.j2")?,
    };
    serde_json::to_writer(io::stdout().lock(), &rendered)?;
    Ok(())
}

fn interpolate(template: &str, address: &str, token: &str, mac: &str) -> RenderResult<String> {
    if template.contains("{%") || template.contains("{#") {
        return Err("Unsupported directive in postboot template".into());
    }
    let mut remaining = template;
    let mut rendered = String::with_capacity(template.len());
    while let Some((before, rest)) = remaining.split_once("{{") {
        let (name, after) = rest
            .split_once("}}")
            .ok_or("Incomplete postboot placeholder")?;
        let value = match name.trim() {
            "pxe_ip" => address,
            "token" => token,
            "mac" => mac,
            _ => return Err("Unknown postboot placeholder".into()),
        };
        rendered.push_str(before);
        rendered.push_str(value);
        remaining = after;
    }
    rendered.push_str(remaining);
    Ok(rendered)
}
