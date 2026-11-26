// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    access::{self, Permission},
    device_operations::Operation,
    jobs::json_reply,
    single, ErrorBox, Reply,
};
use crate::{configured_database, connect};
use http_body_util::{BodyExt, Limited};
use hyper::{body::Incoming, header, http::request::Parts, Method, StatusCode};
use rusqlite::{params, Connection, OpenFlags, Row};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{path::Path, time::Duration};
use tokio::time::timeout;

pub(super) const PREFIX: &str = "/api/v1/";

enum Resource {
    Devices,
    Installations,
    Jobs,
    Images,
}

impl Resource {
    fn find(segment: &str) -> Option<Self> {
        Some(match segment {
            "devices" => Self::Devices,
            "installations" => Self::Installations,
            "jobs" => Self::Jobs,
            "images" => Self::Images,
            _ => return None,
        })
    }

    fn permission(&self) -> Permission {
        match self {
            Self::Devices => Permission::DevicesRead,
            Self::Installations => Permission::ActivityRead,
            Self::Jobs => Permission::JobsRead,
            Self::Images => Permission::ImagesRead,
        }
    }

    fn query(&self) -> &'static str {
        match self {
            Self::Devices => "SELECT id,mac,hostname,status,boot_arch FROM machines",
            Self::Installations => "SELECT id,machine_id,install_status,ansible_status,created_at,ended_at FROM installations",
            Self::Jobs => "SELECT id,job_type,status,progress_percent,created_at,ended_at FROM init_jobs",
            Self::Images => "SELECT id,distro,COALESCE(version_full,version),arch,status,enabled FROM os_images",
        }
    }

    fn row(&self, row: &Row<'_>) -> rusqlite::Result<Value> {
        let id: i64 = row.get(0)?;
        let text = |index| row.get::<_, Option<String>>(index);
        Ok(match self {
            Self::Devices => {
                json!({"id":id,"mac":text(1)?,"hostname":text(2)?,"status":text(3)?,"architecture":text(4)?})
            }
            Self::Installations => json!({"id":id,"device_id":row.get::<_,i64>(1)?,
                "status":text(2)?,"ansible_status":text(3)?,"created_at":text(4)?,"ended_at":text(5)?}),
            Self::Jobs => json!({"id":id,"type":text(1)?,"status":text(2)?,
                "progress_percent":row.get::<_,i64>(3)?,"created_at":text(4)?,"ended_at":text(5)?}),
            Self::Images => json!({"id":id,"distribution":text(1)?,"version":text(2)?,
                "architecture":text(3)?,"status":text(4)?,"enabled":row.get::<_,bool>(5)?}),
        })
    }
}

enum Route {
    Read(Resource, Option<i64>),
    Register,
    Power(i64, Operation),
}

impl Route {
    fn find(path: &str, method: &Method) -> Result<Self, StatusCode> {
        let path = path.strip_prefix(PREFIX).ok_or(StatusCode::NOT_FOUND)?;
        let (resource, rest) = path
            .split_once('/')
            .map_or((path, None), |(left, right)| (left, Some(right)));
        let resource = Resource::find(resource).ok_or(StatusCode::NOT_FOUND)?;
        let parse = |segment: &str| {
            segment
                .parse::<i64>()
                .ok()
                .filter(|id| *id > 0)
                .ok_or(StatusCode::NOT_FOUND)
        };
        if let Some((id, action)) = rest.and_then(|rest| rest.split_once("/actions/")) {
            if !matches!(resource, Resource::Devices) {
                return Err(StatusCode::NOT_FOUND);
            }
            let op = match action {
                "reboot" => Operation::Reboot,
                "shutdown" => Operation::Shutdown,
                "rediscover" => Operation::Rediscover,
                _ => return Err(StatusCode::NOT_FOUND),
            };
            let id = parse(id)?;
            return if method == Method::POST {
                Ok(Self::Power(id, op))
            } else {
                Err(StatusCode::METHOD_NOT_ALLOWED)
            };
        }
        let id = rest.map(parse).transpose()?;
        match *method {
            Method::GET | Method::HEAD => Ok(Self::Read(resource, id)),
            Method::POST if matches!(resource, Resource::Devices) && id.is_none() => {
                Ok(Self::Register)
            }
            _ => Err(StatusCode::METHOD_NOT_ALLOWED),
        }
    }

    fn permission(&self) -> Permission {
        match self {
            Self::Read(resource, _) => resource.permission(),
            Self::Register => Permission::DevicesEdit,
            Self::Power(_, _) => Permission::Power,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewDevice {
    mac: String,
    #[serde(default)]
    hostname: String,
}

pub(super) async fn serve(parts: Parts, body: Incoming, config: &Path) -> Result<Reply, ErrorBox> {
    let head = parts.method == Method::HEAD;
    let route = match Route::find(parts.uri.path(), &parts.method) {
        Ok(route) => route,
        Err(code) => {
            return error(
                code,
                if code == StatusCode::NOT_FOUND {
                    "not_found"
                } else {
                    "method_not_allowed"
                },
            )
        }
    };
    let token = single(&parts.headers, header::AUTHORIZATION.as_str())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, token)| scheme.eq_ignore_ascii_case("Bearer") && token.len() == 68)
        .map(|(_, token)| token.to_owned());
    let Some(token) = token else {
        return unauthorized();
    };
    let page = parts
        .uri
        .query()
        .and_then(|query| {
            form_urlencoded::parse(query.as_bytes())
                .find(|(key, _)| key == "page")
                .and_then(|(_, value)| value.parse::<u32>().ok())
                .filter(|page| *page > 0)
        })
        .unwrap_or(1);
    let request = match route {
        Route::Read(..) => None,
        Route::Register | Route::Power(..) => {
            let is_json = single(&parts.headers, header::CONTENT_TYPE.as_str())
                .and_then(|value| value.split(';').next())
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
            if !is_json {
                return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "expected_json");
            }
            match timeout(Duration::from_secs(5), Limited::new(body, 4096).collect()).await {
                Ok(Ok(body)) => Some(body.to_bytes()),
                Ok(Err(error)) if error.is::<http_body_util::LengthLimitError>() => {
                    return self::error(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large")
                }
                _ => return error(StatusCode::BAD_REQUEST, "invalid_body"),
            }
        }
    };
    let config = config.to_owned();
    let result = tokio::task::spawn_blocking(move || -> Result<Reply, ErrorBox> {
        let path = configured_database(&config).ok_or("SQLite database required")?;
        let db = connect(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let Some((_owner, mask)) = access::token_permissions(&db, &token)? else {
            return unauthorized();
        };
        let scope = route.permission();
        if !access::token_allows(mask, scope) {
            let mut reply = json_reply(
                StatusCode::FORBIDDEN,
                json!({"error":"insufficient_scope","scope":scope.key()}),
            )?;
            reply.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                format!(
                    r#"Bearer error="insufficient_scope", scope="{}""#,
                    scope.key()
                )
                .parse()?,
            );
            return Ok(reply);
        }
        match route {
            Route::Read(resource, id) => read(&db, resource, id, page),
            Route::Register => {
                let Ok(device) = serde_json::from_slice::<NewDevice>(&request.unwrap_or_default())
                else {
                    return error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_device");
                };
                if device.hostname.len() > 63 || device.hostname.chars().any(char::is_control) {
                    return error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_hostname");
                }
                let data = form_urlencoded::Serializer::new(String::new())
                    .append_pair("mac", &device.mac)
                    .append_pair("hostname", &device.hostname)
                    .finish();
                let reply = super::devices::register(&path, Some(data.as_bytes()))?;
                if reply.status() == StatusCode::SEE_OTHER {
                    let id = reply
                        .headers()
                        .get(header::LOCATION)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|location| location.strip_prefix("/admin/inventaire/"))
                        .and_then(|id| id.parse::<i64>().ok())
                        .ok_or("Invalid registration redirect")?;
                    let mut response = json_reply(StatusCode::CREATED, json!({"id":id}))?;
                    response
                        .headers_mut()
                        .insert(header::LOCATION, format!("{PREFIX}devices/{id}").parse()?);
                    Ok(response)
                } else {
                    error(
                        reply.status(),
                        if reply.status() == StatusCode::CONFLICT {
                            "duplicate_device"
                        } else {
                            "invalid_device"
                        },
                    )
                }
            }
            Route::Power(id, op) => {
                let Ok(value) = serde_json::from_slice::<Value>(&request.unwrap_or_default())
                else {
                    return error(StatusCode::UNPROCESSABLE_ENTITY, "expected_empty_object");
                };
                if !value.as_object().is_some_and(|fields| fields.is_empty()) {
                    return error(StatusCode::UNPROCESSABLE_ENTITY, "expected_empty_object");
                }
                let reply = op.run(&path, id, b"")?;
                match reply.status() {
                    StatusCode::SEE_OTHER => json_reply(
                        StatusCode::ACCEPTED,
                        json!({"device_id":id,"accepted":true}),
                    ),
                    StatusCode::NOT_FOUND => error(StatusCode::NOT_FOUND, "device_not_found"),
                    StatusCode::CONFLICT => error(StatusCode::CONFLICT, "device_busy"),
                    status => error(status, "operation_failed"),
                }
            }
        }
    })
    .await??;
    if head {
        Ok(hyper::Response::from_parts(
            result.into_parts().0,
            super::bytes(""),
        ))
    } else {
        Ok(result)
    }
}

fn read(
    db: &Connection,
    resource: Resource,
    id: Option<i64>,
    page: u32,
) -> Result<Reply, ErrorBox> {
    const SIZE: u32 = 100;
    if let Some(id) = id {
        let mut statement = db.prepare(&format!("{} WHERE id=?1", resource.query()))?;
        let mut rows = statement.query([id])?;
        return match rows.next()? {
            Some(row) => json_reply(StatusCode::OK, resource.row(row)?),
            None => error(StatusCode::NOT_FOUND, "not_found"),
        };
    }
    let mut query = db.prepare(&format!(
        "{} ORDER BY id DESC LIMIT ?1 OFFSET ?2",
        resource.query()
    ))?;
    let results = query.query_map(
        params![SIZE + 1, i64::from(page - 1) * i64::from(SIZE)],
        |row| resource.row(row),
    )?;
    let mut items = results.collect::<Result<Vec<_>, _>>()?;
    let next = if items.len() > SIZE as usize {
        items.pop();
        page.checked_add(1)
    } else {
        None
    };
    json_reply(
        StatusCode::OK,
        json!({"items":items,"page":page,"next_page":next}),
    )
}

fn unauthorized() -> Result<Reply, ErrorBox> {
    let mut reply = error(StatusCode::UNAUTHORIZED, "invalid_token")?;
    reply.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        r#"Bearer realm="PXE Tools API", error="invalid_token""#.parse()?,
    );
    Ok(reply)
}

pub(super) fn error(code: StatusCode, message: &str) -> Result<Reply, ErrorBox> {
    json_reply(code, json!({"error":message}))
}
