use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use anyhow::Result;
use axum::{
    Json,
    extract::{ConnectInfo, State},
    response::{IntoResponse, Response},
};
use axum_extra::{TypedHeader, extract::Query};
use headers::{Authorization, authorization::Basic};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    config::{
        Configuration,
        acl::{AclCheck, Action, ResourceContext, SubjectContext},
    },
    context::Access,
    error::RegistryError,
    issuer::issue_token,
    state::RegistryState,
};

#[derive(Debug, Deserialize)]
pub(crate) struct TokenRequest {
    service: String,
    scope: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TokenResponse {
    token: String,
    expires_in: u64,
    issued_at: String,
}

pub async fn authenticate(
    config: &Configuration,
    req_username: &str,
    req_password: &str,
) -> Result<Option<(String, Option<String>, Value)>> {
    let Some(authentication) = config.authentication.as_ref() else {
        return Ok(None);
    };

    for user in &authentication.users {
        match user {
            crate::config::User::Password { username, password } => {
                if username != req_username {
                    continue;
                }

                if pwhash::unix::verify(req_password, password) {
                    let subject = format!("internal:basic:{username}");
                    return Ok(Some((subject, None, Value::Null)));
                }
            }
            crate::config::User::Token { username, issuer } => {
                if username != req_username {
                    continue;
                }

                return Ok(match issuer.verify::<Value>(config, req_password).await? {
                    Some(claims) => {
                        let subject = format!(
                            "internal:token:{username}:subject:{}",
                            claims.subject.clone().unwrap_or("".to_string())
                        );
                        Some((subject, claims.subject, claims.custom))
                    }
                    None => None,
                });
            }
        }
    }
    Ok(None)
}

pub(crate) async fn token(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(TokenRequest { service, scope }): Query<TokenRequest>,
    authorization: Option<TypedHeader<Authorization<Basic>>>,
    State(registry): State<Arc<RegistryState>>,
) -> Result<Response, RegistryError> {
    if service != registry.config.url {
        return Ok((StatusCode::UNAUTHORIZED, "Invalid service").into_response());
    }

    let token = match authorization {
        Some(authorization) => {
            let Some((token_subject, subject, claims)) = authenticate(
                &registry.config,
                authorization.username(),
                authorization.password(),
            )
            .await?
            else {
                return Ok((StatusCode::UNAUTHORIZED, "Invalid credentials").into_response());
            };

            let subject = SubjectContext {
                username: authorization.username().to_string(),
                subject,
                claims: claims.clone(),
                ip: addr.ip(),
            };

            let mut access_map: BTreeMap<String, HashSet<Action>> = BTreeMap::new();

            if let Some(authentication) = registry.config.authentication.as_ref()
                && let Some(scope) = scope
            {
                for scope in &scope {
                    for scope in scope.split(" ") {
                        let parts: Vec<&str> = scope.split(':').collect();
                        if parts.len() == 3 && parts[0] == "repository" {
                            let repo = parts[1];
                            let actions: Vec<_> = parts[2]
                                .split(",")
                                .map(|split| Action::try_from(split.to_string()).unwrap())
                                .collect();

                            let allowed_actions = authentication.acls.check_access(
                                &subject,
                                &ResourceContext {
                                    repository: repo.to_string(),
                                },
                            );
                            for action in actions {
                                if allowed_actions.contains(&action) {
                                    access_map
                                        .entry(repo.to_string())
                                        .or_default()
                                        .insert(action);
                                }
                            }
                        }
                    }
                }
            }
            let access_entries = access_map
                .into_iter()
                .map(|(repo, actions)| {
                    let mut actions: Vec<_> = actions.into_iter().collect();
                    actions.sort();
                    Access {
                        type_: "repository".to_string(),
                        name: repo,
                        actions,
                    }
                })
                .collect();

            issue_token(&registry.config, &token_subject, access_entries)?
        }
        None => issue_token(&registry.config, "internal:anonymous", vec![])?,
    };

    Ok(Json(TokenResponse {
        token: token.token,
        expires_in: token.expires_in.as_secs(),
        issued_at: token
            .issued_at
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })
    .into_response())
}
