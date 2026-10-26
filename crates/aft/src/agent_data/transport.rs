//! Synchronous adapters over daemon-attested module routes, not command-line
//! output parsing or request-supplied principal claims.

use std::path::{Path, PathBuf};
use std::time::Duration;

use cortexkit_project_identity::{
    EnumerateParams, EnumerateReply, Outcome, Request, ResolveParams, ResolveReply,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use subc_client_rs::{CallError, CallOptions, CloseRouteOptions, ConsumerOptions, SubcConsumer};
use subc_protocol::{BindIdentity, RouteTarget};

use super::door::{DoorError, JsonDoorTransport};
use super::ProjectRegistry;

#[derive(Debug, Clone)]
pub struct ModuleTransport {
    connection_file: PathBuf,
    identity: BindIdentity,
    target: RouteTarget,
}

impl ModuleTransport {
    pub fn engram(connection_file: PathBuf, identity: BindIdentity) -> Self {
        Self {
            connection_file,
            identity,
            target: RouteTarget::InternalService {
                module_id: "engram".into(),
                service_id: "session-door".into(),
            },
        }
    }
    pub fn entorhinal(connection_file: PathBuf, identity: BindIdentity) -> Self {
        Self {
            connection_file,
            identity,
            target: RouteTarget::ManagementSurface {
                module_id: "entorhinal".into(),
            },
        }
    }

    fn request(&self, body: Vec<u8>, timeout: Duration) -> Result<Value, DoorError> {
        let this = self.clone();
        // SDK consumers run an async receive loop. A dedicated thread avoids
        // entering a second Tokio runtime on an async caller's executor thread.
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| DoorError::unavailable(error.to_string()))?;
            runtime.block_on(async {
                let principal = crate::launch_nonce::consumer_identity().ok_or_else(|| {
                    DoorError::unavailable("AFT module launch identity is unavailable")
                })?;
                let consumer =
                    SubcConsumer::connect(&this.connection_file, ConsumerOptions::default())
                        .await
                        .map_err(|error| DoorError::unavailable(error.to_string()))?;
                let route = consumer
                    .open_route(
                        this.target,
                        this.identity,
                        CallOptions {
                            consumer_identity: Some(principal),
                            ..CallOptions::default()
                        },
                    )
                    .await
                    .map_err(|error| DoorError::unavailable(error.to_string()))?;
                let result = consumer
                    .request(
                        &route,
                        body,
                        CallOptions {
                            timeout,
                            ..CallOptions::default()
                        },
                    )
                    .await;
                let _ = consumer
                    .close_handle(&route, CloseRouteOptions::default())
                    .await;
                let _ = consumer.close().await;
                let bytes = result.map_err(|error| match error {
                    CallError::Module(body) => {
                        let detail = serde_json::to_value(&body)
                            .ok()
                            .and_then(|value| value.get("detail").cloned())
                            .unwrap_or(Value::Null);
                        DoorError {
                            code: body.code,
                            detail,
                        }
                    }
                    error => DoorError::unavailable(error.to_string()),
                })?;
                serde_json::from_slice(&bytes)
                    .map_err(|error| DoorError::unavailable(error.to_string()))
            })
        })
        .join()
        .map_err(|_| DoorError::unavailable("module transport thread panicked"))?
    }
}

impl super::binding::SessionLookup for ModuleTransport {
    fn session_for_ref(
        &self,
        reference: &cortexkit_role_agent_data::refs::Ref,
    ) -> Result<super::binding::RegisteredSession, super::participant::NotBindable> {
        let request = json!({"method":"agent.session_for_ref", "params":{"ref_kind":reference.ref_kind,"ref":reference.r#ref}});
        let bytes = serde_json::to_vec(&request).map_err(|_| super::participant::NotBindable)?;
        let reply = self
            .request(bytes, Duration::from_secs(30))
            .map_err(|_| super::participant::NotBindable)?;
        serde_json::from_value(
            reply
                .get("result")
                .cloned()
                .ok_or(super::participant::NotBindable)?,
        )
        .map_err(|_| super::participant::NotBindable)
    }
}

impl JsonDoorTransport for ModuleTransport {
    fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, DoorError> {
        let body = serde_json::to_vec(&json!({"method":method,"params":params}))
            .map_err(|error| DoorError::unavailable(error.to_string()))?;
        let reply = self.request(body, timeout)?;
        reply
            .get("result")
            .cloned()
            .ok_or_else(|| DoorError::unavailable("missing module result envelope"))
    }
}

#[derive(Debug)]
pub struct EntorhinalRegistry(pub ModuleTransport);

impl EntorhinalRegistry {
    fn read<P: serde::Serialize, R: DeserializeOwned>(
        &self,
        request: Request<P>,
    ) -> Result<R, String> {
        let body = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
        let reply = self
            .0
            .request(body, Duration::from_secs(30))
            .map_err(|error| error.code)?;
        match serde_json::from_value::<Outcome<R>>(reply).map_err(|error| error.to_string())? {
            Outcome::Success(success) => Ok(success.result),
            Outcome::Refusal(error) => Err(format!("registry unavailable: {}", error.message)),
            _ => Err("registry unavailable: unsupported outcome".into()),
        }
    }
}

impl ProjectRegistry for EntorhinalRegistry {
    fn resolve(&self, path: &Path) -> Result<ResolveReply, String> {
        self.read(Request::new(
            "resolve",
            ResolveParams::new(path.to_str().ok_or("non-UTF8 path")?.to_owned(), None),
        ))
    }
    fn enumerate(&self) -> Result<EnumerateReply, String> {
        self.read(Request::new("enumerate", EnumerateParams::new(None)))
    }
}
