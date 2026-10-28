//! Resolve a carried session from the carrier's scope stamp, not bind labels.

use super::super::*;
use subc_protocol::scope::{ScopeKind, ScopeStamp};

#[derive(Clone, Copy, Debug)]
pub(super) struct ProofCapabilities {
    call_modes: bool,
    on_behalf_of: bool,
}

impl ProofCapabilities {
    fn from_manifest(manifest: &ModuleManifest) -> Self {
        let provides = &manifest.capabilities.provides;
        Self {
            call_modes: provides.iter().any(|s| s == "call-modes/v1"),
            on_behalf_of: provides.iter().any(|s| s == "scope-on-behalf-of/v1"),
        }
    }
}

fn capabilities() -> ProofCapabilities {
    ProofCapabilities::from_manifest(&manifest::build_manifest())
}

fn principal(identity: &RouteIdentity) -> Option<&str> {
    match &identity.spawn_principal {
        AuthenticatedPrincipal::RouteBind { principal_id, .. } => principal_id.as_deref(),
        _ => None,
    }
}

fn same_scope(a: &ScopeStamp, b: &ScopeStamp) -> bool {
    a.owner == b.owner && a.scope_ref == b.scope_ref && a.scope_epoch == b.scope_epoch
}

pub(super) struct Session {
    pub(super) identity: RouteIdentity,
    pub(super) role: tool_provider::CallerRole,
}

/// Read catalog-preset rows without refreshing their retention timestamps.
pub(super) fn resolve(
    ctx: &AppContext,
    carrier: &RouteIdentity,
    routes: &[RouteIdentity],
    capabilities: ProofCapabilities,
) -> Result<Session, ErrorBody> {
    let refusal = super::chunks::refusal;
    let scope = carrier
        .scope
        .as_ref()
        .ok_or_else(|| refusal("session_not_bound"))?;
    if !occipital_carrier_route(carrier) || scope.kind == ScopeKind::Ephemeral {
        return Err(refusal("session_not_bound"));
    }
    let owner = principal_id(&Some(scope.owner.clone()));
    let candidates = routes.iter().filter(|route| {
        principal(route).is_some_and(|id| id != "reserved:occipital")
            && route.scope.as_ref().is_some_and(|s| same_scope(scope, s))
    });
    let mut qualified = Vec::new();
    match scope.kind {
        ScopeKind::Head => {
            qualified.extend(
                candidates
                    .filter(|route| principal(route) == owner.as_deref())
                    .map(|route| (route, false)),
            );
        }
        ScopeKind::Worker => {
            // Even a reads-only Worker needs a route with a saved worker preset:
            // its confinement cannot safely come from the carrier's bind.
            let db = ctx.db().ok_or_else(|| refusal("database_unavailable"))?;
            let conn = db.lock().map_err(|_| refusal("database_unavailable"))?;
            for route in candidates.filter(|route| principal(route) != owner.as_deref()) {
                let key = remote_policy::session_preset_key(route, "worker")
                    .ok_or_else(|| refusal("session_not_bound"))?;
                let presets = crate::db::rich_ui::session_presets(&conn, &key)
                    .map_err(|_| refusal("database_unavailable"))?;
                if presets.iter().any(|preset| preset == "worker") {
                    qualified.push((route, presets.len() != 1));
                }
            }
        }
        _ => {}
    }
    let (first, _) = qualified
        .first()
        .ok_or_else(|| refusal("session_not_bound"))?;
    // Non-root agreement precedes root selection: a different root cannot hide
    // a disagreement about disables, session labels or the binding principal.
    if qualified.iter().any(|(route, _)| {
        route.harness != first.harness
            || route.session != first.session
            || principal(route) != principal(first)
            || route.disabled_tools != first.disabled_tools
    }) {
        return Err(refusal("session_route_ambiguous"));
    }
    let multiple_roots = qualified
        .iter()
        .any(|(route, _)| route.project_root != first.project_root);
    let (policy, ambiguous_preset) = if multiple_roots {
        qualified
            .iter()
            .find(|(route, _)| route.project_root == carrier.project_root)
            .ok_or_else(|| refusal("session_route_ambiguous"))?
    } else {
        &qualified[0]
    };
    if carrier.project_root != policy.project_root
        || carrier.harness != policy.harness
        || carrier.session != policy.session
    {
        return Err(refusal("session_not_bound"));
    }
    if *ambiguous_preset {
        return Err(refusal("session_preset_ambiguous"));
    }
    let proven = scope.owner_authorized && scope.expires_at_ms.is_none() && capabilities.call_modes;
    let role = match scope.kind {
        ScopeKind::Head
            if proven
                && capabilities.on_behalf_of
                && scope.attributes.flow_id.is_none()
                && scope.attributes.on_behalf_of_agent.is_none() =>
        {
            tool_provider::CallerRole::Head
        }
        ScopeKind::Worker if proven => tool_provider::CallerRole::Worker,
        _ => tool_provider::CallerRole::Reader,
    };
    Ok(Session {
        identity: effective_identity(carrier, policy)?,
        role,
    })
}

fn effective_identity(
    carrier: &RouteIdentity,
    policy: &RouteIdentity,
) -> Result<RouteIdentity, ErrorBody> {
    let AuthenticatedPrincipal::RouteBind {
        route_channel,
        route_epoch,
        ..
    } = &carrier.spawn_principal
    else {
        return Err(super::chunks::refusal("session_not_bound"));
    };
    let id = principal(policy).ok_or_else(|| super::chunks::refusal("session_not_bound"))?;
    Ok(RouteIdentity(Arc::new(RouteIdentityData {
        root: policy.root.clone(),
        project_root: policy.project_root.clone(),
        harness: policy.harness.clone(),
        session: policy.session.clone(),
        disabled_tools: policy.disabled_tools.clone(),
        trust: BindTrust::Untrusted,
        spawn_principal: AuthenticatedPrincipal::RouteBind {
            trust: crate::sandbox_spawn::PrincipalTrust::Untrusted,
            route_channel: *route_channel,
            route_epoch: *route_epoch,
            project_root: policy.project_root.clone(),
            harness: policy.harness.clone(),
            session_id: policy.session.clone(),
            principal_id: Some(id.into()),
        },
        role: carrier.role,
        scope: carrier.scope.clone(),
        call_mode: carrier.call_mode.clone(),
        tool_result_body: carrier.tool_result_body,
        consumer_elicitation_capable: false,
        run_owner: None,
        run_scope: OnceLock::new(),
        made_tool_call: AtomicBool::new(true),
    })))
}

impl Session {
    pub(super) fn admit(&self, ctx: &AppContext, name: &str) -> Result<(), ErrorBody> {
        tool_provider::admit_call_mode(name, &self.identity.call_mode)?;
        remote_policy::admit_confined(ctx, &self.identity, name)?;
        tool_provider::admit_role_name(
            name,
            &self.identity.disabled_tools,
            crate::bash_background::powershell_available(),
            &self.identity.session,
            true,
            self.role,
        )
    }

    /// Install the rebuilt principal even for work that moves to another thread.
    /// A deferred handler must capture this principal before leaving the scope.
    pub(super) fn with_policy<T>(
        &self,
        ctx: &AppContext,
        id: &str,
        name: &str,
        args: Value,
        work: impl FnOnce(Value) -> T,
    ) -> Result<T, Response> {
        crate::sandbox_spawn::with_authenticated_principal(
            self.identity.spawn_principal.clone(),
            || {
                call_policy::with_tool_call_policy(
                    ctx,
                    &self.identity,
                    id,
                    crate::access_policy::AskRoute::Deny,
                    BindTrust::Untrusted,
                    name,
                    args,
                    work,
                    |result| result,
                )
            },
        )
    }
}

/// Resolve and execute off the frame loop: neither preset nor confinement
/// SELECTs may hold health checks or unrelated routes behind the database lock.
#[allow(clippy::too_many_arguments)]
pub(in crate::subc) async fn submit(
    tx: &WriterSender,
    frame: &Frame,
    carrier: RouteIdentity,
    routes: &HashMap<RouteChannel, RouteIdentity>,
    executor: &Arc<Executor>,
    active: &ActiveToolCalls,
    metrics: &Arc<DispatchPathMetrics>,
    operation: super::admission::Operation,
    dispatch: DispatchFn,
) -> Result<(), SubcError> {
    let route = route_key(frame.header.channel, frame.header.epoch);
    let id = format!("subc-{}-{}", route.channel, frame.header.corr);
    let job_id = id.clone();
    let routes = routes.values().cloned().collect::<Vec<_>>();
    let name = operation.entry["target"]["tool"]
        .as_str()
        .expect("validated target")
        .to_owned();
    let entry = operation.entry.clone();
    let ledger_key = serde_json::from_slice::<Value>(&frame.body)
        .ok()
        .and_then(|body| {
            body["call_key"]
                .as_str()
                .map(|key| tool_provider::LedgerEdge::key(&carrier, key))
        });
    let rx = submit_active_tool_call(
        executor,
        active,
        route,
        frame.header.corr,
        carrier.root.clone(),
        command_lane(&name),
        id.clone(),
        RouteDetachPolicy::RetainForReplay,
        &name,
        RequestFrameMeta {
            ver: frame.header.ver,
            flags: frame.header.flags,
        },
        Box::new(move |ctx| {
            let session = match resolve(ctx, &carrier, &routes, capabilities()) {
                Ok(session) => session,
                Err(error)
                    if matches!(
                        error.code.as_str(),
                        "session_not_bound" | "session_route_ambiguous"
                    ) =>
                {
                    return Response::success(job_id, json!({"session_error": error}));
                }
                Err(error) => {
                    return Response::success(
                        job_id,
                        json!({"body":super::carrier::error_body(&error.code)}),
                    )
                }
            };
            if let Err(error) = session.admit(ctx, &name) {
                return Response::success(
                    job_id,
                    json!({"body":super::carrier::error_body(&error.code)}),
                );
            }
            // Calls specifying a task fail closed until task resolution and the
            // bash output/watch handlers are connected to carrier dispatch.
            if operation.task.is_some() {
                return Response::success(
                    job_id,
                    json!({"body":super::carrier::error_body("task_not_found")}),
                );
            }
            let args = match operation.translate_query(None, ctx.config().bash.watch_sync_max_ms) {
                Ok(args) => args,
                Err(error) => {
                    return Response::success(
                        job_id,
                        json!({"body":super::carrier::error_body(&error.code)}),
                    )
                }
            };
            let identity = &session.identity;
            let mut format = crate::subc_format::FormatContext::from_tool_call(
                &name,
                &args,
                &identity.project_root,
            );
            format.worker_session = false;
            let tool_ctx = ToolCallContext {
                project_root: identity.project_root.clone(),
                session_id: Some(identity.session.clone()),
                request_id: job_id.clone(),
                diagnostics_on_edit: false,
                preview: false,
                edit_slot_survives: None,
                report_registration_downgrade: false,
                standard_edit_grammar: true,
                disabled_tools: Some(identity.disabled_tools.clone()),
                worker_session: false,
                host_tool_names: None,
            };
            let result = log_ctx::with_session(Some(identity.session.clone()), || {
                session
                    .with_policy(ctx, &job_id, &name, args, |args| {
                        let ToolCallOutcome::Unary(result) = run_tool_call(
                            &name, args, &format, &tool_ctx, ctx, &dispatch, None, None,
                        );
                        result.response
                    })
                    .unwrap_or_else(|response| response)
            });
            tool_provider::note_native_outcome(ctx, ledger_key.as_ref(), &result);
            Response::success(
                job_id,
                json!({"body":super::carrier::response_body(&entry, &result)}),
            )
        }),
    );
    let tx = tx.clone();
    let metrics = metrics.clone();
    let active = active.clone();
    let request = frame.clone();
    tokio::spawn(async move {
        let response = await_executor_response(rx, id).await;
        if !claim_active_tool_call(&active, route, request.header.corr) {
            return;
        }
        let reply = if let Some(error) = response.data.get("session_error") {
            Frame::build_with_version(
                request.header.ver,
                FrameType::Error,
                request.header.flags,
                route.channel,
                route.epoch,
                request.header.corr,
                serde_json::to_vec(error).expect("error serializes"),
            )
            .map_err(SubcError::FrameBuild)
        } else {
            wire::build_carrier_response_frame(
                &request,
                None,
                response
                    .data
                    .get("body")
                    .cloned()
                    .unwrap_or_else(|| super::carrier::error_body("executor_failure")),
            )
        };
        match reply {
            Ok(reply) => {
                if let Err(error) =
                    send_reliable_writer_frame(&tx, &metrics, reply, "carrier session reply").await
                {
                    log::warn!("carrier reply could not be queued: {error}");
                }
            }
            Err(error) => log::warn!("carrier reply could not be built: {error}"),
        }
        finish_active_tool_call(&active, route, request.header.corr);
    });
    Ok(())
}

#[cfg(test)]
#[path = "session/tests.rs"]
mod tests;
