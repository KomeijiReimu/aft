use super::*;
use crate::gh_shim_speech::{Code, Refusal, ScopeRole};

struct DispatchItem {
    body: Value,
    selector: ScopeSelector,
    _slot: tokio::sync::OwnedSemaphorePermit,
}

pub(super) fn unknown() -> RelayReply {
    RelayReply::refused("outcome_unknown", "plexus", "this GitHub write was already queued and its outcome cannot be confirmed; do not repeat it with a new request key")
}

pub(super) async fn post_bound_background<T: RelayTransport>(
    transport: &T,
    redeemed: &crate::gh_shim_ticket::Redeemed,
    stamp: &ScopeStamp,
    params: &Value,
    routes: &RouteScopes,
    nonce: &str,
    request: &Value,
) -> Result<RelayReply, Refusal> {
    let invalid = || Refusal::new(Code::AuthorityUnavailable, "snapshot_invalid");
    let launch = redeemed.launch.as_ref().ok_or_else(invalid)?;
    launch.validate()?;
    let service = routes
        .speech
        .as_ref()
        .ok_or_else(|| Refusal::new(Code::AuthorityUnavailable, "not_serving_mode"))?;
    if !service.try_serve() {
        return Err(Refusal::new(
            Code::AuthorityUnavailable,
            "serving_lock_unavailable",
        ));
    }
    let ticket = params
        .get("ticket")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let warm = crate::gh_shim_ticket::speech_for_ticket(ticket).ok_or_else(invalid)?;
    if !warm.stored.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(Refusal::new(
            Code::AuthorityUnavailable,
            "start_policy_missing",
        ));
    }
    if let Some(error) = warm
        .failure
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone()
    {
        return Err(error);
    }
    if warm.prepared.context.service.store.path() != service.store.path() {
        return Err(invalid());
    }
    let digest = blake3::derive_key(
        "aft-gh-bound-request-v1",
        &serde_json::to_vec(request).map_err(|_| invalid())?,
    );
    match service
        .store
        .legacy_dispatch_status(nonce, &warm.incarnation, &digest)?
    {
        Some(
            crate::db::gh_speech::LegacyDispatchStatus::Queued
            | crate::db::gh_speech::LegacyDispatchStatus::Settled,
        ) => return Ok(unknown()),
        None => {}
    }
    service.check_pending(
        Some(&warm.incarnation),
        launch,
        &redeemed.session_id,
        &redeemed.task_id,
    )?;
    let stored = service.store.get(&warm.incarnation)?;
    if stored.record.launch != *launch {
        return Err(invalid());
    }
    let start = stored
        .record
        .policy
        .as_ref()
        .ok_or_else(|| Refusal::new(Code::AuthorityUnavailable, "start_policy_missing"))?;
    let (current, _) = service
        .register_accepted_policy()?
        .ok_or_else(|| Refusal::new(Code::AuthorityUnavailable, "current_manifest_unverifiable"))?;
    let invocation = serde_json::from_value(params.get("invocation").cloned().ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    crate::gh_shim::validate_speech_policy(start, &current, request, &invocation)?;
    let policy_generation = service.store.advance_policy(&current)?;
    let run = crate::gh_shim_speech::service::run_nonce().ok_or_else(invalid)?;
    let selector = scope_selector(stamp);
    let selector_json = serde_json::to_string(stamp).map_err(|_| invalid())?;
    service
        .store
        .prepare_request(nonce, &warm.incarnation, &digest, &selector_json)?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let gate = {
        let _local = service
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        service.check_pending(
            Some(&warm.incarnation),
            launch,
            &redeemed.session_id,
            &redeemed.task_id,
        )?;
        #[cfg(test)]
        service.test_before_final_gate();
        service.store.final_legacy_gate(
            &warm.incarnation,
            nonce,
            stored.generation,
            policy_generation,
            &current,
            run,
            || {
                if !service.try_serve() {
                    return Err(Refusal::new(
                        Code::AuthorityUnavailable,
                        "serving_lock_unavailable",
                    ));
                }
                let slot = service.try_legacy_slot()?;
                // This local enqueue is the ordered dispatch boundary for the bound
                // compatibility transport only. The receiver is polled after commit.
                sender
                    .send(DispatchItem {
                        body: github_call(
                            json!({"op":"bot_request","request_nonce":nonce,"request":request}),
                        ),
                        selector,
                        _slot: slot,
                    })
                    .map_err(|_| Refusal::new(Code::AuthorityUnavailable, "admission_raced"))?;
                #[cfg(test)]
                service.test_bound_enqueued();
                Ok(())
            },
        )
    };
    match gate {
        Ok(()) => {}
        Err(crate::db::gh_speech::GateError::BeforeSend(error)) => return Err(error),
        Err(crate::db::gh_speech::GateError::AfterSend) => return Ok(unknown()),
    }
    #[cfg(test)]
    if !service.test_after_bound_commit() {
        return Ok(unknown());
    }
    let item = match receiver.await {
        Ok(item) => item,
        Err(_) => return Ok(unknown()),
    };
    if !service.try_serve() {
        return Ok(unknown());
    }
    let dispatch_generation = service.generation();
    let route_role = if launch.run.as_ref() == Some(stamp) {
        ScopeRole::Run
    } else if launch.run.is_some() {
        ScopeRole::Head
    } else {
        ScopeRole::Authority
    };
    let reply = match transport
        .plexus(
            &redeemed.project_root,
            &redeemed.session_id,
            Some(&item.selector),
            item.body,
        )
        .await
    {
        Ok(reply) => {
            let facade = facade_reply(&reply);
            let result = facade.get("result").unwrap_or(&facade);
            if crate::gh_shim_speech::partner::scope_end_role(result, route_role, false).is_some() {
                let _ = service.record_rpc_end(
                    stamp,
                    route_role,
                    &item.selector,
                    &dispatch_generation,
                    crate::gh_shim_speech::scope::ScopedRpcEndSource::Provider,
                );
            }
            RelayReply::relayed(reply)
        }
        Err(TransportError::ScopeEnded {
            selector,
            message: _,
        }) => {
            let proof = service.record_rpc_end(
                stamp,
                route_role,
                &selector,
                &dispatch_generation,
                crate::gh_shim_speech::scope::ScopedRpcEndSource::RouteOpen,
            );
            match proof {
                Err(error) if error.code == Code::ScopeUnknown => RelayReply::task_refused(error),
                _ => {
                    RelayReply::task_refused(Refusal::scoped(Code::ScopeEnded, "ended", route_role))
                }
            }
        }
        Err(error) => {
            if matches!(&error, TransportError::Refused { code, .. } if code == subc_protocol::error_codes::SCOPE_ENDED)
            {
                service.observe_unqualified_end(
                    launch
                        .required_scopes()
                        .into_iter()
                        .map(|(role, scope)| (role, scope.clone()))
                        .collect(),
                );
            }
            transport_refusal("plexus", error)
        }
    };
    if reply.data.get("refusal_code").and_then(Value::as_str) != Some("outcome_unknown") {
        if let Err(error) = service
            .store
            .settle_legacy_dispatch(nonce, &warm.incarnation, run)
        {
            log::warn!(
                "legacy speech reply received but dispatch settlement failed: {}",
                error.reason
            );
        }
    }
    Ok(reply)
}
