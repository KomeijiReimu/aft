use super::*;

fn run(reference: &str, epoch: u64) -> ScopeStamp {
    ScopeStamp::new(
        subc_protocol::Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        reference,
        epoch,
        subc_protocol::scope::ScopeKind::Ephemeral,
    )
}

#[test]
fn expect_is_a_top_level_sibling_and_has_exactly_the_two_required_members() {
    let body = BotRequest::new(
        json!({"action":"issue comment"}),
        "nonce-a",
        Binding {
            app_handle_id: "app-a".into(),
            repo_binding_generation: 0,
        },
        None,
    )
    .unwrap();
    assert_eq!(
        body.value(),
        json!({"op":"bot_request","request":{"action":"issue comment"},"request_nonce":"nonce-a","expect":{"app_handle_id":"app-a","repo_binding_generation":0}})
    );
    assert!(serde_json::from_value::<Binding>(
        json!({"app_handle_id":"app-a","repo_binding_generation":0,"other":true})
    )
    .is_err());
    assert!(serde_json::from_value::<Binding>(json!({"app_handle_id":"app-a"})).is_err());
    assert!(serde_json::from_value::<Binding>(
        json!({"app_handle_id":"app-a","repo_binding_generation":-1})
    )
    .is_err());
}

#[test]
fn run_scope_wire_is_separate_from_the_head_route_and_expect() {
    let body = BotRequest::new(
        json!({"action":"issue comment"}),
        "nonce-a",
        Binding {
            app_handle_id: "app-a".into(),
            repo_binding_generation: 4,
        },
        Some(&run("run-a", 9)),
    )
    .unwrap();
    assert_eq!(
        body.value()["run_scope"],
        json!({"owner":"reserved:prefrontal-core","ref":"run-a","epoch":9})
    );
    assert!(serde_json::from_value::<RunSelector>(
        json!({"owner":"reserved:prefrontal-core","ref":"run-a","epoch":9,"extra":false})
    )
    .is_err());
    assert!(serde_json::from_value::<RunSelector>(
        json!({"owner":"reserved:prefrontal-core","ref":"run-a"})
    )
    .is_err());
    assert!(serde_json::from_value::<RunSelector>(
        json!({"owner":"reserved:prefrontal-core","ref":"run-a","epoch":-1})
    )
    .is_err());
}

#[test]
fn run_scope_is_not_in_the_nonce_fingerprint_but_expect_is() {
    let make = |scope: &ScopeStamp, handle: &str, generation: u64| {
        BotRequest::new(
            json!({"action":"issue comment"}),
            "nonce-a",
            Binding {
                app_handle_id: handle.into(),
                repo_binding_generation: generation,
            },
            Some(scope),
        )
        .unwrap()
    };
    let a = make(&run("run-a", 9), "app-a", 4);
    let b = make(&run("run-b", 10), "app-a", 4);
    assert_eq!(a.payload_digest(), b.payload_digest());
    assert_ne!(
        a.payload_digest(),
        make(&run("run-a", 9), "app-b", 4).payload_digest()
    );
    assert_ne!(
        a.payload_digest(),
        make(&run("run-a", 9), "app-a", 5).payload_digest()
    );
}

#[test]
fn unconfirmed_plex_placement_cannot_authorize_classic_or_codemode_forwarding() {
    for codemode in [false, true] {
        let err = require_plex_guards(codemode).unwrap_err();
        assert_eq!(err.code, Code::AuthorityUnavailable);
        assert_eq!(err.reason, "guard_unsupported");
    }
    assert_eq!(SUBC_RESERVATION_LAST_CHECKED, "0.32.3");
}

#[tokio::test]
async fn unpublished_subc_slot_stays_unavailable_without_an_async_send_fallback() {
    let result = reserve_bot_request(json!({"op":"bot_request"})).await;
    let refusal = result
        .err()
        .expect("the published client cannot reserve a send slot");
    assert_eq!(refusal.code, Code::AuthorityUnavailable);
    assert_eq!(refusal.reason, "guard_unsupported");
}

#[test]
fn sent_legs_never_become_a_pre_write_refusal_even_with_a_conflicting_transmission() {
    assert!(map_refusal(&json!({"status":"refused","code":"scope_ended","scope_role":"run","transmission":"not_sent","legs_sent":["add_issue_comment"]}),ScopeRole::Head).is_none());
    assert!(map_refusal(
        &json!({"status":"refused","code":"scope_ended","scope_role":"run"}),
        ScopeRole::Head
    )
    .is_none());
}

#[test]
fn contradictory_or_unknown_partner_errors_are_not_blessed_as_pre_write_refusals() {
    assert!(map_refusal(&json!({"status":"refused","code":"invalid_request","refusal_code":"scope_ended","transmission":"not_sent"}),ScopeRole::Authority).is_none());
    assert!(map_refusal(
        &json!({"status":"refused","code":"brand_new_error","transmission":"not_sent"}),
        ScopeRole::Authority
    )
    .is_none());
    assert!(map_refusal(&json!({"status":"refused","code":"run_scope_not_child","scope_role":"route","transmission":"not_sent"}),ScopeRole::Head).is_none());
}
