//! Defer carrier polling without holding an executor slot or using worker waits.

use super::super::*;
use crate::commands::blocking_wait::ReplyBudget;
use crate::response_finalize::{DeferredResponseWake, DispatchOutcome, PendingResponse};

pub(super) struct Watch {
    budget: ReplyBudget,
    wake: DeferredResponseWake,
    pending: std::sync::Mutex<Option<PendingResponse>>,
}

impl Watch {
    pub(super) fn new(frame: &Frame) -> Self {
        let received_at = Instant::now();
        let envelope = serde_json::from_slice::<Value>(&frame.body).unwrap_or(Value::Null);
        let mut budget = ReplyBudget::from_envelope(received_at, &envelope);
        budget.deadline = budget.deadline.min(received_at + Duration::from_secs(20));
        Self {
            budget,
            wake: DeferredResponseWake::default(),
            pending: std::sync::Mutex::new(None),
        }
    }

    pub(super) fn start(&self, request: &RawRequest, ctx: Arc<AppContext>) -> Response {
        debug_assert!(!request.worker_session());
        let _wake = self.wake.install();
        match crate::commands::bash_watch::handle_deferred_with_observation_only(
            request,
            ctx,
            self.budget,
            true,
        ) {
            DispatchOutcome::Immediate(response) => response,
            DispatchOutcome::Deferred(pending) => {
                *self.pending.lock().unwrap() = Some(pending);
                // This placeholder stays inside the executor. Only the completed
                // handler response is projected and sent to the carrier.
                Response::success(&request.id, json!({}))
            }
        }
    }

    pub(super) fn is_pending(&self) -> bool {
        self.pending.lock().unwrap().is_some()
    }

    pub(super) async fn finish(&self, ctx: &AppContext) -> Option<Response> {
        let mut pending = self.pending.lock().unwrap().take()?;
        loop {
            if let Some(response) = (pending.poll)(ctx) {
                return Some(response);
            }
            self.wake.notified().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carrier_watch_budget_is_absolute_and_preserves_shorter_client_deadlines() {
        for window_ms in [None, Some(1000), Some(60_000)] {
            let mut envelope = json!({});
            if let Some(ms) = window_ms {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                envelope["deadline_ms"] = (now + ms).into();
            }
            let frame = Frame::build(
                FrameType::Request,
                control_flags(),
                41,
                9,
                1,
                serde_json::to_vec(&envelope).unwrap(),
            )
            .unwrap();
            let watch = Watch::new(&frame);
            let window = watch
                .budget
                .deadline
                .duration_since(watch.budget.received_at);
            assert!(window <= Duration::from_secs(20));
            if window_ms == Some(1000) {
                assert!(window <= Duration::from_millis(1000));
            } else {
                assert_eq!(window, Duration::from_secs(20));
            }
        }
    }
}
