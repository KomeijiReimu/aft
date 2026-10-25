//! Bind publication and control replies do not wait for native tool calls to
//! record their outcomes in the call ledger.

use super::wire::WriterEnqueueOutcome;
use super::*;
use std::sync::atomic::AtomicU8;

const QUEUED: u8 = 0;
const WRITING: u8 = 1;
const WRITTEN: u8 = 2;
const CANCELLED: u8 = 3;

#[derive(Clone, Default, Debug)]
pub(super) struct AckPublication(Arc<AtomicU8>);

impl AckPublication {
    pub(super) fn begin_write(&self) -> bool {
        self.0
            .compare_exchange(QUEUED, WRITING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
    pub(super) fn written(&self) {
        self.0.store(WRITTEN, Ordering::Release);
    }
    pub(super) fn cancel_before_write(&self) -> bool {
        self.0
            .compare_exchange(QUEUED, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

pub(super) enum ControlCompletion {
    ConfigureReady(RouteBindCompletion),
    AckWritten(RouteBindCompletion),
    AckCancelled(Box<ControlCompletion>),
    ManagementAckWritten {
        route: RouteChannel,
        principal: Option<Principal>,
        corr: u64,
    },
    WriteFailed,
}

impl ControlCompletion {
    pub(super) fn corr(&self) -> u64 {
        match self {
            Self::ConfigureReady(done) | Self::AckWritten(done) => done.corr,
            Self::ManagementAckWritten { corr, .. } => *corr,
            Self::AckCancelled(done) => done.corr(),
            Self::WriteFailed => 0,
        }
    }
}

pub(super) struct AckCompletion {
    permit: mpsc::OwnedPermit<ControlCompletion>,
    completion: ControlCompletion,
    metrics: Arc<DispatchPathMetrics>,
    _slot: tokio::sync::OwnedSemaphorePermit,
}

impl AckCompletion {
    pub(super) fn publish(self, cancelled: bool) {
        let completion = if cancelled {
            ControlCompletion::AckCancelled(Box::new(self.completion))
        } else {
            self.completion
        };
        self.metrics
            .control_completion_queued
            .fetch_add(1, Ordering::Relaxed);
        let _ = self.permit.send(completion);
    }
}

pub(super) struct A0Egress {
    pub(super) writer: WriterSender,
    completions: mpsc::Sender<ControlCompletion>,
    stop: PersistentCancelSignal,
    publications: StdMutex<HashMap<RouteChannel, AckPublication>>,
    slots: Arc<tokio::sync::Semaphore>,
    probe: Option<SubcTestLifecycleProbe>,
}

impl A0Egress {
    pub(super) fn new(writer: WriterSender, completions: mpsc::Sender<ControlCompletion>) -> Self {
        Self {
            writer,
            completions,
            stop: PersistentCancelSignal::new(),
            publications: StdMutex::new(HashMap::new()),
            slots: Arc::new(tokio::sync::Semaphore::new(WRITER_QUEUE_CAPACITY)),
            probe: None,
        }
    }

    pub(super) fn with_probe(mut self, probe: Option<SubcTestLifecycleProbe>) -> Self {
        self.probe = probe;
        self
    }

    pub(super) fn stop(&self) {
        for publication in self.publications.lock().unwrap().values() {
            publication.cancel_before_write();
        }
        self.stop.cancel();
    }

    pub(super) fn cancel(&self, route: RouteChannel) {
        if let Some(publication) = self.publications.lock().unwrap().get(&route) {
            publication.cancel_before_write();
        }
    }

    pub(super) fn retire(&self, route: RouteChannel) {
        self.publications.lock().unwrap().remove(&route);
    }

    pub(super) fn enqueue_ack(
        &self,
        route: RouteChannel,
        frame: Frame,
        completion: ControlCompletion,
        metrics: &Arc<DispatchPathMetrics>,
    ) -> Result<AckPublication, ControlCompletion> {
        let Ok(slot) = Arc::clone(&self.slots).try_acquire_owned() else {
            return Err(completion);
        };
        // Reserve the completion before exposing the ACK to the socket. The
        // writer can then publish its event synchronously, before a fast peer's
        // first route request is polled on the shared current-thread runtime.
        let Ok(permit) = self.completions.clone().try_reserve_owned() else {
            return Err(completion);
        };
        let publication = AckPublication::default();
        let corr = completion.corr();
        self.publications
            .lock()
            .unwrap()
            .insert(route, publication.clone());
        let (mut outgoing, receipt) = WriterFrame::with_ack_receipt(frame, publication.clone());
        outgoing.set_ack_completion(AckCompletion {
            permit,
            completion,
            metrics: Arc::clone(metrics),
            _slot: slot,
        });
        let writer = self.writer.clone();
        let completions = self.completions.clone();
        let metrics = Arc::clone(metrics);
        let stop = self.stop.clone();
        let probe = self.probe.clone();
        let pending = match wire::try_enqueue_writer_item(&writer, &metrics, outgoing) {
            WriterEnqueueOutcome::Enqueued => {
                if let Some(probe) = self.probe.as_ref() {
                    probe.route_bind_ack_queued(corr);
                }
                None
            }
            WriterEnqueueOutcome::Full(outgoing) => Some(outgoing),
            WriterEnqueueOutcome::Closed => None,
        };
        tokio::spawn(async move {
            let result = tokio::select! {
                biased;
                _ = stop.cancelled() => return,
                result = async {
                    if let Some(outgoing) = pending {
                        wire::send_reliable_writer_item(&writer, &metrics, outgoing, "A0 bind ACK").await?;
                        if let Some(probe) = probe.as_ref() { probe.route_bind_ack_queued(corr); }
                    }
                    receipt.await.map_err(|_| SubcError::WriterClosed)?
                } => result,
            };
            let completion = match result {
                Ok(_) => return,
                Err(_) => ControlCompletion::WriteFailed,
            };
            tokio::select! {
                biased;
                _ = stop.cancelled() => {},
                _ = send_counted_channel(&completions, &metrics.control_completion_queued, completion) => {},
            }
        });
        Ok(publication)
    }
}

impl Drop for A0Egress {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncWrite;

    struct HeldWriter {
        entered: Option<oneshot::Sender<()>>,
        release: oneshot::Receiver<()>,
        released: bool,
        bytes: Arc<StdMutex<Vec<u8>>>,
    }

    impl AsyncWrite for HeldWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
            }
            if !self.released {
                match Pin::new(&mut self.release).poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(_) => self.released = true,
                }
            }
            self.bytes.lock().unwrap().extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn a0_sender_is_captured_before_ledger_proxy_wraps_the_bulk_lane() {
        let source = include_str!("mod.rs");
        let body = source
            .split_once("async fn run_module_loop<")
            .unwrap()
            .1
            .split_once("fn classify_connection_end(")
            .unwrap()
            .0;
        let raw = body.find("let raw_writer_tx = writer_tx.clone();").unwrap();
        let proxy = body.find("ledger_edge.proxy(").unwrap();
        assert!(
            raw < proxy,
            "A0 replies would queue behind native ledger waits"
        );
        assert!(body.contains("A0Egress::new(raw_writer_tx, control_completion_tx.clone())"));
        let management = body.split_once("handle_management_request(").unwrap().1;
        assert!(management.trim_start().starts_with("&a0.writer,"));
    }

    #[test]
    fn cancellation_can_retract_only_an_ack_that_has_not_started_writing() {
        let cancelled = AckPublication::default();
        assert!(cancelled.cancel_before_write());
        assert!(!cancelled.begin_write());
        let writing = AckPublication::default();
        assert!(writing.begin_write());
        assert!(!writing.cancel_before_write());
        writing.written();
        assert!(!writing.cancel_before_write());
    }

    #[tokio::test]
    async fn stopping_egress_retracts_a_queued_ack_before_it_reaches_the_socket() {
        let (writer, mut frames) = mpsc::channel(1);
        let (events, mut completed) = mpsc::channel(1);
        let a0 = A0Egress::new(writer, events);
        assert!(a0
            .enqueue_ack(
                route_key(7, 1),
                route_bind_ack_frame(PROTOCOL_VERSION, 891, control_flags()).unwrap(),
                ControlCompletion::ManagementAckWritten {
                    route: route_key(7, 1),
                    principal: None,
                    corr: 891
                },
                &Arc::new(DispatchPathMetrics::new())
            )
            .is_ok());
        let mut queued = frames.recv().await.unwrap();
        a0.stop();
        assert!(!queued.begin_ack_write());
        assert!(matches!(
            completed.recv().await,
            Some(ControlCompletion::AckCancelled(_))
        ));
    }

    #[tokio::test]
    async fn ack_publication_reserves_capacity_before_spawning_a_waiter() {
        let (writer, mut frames) = mpsc::channel(1);
        let (events, _completed) = mpsc::channel(1);
        let a0 = A0Egress::new(writer, events);
        let held = a0
            .slots
            .acquire_many(WRITER_QUEUE_CAPACITY as u32)
            .await
            .unwrap();
        let result = a0.enqueue_ack(
            route_key(7, 1),
            route_bind_ack_frame(PROTOCOL_VERSION, 891, control_flags()).unwrap(),
            ControlCompletion::ManagementAckWritten {
                route: route_key(7, 1),
                principal: None,
                corr: 891,
            },
            &Arc::new(DispatchPathMetrics::new()),
        );
        assert!(matches!(
            result,
            Err(ControlCompletion::ManagementAckWritten { .. })
        ));
        assert!(frames.try_recv().is_err());
        assert!(a0.publications.lock().unwrap().is_empty());
        drop(held);
    }

    #[tokio::test]
    async fn ack_completion_waits_for_actual_write_not_queue_acceptance() {
        let metrics = Arc::new(DispatchPathMetrics::new());
        let (tx, rx) = mpsc::channel(8);
        let (pong, pong_rx) = mpsc::channel(8);
        let (done, mut completions) = mpsc::channel(8);
        let a0 = A0Egress::new(tx, done);
        let (entered, entering) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let bytes = Arc::new(StdMutex::new(Vec::new()));
        let writer = spawn_writer_task(
            HeldWriter {
                entered: Some(entered),
                release: released,
                released: false,
                bytes: Arc::clone(&bytes),
            },
            rx,
            pong_rx,
            Arc::clone(&metrics),
        );
        assert!(a0
            .enqueue_ack(
                route_key(7, 1),
                route_bind_ack_frame(PROTOCOL_VERSION, 891, control_flags()).unwrap(),
                ControlCompletion::ManagementAckWritten {
                    route: route_key(7, 1),
                    principal: None,
                    corr: 891,
                },
                &metrics,
            )
            .is_ok());
        entering.await.unwrap();
        assert!(
            completions.try_recv().is_err(),
            "ACK published before write_all finished"
        );
        assert!(bytes.lock().unwrap().is_empty());
        release.send(()).unwrap();
        assert!(matches!(
            completions.recv().await,
            Some(ControlCompletion::ManagementAckWritten { .. })
        ));
        assert!(!bytes.lock().unwrap().is_empty());
        a0.stop();
        drop(a0);
        drop(pong);
        writer.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn control_ack_bypasses_a_real_ledger_detach_wait() {
        let (_dir, root) = test_support::test_root("a0-held-ledger-detach");
        let executor = Arc::new(Executor::new());
        assert!(executor.register_actor(root.clone(), test_support::test_ctx()));
        let (entered, entering) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let held = executor.submit_async(
            root.clone(),
            Lane::Mutating,
            "held-egress-lane".into(),
            Box::new(move |_| {
                entered.send(()).unwrap();
                let _ = released.recv_timeout(Duration::from_secs(10));
                Response::success("held-egress-lane", json!({}))
            }),
        );
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
        let metrics = Arc::new(DispatchPathMetrics::new());
        let (actual, mut receiving) = mpsc::channel(8);
        let (edge, _ready) = tool_provider::LedgerEdge::new();
        edge.retain_shell_for_egress_test(root.clone(), route_key(5, 1), 1);
        let (proxy, proxy_task) =
            edge.proxy(actual.clone(), Arc::clone(&executor), Arc::clone(&metrics));
        proxy
            .send(
                build_error_frame(
                    PROTOCOL_VERSION,
                    5,
                    1,
                    1,
                    control_flags(),
                    "detached",
                    "running",
                )
                .unwrap()
                .into(),
            )
            .await
            .unwrap();
        let queued = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if executor.try_mutating_job_state_label(&root, "ledger-detach") == Some("queued") {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        let (completed, mut completion_rx) = mpsc::channel(8);
        let a0 = A0Egress::new(actual, completed);
        assert!(a0
            .enqueue_ack(
                route_key(7, 1),
                route_bind_ack_frame(PROTOCOL_VERSION, 891, control_flags()).unwrap(),
                ControlCompletion::ManagementAckWritten {
                    route: route_key(7, 1),
                    principal: None,
                    corr: 891,
                },
                &metrics,
            )
            .is_ok());
        let ack = tokio::time::timeout(Duration::from_secs(1), receiving.recv()).await;
        let _ = release.send(());
        let _ = held.await;
        queued.expect("ledger-detach was never queued behind the holder");
        let mut ack = ack.expect("A0 ACK waited on ledger-detach").unwrap();
        assert_eq!(ack.header.corr, 891);
        assert!(ack.begin_ack_write());
        ack.finish_ack_write(true);
        assert!(matches!(
            completion_rx.recv().await,
            Some(ControlCompletion::ManagementAckWritten { .. })
        ));
        drop(proxy);
        proxy_task.await.unwrap();
        a0.stop();
    }
}
