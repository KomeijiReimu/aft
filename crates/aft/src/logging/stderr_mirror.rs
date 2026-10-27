//! Best-effort stderr for supervised modules, independent of the file writer.

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(super) const QUEUE_CAPACITY: usize = 256;
const MAX_RECORD_BYTES: usize = 64 * 1024;

#[derive(Default)]
pub(super) struct MirrorHealth {
    dropped_lines: AtomicU64,
    dropped_flushes: AtomicU64,
    write_errors: AtomicU64,
    flush_errors: AtomicU64,
    start_failures: AtomicU64,
}

impl MirrorHealth {
    pub(super) fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "dropped_lines_total": self.dropped_lines.load(Ordering::Relaxed),
            "dropped_flushes_total": self.dropped_flushes.load(Ordering::Relaxed),
            "write_errors_total": self.write_errors.load(Ordering::Relaxed),
            "flush_errors_total": self.flush_errors.load(Ordering::Relaxed),
            "worker_start_failures_total": self.start_failures.load(Ordering::Relaxed),
        })
    }

    fn drop_message(&self, message: &Message) {
        match message {
            Message::Record(bytes) => {
                self.dropped_lines
                    .fetch_add(super::log_line_count(bytes), Ordering::Relaxed);
            }
            Message::Flush | Message::Drain(_) => {
                self.dropped_flushes.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

enum Message {
    Record(Vec<u8>),
    Flush,
    Drain(SyncSender<bool>),
}

#[derive(Clone)]
pub(super) struct Mirror {
    tx: Option<SyncSender<Message>>,
    health: Arc<MirrorHealth>,
}

impl Mirror {
    pub(super) fn spawn<W: Write + Send + 'static>(
        mut sink: W,
        capacity: usize,
        health: Arc<MirrorHealth>,
    ) -> io::Result<(Self, JoinHandle<()>)> {
        let (tx, rx) = mpsc::sync_channel(capacity);
        let worker_health = Arc::clone(&health);
        let worker = thread::Builder::new()
            .name("aft-stderr-mirror".into())
            .spawn(move || {
                while let Ok(message) = rx.recv() {
                    // No channel or file-sink lock is held during stderr I/O.
                    let result = match &message {
                        Message::Record(bytes) => sink.write_all(bytes),
                        Message::Flush | Message::Drain(_) => sink.flush(),
                    };
                    if result.is_err() {
                        match &message {
                            Message::Record(_) => {
                                worker_health.write_errors.fetch_add(1, Ordering::Relaxed);
                            }
                            Message::Flush | Message::Drain(_) => {
                                worker_health.flush_errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        worker_health.drop_message(&message);
                    }
                    if let Message::Drain(done) = &message {
                        let _ = done.send(result.is_ok());
                    }
                }
            })?;
        Ok((
            Self {
                tx: Some(tx),
                health,
            },
            worker,
        ))
    }

    pub(super) fn disabled(health: Arc<MirrorHealth>) -> Self {
        health.start_failures.fetch_add(1, Ordering::Relaxed);
        Self { tx: None, health }
    }

    pub(super) fn record(&self, bytes: &[u8]) {
        // Reject the entire record before copying, rather than leaving a partial
        // line in the mirror. Both queue length and queued bytes stay bounded.
        if self.tx.is_none() || bytes.len() > MAX_RECORD_BYTES {
            self.health
                .dropped_lines
                .fetch_add(super::log_line_count(bytes), Ordering::Relaxed);
            return;
        }
        self.enqueue(Message::Record(bytes.to_vec()));
    }

    pub(super) fn flush(&self) {
        self.enqueue(Message::Flush);
    }

    // Only process teardown waits for this fence. Ordinary logger flushes stay
    // nonblocking, including when stderr is full or its sink is wedged.
    pub(super) fn drain_on_exit(&self, timeout: Duration) -> bool {
        let Some(tx) = self.tx.as_ref() else {
            return false;
        };
        let deadline = Instant::now() + timeout;
        let (done, received) = mpsc::sync_channel(1);
        let mut message = Message::Drain(done);
        loop {
            match tx.try_send(message) {
                Ok(()) => break,
                Err(TrySendError::Disconnected(message)) => {
                    self.health.drop_message(&message);
                    return false;
                }
                Err(TrySendError::Full(returned)) => message = returned,
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.health.drop_message(&message);
                return false;
            }
            thread::sleep(remaining.min(Duration::from_millis(1)));
        }
        received
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(false)
    }

    fn enqueue(&self, message: Message) {
        let Some(tx) = self.tx.as_ref() else {
            self.health.drop_message(&message);
            return;
        };
        match tx.try_send(message) {
            Ok(()) => {}
            Err(TrySendError::Full(message) | TrySendError::Disconnected(message)) => {
                self.health.drop_message(&message);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    struct GateWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
        write_gate: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
        flush_gate: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
    }

    impl Write for GateWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some((entered, release)) = self.write_gate.take() {
                entered.send(()).unwrap();
                let _ = release.recv_timeout(Duration::from_secs(5));
            }
            self.bytes.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if let Some((entered, release)) = self.flush_gate.take() {
                entered.send(()).unwrap();
                let _ = release.recv_timeout(Duration::from_secs(5));
            }
            Ok(())
        }
    }

    #[test]
    fn exit_drain_confirms_accepted_records_and_has_a_bounded_wait() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let (mirror, worker) = Mirror::spawn(
            GateWriter {
                bytes: bytes.clone(),
                write_gate: Some((entered, released)),
                flush_gate: None,
            },
            8,
            Arc::new(MirrorHealth::default()),
        )
        .unwrap();
        mirror.record(b"shutdown reason\n");
        entering.recv_timeout(Duration::from_secs(1)).unwrap();
        let probe = mirror.clone();
        let (done, received) = mpsc::channel();
        let drainer = thread::spawn(move || {
            let _ = done.send(probe.drain_on_exit(Duration::from_millis(20)));
        });
        let bounded = received.recv_timeout(Duration::from_secs(1));
        // Release the sink before asserting, so even a broken fence cannot leave
        // the worker blocked behind the test's gate after a failure.
        release.send(()).unwrap();
        drainer.join().unwrap();
        assert!(!bounded.expect("exit drain exceeded its wait budget"));
        assert!(mirror.drain_on_exit(Duration::from_secs(1)));
        assert_eq!(&*bytes.lock().unwrap(), b"shutdown reason\n");
        drop(mirror);
        worker.join().unwrap();
    }

    #[test]
    fn full_queue_drops_whole_records_and_flushes_without_waiting() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let health = Arc::new(MirrorHealth::default());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (mirror, worker) = Mirror::spawn(
            GateWriter {
                bytes: Arc::clone(&bytes),
                write_gate: Some((entered_tx, release_rx)),
                flush_gate: None,
            },
            1,
            Arc::clone(&health),
        )
        .unwrap();
        mirror.record(b"first\n");
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        mirror.record(b"second\n");
        let start = Instant::now();
        mirror.record(b"dropped\n");
        mirror.flush();
        let elapsed = start.elapsed();
        let snapshot = health.snapshot();
        let _ = release_tx.send(());
        drop(mirror);
        worker.join().unwrap();
        assert!(
            elapsed < Duration::from_secs(1),
            "full mirror queue blocked its caller: {elapsed:?}"
        );
        assert_eq!(snapshot["dropped_lines_total"], 1);
        assert_eq!(snapshot["dropped_flushes_total"], 1);
        assert_eq!(&*bytes.lock().unwrap(), b"first\nsecond\n");
    }

    #[test]
    fn blocked_worker_flush_does_not_block_producers_or_health() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let health = Arc::new(MirrorHealth::default());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (mirror, worker) = Mirror::spawn(
            GateWriter {
                bytes: Arc::clone(&bytes),
                write_gate: None,
                flush_gate: Some((entered_tx, release_rx)),
            },
            1,
            Arc::clone(&health),
        )
        .unwrap();
        mirror.flush();
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let start = Instant::now();
        mirror.record(b"after flush\n");
        mirror.flush();
        let snapshot = health.snapshot();
        let elapsed = start.elapsed();
        let _ = release_tx.send(());
        drop(mirror);
        worker.join().unwrap();
        assert!(elapsed < Duration::from_secs(1));
        assert_eq!(snapshot["dropped_flushes_total"], 1);
        assert_eq!(&*bytes.lock().unwrap(), b"after flush\n");
    }

    #[test]
    fn oversized_disconnected_and_unavailable_records_are_counted() {
        let health = Arc::new(MirrorHealth::default());
        let (tx, rx) = mpsc::sync_channel(1);
        let mirror = Mirror {
            tx: Some(tx),
            health: Arc::clone(&health),
        };
        mirror.record(&vec![b'x'; MAX_RECORD_BYTES + 1]);
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        drop(rx);
        mirror.record(b"disconnected\n");
        mirror.flush();
        let disabled = Mirror::disabled(Arc::clone(&health));
        disabled.record(b"disabled\n");
        disabled.flush();
        let snapshot = health.snapshot();
        assert_eq!(snapshot["dropped_lines_total"], 3);
        assert_eq!(snapshot["dropped_flushes_total"], 2);
        assert_eq!(snapshot["worker_start_failures_total"], 1);
    }

    #[test]
    fn sink_errors_are_counted_without_recursive_logging() {
        struct FailedSink;
        impl Write for FailedSink {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        let health = Arc::new(MirrorHealth::default());
        let (mirror, worker) = Mirror::spawn(FailedSink, 2, Arc::clone(&health)).unwrap();
        mirror.record(b"one\ntwo\n");
        mirror.flush();
        drop(mirror);
        worker.join().unwrap();
        let snapshot = health.snapshot();
        assert_eq!(snapshot["dropped_lines_total"], 2);
        assert_eq!(snapshot["dropped_flushes_total"], 1);
        assert_eq!(snapshot["write_errors_total"], 1);
        assert_eq!(snapshot["flush_errors_total"], 1);
    }
}
