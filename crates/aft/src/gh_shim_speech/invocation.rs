//! Frozen parser input. Replay never opens a caller-supplied body-file path.

use std::cell::RefCell;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{Code, Refusal};

const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Invocation {
    pub(crate) args: Vec<String>,
    pub(crate) body_inputs: BTreeMap<String, String>,
}

impl Invocation {
    pub(crate) fn validate(&self) -> Result<(), Refusal> {
        let mut bytes = 0usize;
        for value in self
            .args
            .iter()
            .chain(self.body_inputs.keys())
            .chain(self.body_inputs.values())
        {
            bytes = bytes.checked_add(value.len()).ok_or_else(denied)?;
            if bytes > MAX_INPUT_BYTES {
                return Err(denied());
            }
        }
        Ok(())
    }
}

fn denied() -> Refusal {
    Refusal::new(Code::PolicyDenied, "payload_denied")
}

enum Mode {
    Record(BTreeMap<String, String>),
    Replay(BTreeMap<String, String>),
}

thread_local! {static INPUT:RefCell<Option<Mode>>=const{RefCell::new(None)};}

struct Restore(Option<Mode>);
impl Drop for Restore {
    fn drop(&mut self) {
        INPUT.with(|slot| *slot.borrow_mut() = self.0.take());
    }
}

pub(crate) fn record<T>(run: impl FnOnce() -> T) -> (T, BTreeMap<String, String>) {
    let _restore = Restore(INPUT.with(|slot| slot.replace(Some(Mode::Record(BTreeMap::new())))));
    let result = run();
    let captured = INPUT.with(|slot| match slot.borrow().as_ref() {
        Some(Mode::Record(inputs)) => inputs.clone(),
        _ => BTreeMap::new(),
    });
    (result, captured)
}

pub(crate) fn replay<T>(invocation: &Invocation, run: impl FnOnce() -> T) -> Result<T, Refusal> {
    invocation.validate()?;
    let _restore = Restore(
        INPUT.with(|slot| slot.replace(Some(Mode::Replay(invocation.body_inputs.clone())))),
    );
    Ok(run())
}

pub(crate) fn captured(path: &std::path::Path) -> Option<Result<String, String>> {
    let Some(key) = path.to_str() else {
        return INPUT.with(|slot| {
            matches!(slot.borrow().as_ref(), Some(Mode::Replay(_)))
                .then(|| Err("body-file path is not UTF-8".into()))
        });
    };
    INPUT.with(|slot| match slot.borrow().as_ref() {
        Some(Mode::Replay(inputs)) => Some(
            inputs
                .get(key)
                .cloned()
                .ok_or_else(|| "body-file input was not captured".into()),
        ),
        Some(Mode::Record(inputs)) => inputs.get(key).cloned().map(Ok),
        None => None,
    })
}

pub(crate) fn remember(path: &std::path::Path, body: &str) -> Result<(), String> {
    if INPUT.with(|slot| slot.borrow().is_none()) {
        return Ok(());
    }
    if body.len() > MAX_INPUT_BYTES {
        return Err("body input exceeds the parser limit".into());
    }
    if let Some(key) = path.to_str() {
        INPUT.with(|slot| {
            if let Some(Mode::Record(inputs)) = slot.borrow_mut().as_mut() {
                inputs.insert(key.to_string(), body.to_string());
            }
        });
    }
    Ok(())
}
