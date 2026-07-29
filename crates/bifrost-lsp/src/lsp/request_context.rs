use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use lsp_server::Message;
use lsp_types::{
    ProgressToken, WorkDoneProgress, WorkDoneProgressBegin, WorkDoneProgressEnd,
    WorkDoneProgressReport,
};

use crate::cancellation::CancellationToken;
use crate::lsp::progress::work_done_progress_message;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequestCancelled;

pub(crate) struct RequestContext {
    cancellation: CancellationToken,
    progress: RequestProgress,
}

impl RequestContext {
    pub(crate) fn new(
        cancellation: CancellationToken,
        work_done_token: Option<ProgressToken>,
        title: impl Into<String>,
        initial_message: impl Into<String>,
        send_message: Arc<dyn Fn(Message) -> Result<(), String> + Send + Sync>,
    ) -> Self {
        Self {
            cancellation,
            progress: RequestProgress::new(
                work_done_token,
                title.into(),
                initial_message.into(),
                send_message,
            ),
        }
    }

    pub(crate) fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub(crate) fn check_cancelled(&self) -> Result<(), RequestCancelled> {
        if self.cancellation.is_cancelled() {
            Err(RequestCancelled)
        } else {
            Ok(())
        }
    }

    pub(crate) fn begin(&self) {
        self.progress.begin();
    }

    pub(crate) fn report(&self, message: &str) {
        self.progress.report(message);
    }

    pub(crate) fn end(&self, message: &str) {
        self.progress.end(message);
    }
}

struct RequestProgress {
    token: Option<ProgressToken>,
    title: String,
    initial_message: String,
    send_message: Arc<dyn Fn(Message) -> Result<(), String> + Send + Sync>,
    started: AtomicBool,
    ended: AtomicBool,
}

impl RequestProgress {
    fn new(
        token: Option<ProgressToken>,
        title: String,
        initial_message: String,
        send_message: Arc<dyn Fn(Message) -> Result<(), String> + Send + Sync>,
    ) -> Self {
        Self {
            token,
            title,
            initial_message,
            send_message,
            started: AtomicBool::new(false),
            ended: AtomicBool::new(false),
        }
    }

    fn begin(&self) {
        if self.token.is_none() || self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        self.send(WorkDoneProgress::Begin(WorkDoneProgressBegin {
            title: self.title.clone(),
            cancellable: Some(true),
            message: Some(self.initial_message.clone()),
            percentage: None,
        }));
    }

    fn report(&self, message: &str) {
        if !self.started.load(Ordering::Acquire) || self.ended.load(Ordering::Acquire) {
            return;
        }
        self.send(WorkDoneProgress::Report(WorkDoneProgressReport {
            cancellable: Some(true),
            message: Some(message.to_string()),
            percentage: None,
        }));
    }

    fn end(&self, message: &str) {
        if !self.started.load(Ordering::Acquire) || self.ended.swap(true, Ordering::AcqRel) {
            return;
        }
        self.send(WorkDoneProgress::End(WorkDoneProgressEnd {
            message: Some(message.to_string()),
        }));
    }

    fn send(&self, value: WorkDoneProgress) {
        let Some(token) = self.token.clone() else {
            return;
        };
        if let Err(err) = (self.send_message)(work_done_progress_message(token, value)) {
            eprintln!("[bifrost-lsp] failed to send request progress: {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use lsp_types::ProgressParams;

    #[test]
    fn progress_is_absent_without_a_token() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&messages);
        let context = RequestContext::new(
            CancellationToken::default(),
            None,
            "Finding references",
            "Resolving symbol",
            Arc::new(move |message| {
                sink.lock().unwrap().push(message);
                Ok(())
            }),
        );

        context.begin();
        context.report("Searching workspace");
        context.end("References ready");

        assert!(messages.lock().unwrap().is_empty());
    }

    #[test]
    fn progress_uses_one_begin_report_end_sequence() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&messages);
        let context = RequestContext::new(
            CancellationToken::default(),
            Some(ProgressToken::String("reference-progress".to_string())),
            "Finding references",
            "Resolving symbol",
            Arc::new(move |message| {
                sink.lock().unwrap().push(message);
                Ok(())
            }),
        );

        context.begin();
        context.begin();
        context.report("Searching workspace");
        context.end("References ready");
        context.end("Ignored");

        let messages = messages.lock().unwrap();
        assert_eq!(messages.len(), 3);
        for message in messages.iter() {
            let Message::Notification(note) = message else {
                panic!("expected progress notification");
            };
            let params: ProgressParams = serde_json::from_value(note.params.clone()).unwrap();
            assert_eq!(
                params.token,
                ProgressToken::String("reference-progress".to_string())
            );
        }
    }
}
