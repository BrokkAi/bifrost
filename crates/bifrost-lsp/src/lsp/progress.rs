use lsp_server::{Message, Notification};
use lsp_types::notification::{Notification as LspNotification, Progress};
use lsp_types::{ProgressParams, ProgressParamsValue, ProgressToken, WorkDoneProgress};

pub(crate) fn work_done_progress_message(token: ProgressToken, value: WorkDoneProgress) -> Message {
    Message::Notification(Notification::new(
        Progress::METHOD.to_string(),
        ProgressParams {
            token,
            value: ProgressParamsValue::WorkDone(value),
        },
    ))
}
