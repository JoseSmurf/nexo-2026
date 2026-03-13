#[derive(Debug)]
pub(super) enum AuthError {
    Unauthorized(&'static str),
    RequestTimeout(&'static str),
    Conflict(&'static str),
    ServiceUnavailable(&'static str),
}

#[derive(Debug)]
pub(super) enum ChatSendError {
    BadRequest(&'static str),
    ServiceUnavailable(&'static str),
}
