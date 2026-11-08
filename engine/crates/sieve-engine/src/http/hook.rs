//! The response-body hook. Production is `inject::content::ContentHook`, which
//! rewrites nothing while `filtering.content` is off; [`NoRewrite`] is for tests
//! of the path.
//!
//! The contract is the one in `inject/mod.rs`: a [`HookError`] resets, RST_STREAM
//! on h2 and a close on h1, because part of a rewritten body has gone out, so
//! it can neither pass the original nor finish cleanly. Trailers pass through
//! unchanged.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use ::http::{HeaderMap, StatusCode};
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::{Body, Frame, Incoming};
use sieve_ipc::LogChange;

use super::facts::RequestFacts;
use super::serve::{BodyError, ResponseBody};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct HookError(pub String);

/// One rewrite, from the first byte to the last.
pub trait BodyRewrite: Send {
    fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, HookError>;
    fn finish(self: Box<Self>) -> Result<Vec<u8>, HookError>;
    /// What tracking protection this rewrite puts in the page, for the request's
    /// log row. None by default.
    fn changes(&self) -> Vec<LogChange> {
        Vec::new()
    }
}

/// Asked about every decrypted response.
pub trait ResponseHook: Send + Sync {
    /// The request's headers before they go upstream, for what a response this
    /// hook will rewrite needs asked of the origin. No change by default.
    fn prepare_request(&self, _req: &RequestFacts<'_>, _headers: &mut HeaderMap) {}

    /// Whether [`ResponseHook::begin`] should see this response at all. False
    /// streams it as it comes: `begin` needs the first data frame, and holding
    /// the head for that would stall a server-sent stream that stays quiet
    /// after its headers.
    fn wants(&self, req: &RequestFacts<'_>, status: StatusCode, headers: &HeaderMap) -> bool;

    /// `body_start` is the first data frame, held until this answers. None
    /// passes the body through unchanged.
    fn begin(&self, req: &RequestFacts<'_>, status: StatusCode, headers: &mut HeaderMap, body_start: &[u8]) -> Option<Box<dyn BodyRewrite>>;
}

/// Every response streams as it comes.
pub struct NoRewrite;

impl ResponseHook for NoRewrite {
    fn wants(&self, _: &RequestFacts<'_>, _: StatusCode, _: &HeaderMap) -> bool {
        false
    }

    fn begin(&self, _: &RequestFacts<'_>, _: StatusCode, _: &mut HeaderMap, _: &[u8]) -> Option<Box<dyn BodyRewrite>> {
        None
    }
}

/// A body with its first frames already read, and possibly a rewrite.
struct Hooked {
    inner: Incoming,
    rewrite: Option<Box<dyn BodyRewrite>>,
    queued: VecDeque<Frame<Bytes>>,
    failed: Option<BodyError>,
    ended: bool,
}

impl Hooked {
    fn data(&mut self, chunk: &[u8]) {
        match &mut self.rewrite {
            Some(rewrite) => match rewrite.push(chunk) {
                Ok(out) if out.is_empty() => {}
                Ok(out) => self.queued.push_back(Frame::data(Bytes::from(out))),
                Err(e) => self.failed = Some(Box::new(e)),
            },
            None => self.queued.push_back(Frame::data(Bytes::copy_from_slice(chunk))),
        }
    }

    fn finish(&mut self) {
        if let Some(rewrite) = self.rewrite.take() {
            match rewrite.finish() {
                Ok(out) if out.is_empty() => {}
                Ok(out) => self.queued.push_back(Frame::data(Bytes::from(out))),
                Err(e) => self.failed = Some(Box::new(e)),
            }
        }
    }

    fn take_frame(&mut self, frame: Frame<Bytes>) {
        match frame.into_data() {
            Ok(chunk) => self.data(&chunk),
            Err(trailers) => {
                self.finish();
                self.queued.push_back(trailers);
            }
        }
    }
}

impl Body for Hooked {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        loop {
            if let Some(frame) = this.queued.pop_front() {
                return Poll::Ready(Some(Ok(frame)));
            }
            if let Some(e) = this.failed.take() {
                return Poll::Ready(Some(Err(e)));
            }
            if this.ended {
                return Poll::Ready(None);
            }
            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(frame)) => this.take_frame(frame),
                Some(Err(e)) => return Poll::Ready(Some(Err(Box::new(e)))),
                None => {
                    this.ended = true;
                    this.finish();
                }
            }
        }
    }
}

/// The response body after the hook: as it comes when the hook does not want
/// it, otherwise through `begin` with the first data frame held until then.
/// A rewrite falsifies `Content-Length`: `begin` holds the headers and owns that.
/// Also what the rewrite says it changed, for the log.
pub async fn apply(hook: &dyn ResponseHook, req: &RequestFacts<'_>, status: StatusCode, headers: &mut HeaderMap, mut body: Incoming) -> (ResponseBody, Vec<LogChange>) {
    if !hook.wants(req, status, headers) {
        return (boxed(body), Vec::new());
    }
    let first = body.frame().await;
    let start = match &first {
        Some(Ok(frame)) => frame.data_ref().cloned().unwrap_or_default(),
        _ => Bytes::new(),
    };
    let rewrite = hook.begin(req, status, headers, &start);
    let changes = rewrite.as_ref().map(|r| r.changes()).unwrap_or_default();
    let mut hooked = Hooked { inner: body, rewrite, queued: VecDeque::new(), failed: None, ended: false };
    match first {
        Some(Ok(frame)) => hooked.take_frame(frame),
        Some(Err(e)) => hooked.failed = Some(Box::new(e)),
        None => {
            hooked.ended = true;
            hooked.finish();
        }
    }
    (UnsyncBoxBody::new(hooked), changes)
}

/// A hyper body as the path's one body type.
pub fn boxed(body: Incoming) -> ResponseBody {
    UnsyncBoxBody::new(body.map_err(|e| Box::new(e) as BodyError))
}
