//! Channel "is typing" signal (typing-signal contract v1). Cosmetic: nothing here may
//! fail, delay a reply beyond `STOP_GRACE`, or alter a turn. See docs/typing-signal.md.
mod dto;
pub(crate) use dto::{SendTypingInV1, SendTypingOutV1};

/// The OPTIONAL provider op. The host calls it only when the provider declares it.
pub(crate) const TYPING_OP: &str = "send_typing";
