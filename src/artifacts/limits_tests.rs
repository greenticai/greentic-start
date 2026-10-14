use super::limits::*;

#[test]
fn limits_match_the_contract() {
    assert_eq!(MAX_FILE_BYTES, 10 * 1024 * 1024);
    assert_eq!(MAX_FILES, 5);
    assert_eq!(MAX_MESSAGE_BYTES, 50 * 1024 * 1024);
    assert_eq!(MAX_TEXT_CHARS, 200_000);
}

#[test]
fn a_message_can_hold_five_full_files() {
    assert!(MAX_FILE_BYTES * MAX_FILES as u64 <= MAX_MESSAGE_BYTES);
}
