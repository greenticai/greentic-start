# API channel SSE stream

`GET <route>/conversations/{id}/stream` on a route owned by a `messaging.api`
provider (`src/api_channel/`, wired in `src/revision_serve/api_stream.rs`).

- Auth: `Authorization: Bearer <key>`. The host holds no copy; it forwards the
  key to the provider's `ingest_http` for the stream path, which must answer
  `401` for a wrong or missing key. No bearer is `401` without asking.
- `Last-Event-ID` is the cursor of the last event seen; the stream resumes at
  `cursor + 1`. Without it the stream starts at the oldest retained event.
- A resume whose next event is not the first retained one answers `410` with
  `{"error":"cursor_expired","oldest_cursor":N}`.
- A `: keep-alive` comment every 15 s; the stream closes after 5 minutes and the
  client resumes with `Last-Event-ID`.
- Limits per credential (digest of the key, never the key): the interop token
  bucket for opens, and 8 concurrent streams. Per process, not per fleet.
- Events come from the provider op `poll_events` (`docs/fixtures/api-channel/`).
  Each stream also polls every 2 s, so a missed notifier wake-up costs latency,
  not events.
