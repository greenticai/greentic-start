//! Policy tests with a fake IMAP server: poll -> firing document -> dispatch,
//! idempotency, auth failure -> no firing, size cap, budget, backoff.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::OwnedSemaphorePermit;
use ulid::Ulid;

use super::*;
use crate::http_routes::RevisionScope;
use crate::triggers::schema::{self, TriggerKind};
use crate::triggers::store::InMemoryTriggerStore;
use greentic_deploy_spec::{BundleId, DeploymentId, RevisionId};

const FIXTURE: &str = include_str!("../../tests/fixtures/triggers/triggers_v1_email_imap.json");
const PASSWORD: &[u8] = b"imap-password\n";

#[derive(Default)]
struct Mailbox {
    uid_validity: u32,
    messages: Vec<(u32, Fetched)>,
    marked: Vec<u32>,
    moved: Vec<(u32, String)>,
    selected: Vec<String>,
    searched: Vec<SearchFilter>,
}

struct FakeServer {
    mailbox: Arc<Mutex<Mailbox>>,
    accepts: &'static str,
    connects: Mutex<u32>,
    logins: Mutex<Vec<String>>,
}

struct FakeSession(Arc<Mutex<Mailbox>>);

#[async_trait]
impl ImapSession for FakeSession {
    async fn select(&mut self, mailbox: &str) -> Result<MailboxState, ImapError> {
        let mut m = self.0.lock().unwrap();
        m.selected.push(mailbox.to_string());
        Ok(MailboxState {
            uid_validity: m.uid_validity,
        })
    }
    async fn search(&mut self, filter: &SearchFilter) -> Result<Vec<u32>, ImapError> {
        let mut m = self.0.lock().unwrap();
        m.searched.push(filter.clone());
        let done: Vec<u32> = m
            .marked
            .iter()
            .chain(m.moved.iter().map(|(u, _)| u))
            .copied()
            .collect();
        Ok(m.messages
            .iter()
            .map(|(u, _)| *u)
            .filter(|u| !done.contains(u))
            .collect())
    }
    async fn fetch(&mut self, uid: u32, _max: usize) -> Result<Fetched, ImapError> {
        let m = self.0.lock().unwrap();
        Ok(m.messages
            .iter()
            .find(|(u, _)| *u == uid)
            .map(|(_, f)| f.clone())
            .unwrap_or(Fetched::Gone))
    }
    async fn mark_seen(&mut self, uid: u32) -> Result<(), ImapError> {
        self.0.lock().unwrap().marked.push(uid);
        Ok(())
    }
    async fn move_to(&mut self, uid: u32, mailbox: &str) -> Result<(), ImapError> {
        self.0.lock().unwrap().moved.push((uid, mailbox.into()));
        Ok(())
    }
}

#[async_trait]
impl ImapConnector for FakeServer {
    async fn connect(
        &self,
        _: &EmailImapSpec,
        password: &str,
    ) -> Result<Box<dyn ImapSession>, ImapError> {
        *self.connects.lock().unwrap() += 1;
        self.logins.lock().unwrap().push(password.to_string());
        match self.accepts {
            "ok" => Ok(Box::new(FakeSession(Arc::clone(&self.mailbox)))),
            "auth" => Err(ImapError::Auth),
            _ => Err(ImapError::Transport("connection reset".into())),
        }
    }
}

struct FakeHost {
    secrets: HashMap<String, Vec<u8>>,
    fired: Mutex<Vec<Firing>>,
    held: Mutex<Vec<OwnedSemaphorePermit>>,
}

#[async_trait]
impl TriggerHost for FakeHost {
    async fn read_secret(&self, _: &LoadedTrigger, secret_ref: &str) -> anyhow::Result<Vec<u8>> {
        self.secrets
            .get(secret_ref)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("secret `{secret_ref}` unreadable"))
    }
    fn spawn_fire(&self, _: Arc<LoadedTrigger>, firing: Firing, permit: OwnedSemaphorePermit) {
        self.fired.lock().unwrap().push(firing);
        // A still-running flow keeps its permit.
        self.held.lock().unwrap().push(permit);
    }
}

struct Sink;
#[async_trait]
impl AttachmentSink for Sink {
    async fn store(&self, name: &str, _: &str, bytes: Vec<u8>) -> anyhow::Result<String> {
        Ok(format!("artifact://{name}-{}", bytes.len()))
    }
}

struct Rig {
    host: FakeHost,
    server: FakeServer,
    store: Arc<dyn TriggerStore>,
    entry: Arc<LoadedTrigger>,
    spec: EmailImapSpec,
}

fn mail(id: Option<&str>, subject: &str) -> Fetched {
    Fetched::Message(Box::new(MailMessage {
        message_id: id.map(str::to_string),
        from: "Customer <customer@example.com>".into(),
        to: vec!["support@acme.example".into()],
        subject: subject.into(),
        text: "Hello\u{0}there".into(),
        html: Some("<script>alert(1)</script>".into()),
        received_at: Utc::now(),
        attachments: vec![MailAttachment {
            name: "invoice.pdf".into(),
            mime_type: "application/pdf".into(),
            size_bytes: 3,
            bytes: Some(vec![1, 2, 3]),
        }],
    }))
}

fn rig(
    accepts: &'static str,
    patch: impl FnOnce(&mut EmailImapSpec),
    msgs: Vec<(u32, Fetched)>,
) -> Rig {
    let mut parsed = schema::parse(FIXTURE.as_bytes(), "pack.acme.support").expect("parses");
    let spec = parsed.triggers.remove(0);
    let TriggerKind::EmailImap(mut email) = spec.kind.clone() else {
        panic!("not email");
    };
    patch(&mut email);
    let entry = Arc::new(LoadedTrigger {
        scope: RevisionScope {
            deployment_id: DeploymentId(Ulid::new()),
            bundle_id: BundleId::new("bundle"),
            revision_id: RevisionId(Ulid::new()),
        },
        tenant: "acme".into(),
        pack_id: "pack.acme.support".into(),
        spec: Arc::new(spec),
        unavailable: None,
    });
    Rig {
        host: FakeHost {
            secrets: HashMap::from([("mail/imap_password".to_string(), PASSWORD.to_vec())]),
            fired: Mutex::new(Vec::new()),
            held: Mutex::new(Vec::new()),
        },
        server: FakeServer {
            mailbox: Arc::new(Mutex::new(Mailbox {
                uid_validity: 7,
                messages: msgs,
                ..Mailbox::default()
            })),
            accepts,
            connects: Mutex::new(0),
            logins: Mutex::new(Vec::new()),
        },
        store: Arc::new(InMemoryTriggerStore::default()),
        entry,
        spec: email,
    }
}

impl Rig {
    fn set_concurrency(&mut self, n: u32) {
        let mut spec = (*self.entry.spec).clone();
        spec.max_concurrency = n;
        self.entry = Arc::new(LoadedTrigger {
            spec: Arc::new(spec),
            ..(*self.entry).clone()
        });
    }
    async fn poll(&self, at: i64) -> PollResult {
        let ctx = PollCtx {
            host: &self.host,
            connector: &self.server,
            sink: &Sink,
            store: &self.store,
        };
        let now = DateTime::from_timestamp(at, 0).unwrap();
        poll_entry(&ctx, "env", &self.entry, &self.spec, now).await
    }
    fn fired(&self) -> Vec<Firing> {
        self.host.fired.lock().unwrap().clone()
    }
    /// A flow run ends: its permit is released.
    fn finish_flows(&self) {
        self.host.held.lock().unwrap().clear();
    }
}

#[tokio::test]
async fn a_new_mail_becomes_a_firing_with_the_email_document() {
    let r = rig(
        "ok",
        |_| {},
        vec![(1, mail(Some("<a@x>"), "Order\r\nBcc: evil@x"))],
    );
    assert_eq!(r.poll(1_000).await, PollResult::Polled { fired: 1 });

    let firings = r.fired();
    assert_eq!(firings.len(), 1);
    let p = &firings[0].payload;
    assert_eq!(p["trigger"]["kind"], "email_imap");
    assert!(p["webhook"].is_null() && p["cron"].is_null());
    let e = &p["email"];
    assert_eq!(e["from"], "Customer <customer@example.com>");
    assert_eq!(e["message_id"], "<a@x>");
    // Header injection: CR/LF cannot survive into the flow.
    assert_eq!(e["subject"], "OrderBcc: evil@x");
    // Body: NUL stripped. HTML is off by default and never passed through.
    assert_eq!(e["text"], "Hellothere");
    assert!(e["html"].is_null());
    assert_eq!(e["attachments"][0]["name"], "invoice.pdf");
    assert!(
        e["attachments"][0]["artifact"].is_null(),
        "attachments default to none"
    );
    // Per-run session, mailbox untouched except for the success policy.
    assert!(
        firings[0]
            .session_hint
            .starts_with("trigger:support_inbox:")
    );
    assert_eq!(r.server.mailbox.lock().unwrap().marked, vec![1]);
    // The trailing newline of the stored secret is not part of the password.
    assert_eq!(r.server.logins.lock().unwrap()[0], "imap-password");
}

#[tokio::test]
async fn the_same_message_id_never_fires_twice_even_under_a_new_uid() {
    let r = rig("ok", |_| {}, vec![(1, mail(Some("<a@x>"), "Order"))]);
    assert_eq!(r.poll(1_000).await, PollResult::Polled { fired: 1 });
    r.finish_flows();
    // The server renumbers (UIDVALIDITY change): same Message-ID, new UID, and
    // the mail is unseen again.
    {
        let mut m = r.server.mailbox.lock().unwrap();
        m.uid_validity = 8;
        m.marked.clear();
        m.messages = vec![(900, mail(Some("<a@x>"), "Order"))];
    }
    assert_eq!(r.poll(1_000 + 60).await, PollResult::Polled { fired: 0 });
    assert_eq!(r.fired().len(), 1);
    // ...and it is taken out of the unseen set instead of being re-listed.
    assert_eq!(r.server.mailbox.lock().unwrap().marked, vec![900]);
}

#[tokio::test]
async fn a_mail_without_message_id_is_keyed_by_uidvalidity_and_uid() {
    let r = rig("ok", |_| {}, vec![(5, mail(None, "No id"))]);
    assert_eq!(r.poll(1_000).await, PollResult::Polled { fired: 1 });
    r.finish_flows();
    r.server.mailbox.lock().unwrap().marked.clear();
    assert_eq!(r.poll(1_060).await, PollResult::Polled { fired: 0 });
    assert_eq!(r.fired().len(), 1);
}

#[tokio::test]
async fn an_auth_failure_fires_nothing_and_backs_off_hard() {
    let r = rig("auth", |_| {}, vec![(1, mail(Some("<a@x>"), "Order"))]);
    let result = r.poll(1_000).await;
    assert_eq!(result, PollResult::AuthFailed);
    assert!(r.fired().is_empty());
    assert!(r.server.mailbox.lock().unwrap().selected.is_empty());
    let (delay, failures) = next_delay(&result, Duration::from_secs(60), 0);
    assert_eq!((delay, failures), (Duration::from_secs(900), 1));
}

#[tokio::test]
async fn an_unreadable_password_never_connects() {
    let mut r = rig("ok", |_| {}, vec![(1, mail(Some("<a@x>"), "Order"))]);
    r.host.secrets.clear();
    assert_eq!(r.poll(1_000).await, PollResult::Skipped);
    assert_eq!(*r.server.connects.lock().unwrap(), 0);
    assert!(r.fired().is_empty());
}

#[tokio::test]
async fn a_transport_failure_backs_off_exponentially_up_to_a_cap() {
    let r = rig("down", |_| {}, vec![]);
    let result = r.poll(1_000).await;
    assert_eq!(result, PollResult::Failed);
    let interval = Duration::from_secs(60);
    assert_eq!(
        next_delay(&result, interval, 0),
        (Duration::from_secs(120), 1)
    );
    assert_eq!(
        next_delay(&result, interval, 2),
        (Duration::from_secs(480), 3)
    );
    assert_eq!(
        next_delay(&result, interval, 20).0,
        Duration::from_secs(900)
    );
    assert_eq!(
        next_delay(&PollResult::Polled { fired: 0 }, interval, 5),
        (interval, 0)
    );
}

#[tokio::test]
async fn an_oversize_mail_is_reported_taken_out_of_the_way_and_never_fired() {
    let r = rig(
        "ok",
        |_| {},
        vec![(1, Fetched::TooLarge { size: 99_000_000 })],
    );
    assert_eq!(r.poll(1_000).await, PollResult::Polled { fired: 0 });
    assert!(r.fired().is_empty());
    assert_eq!(r.server.mailbox.lock().unwrap().marked, vec![1]);
}

#[tokio::test]
async fn one_poll_takes_at_most_max_messages_oldest_first() {
    let msgs = (1..=5)
        .rev()
        .map(|u| (u, mail(Some(&format!("<{u}@x>")), "m")))
        .collect();
    let mut r = rig("ok", |s| s.max_messages_per_poll = 2, msgs);
    r.set_concurrency(4);
    assert_eq!(r.poll(1_000).await, PollResult::Polled { fired: 2 });
    assert_eq!(r.server.mailbox.lock().unwrap().marked, vec![1, 2]);
}

#[tokio::test]
async fn a_busy_flow_leaves_the_rest_unseen_for_the_next_poll() {
    let mut r = rig(
        "ok",
        |_| {},
        vec![(1, mail(Some("<1@x>"), "a")), (2, mail(Some("<2@x>"), "b"))],
    );
    let mut spec = (*r.entry.spec).clone();
    spec.max_concurrency = 1;
    r.entry = Arc::new(LoadedTrigger {
        spec: Arc::new(spec),
        ..(*r.entry).clone()
    });
    assert_eq!(r.poll(1_000).await, PollResult::Polled { fired: 1 });
    assert_eq!(r.server.mailbox.lock().unwrap().marked, vec![1]);
    r.finish_flows();
    assert_eq!(r.poll(1_060).await, PollResult::Polled { fired: 1 });
    assert_eq!(r.fired().len(), 2);
}

#[tokio::test]
async fn only_one_poll_per_interval_runs() {
    let r = rig("ok", |_| {}, vec![]);
    assert_eq!(r.poll(1_000).await, PollResult::Polled { fired: 0 });
    // Same 60 s bucket: the lease is taken (another replica, or a re-entry).
    assert_eq!(r.poll(1_010).await, PollResult::Skipped);
    assert_eq!(*r.server.connects.lock().unwrap(), 1);
}

#[tokio::test]
async fn move_policy_moves_instead_of_marking() {
    let r = rig(
        "ok",
        |s| s.on_success = OnSuccess::MoveTo("Processed".into()),
        vec![(1, mail(Some("<a@x>"), "Order"))],
    );
    r.poll(1_000).await;
    let m = r.server.mailbox.lock().unwrap();
    assert_eq!(m.moved, vec![(1, "Processed".to_string())]);
    assert!(m.marked.is_empty());
}

#[tokio::test]
async fn html_and_attachment_bytes_flow_only_when_declared() {
    let r = rig(
        "ok",
        |s| {
            s.include_html = true;
            s.attachments = AttachmentMode::Artifacts;
        },
        vec![(1, mail(Some("<a@x>"), "Order"))],
    );
    r.poll(1_000).await;
    let e = &r.fired()[0].payload["email"];
    // Carried as inert text for the flow to treat as data; never rendered here.
    assert_eq!(e["html"], "<script>alert(1)</script>");
    assert_eq!(e["attachments"][0]["artifact"], "artifact://invoice.pdf-3");
}

#[tokio::test]
async fn text_is_cut_at_the_cap_on_a_character_boundary() {
    let (text, truncated) = bounded_text("héllo wörld", 4);
    assert!(truncated);
    assert_eq!(text, "hél");
}

#[test]
fn a_disabled_trigger_is_never_polled_status_has_no_secret() {
    let r = rig("ok", |_| {}, vec![]);
    let table = crate::triggers::TriggerTable::build(vec![(*r.entry).clone()], &HashMap::new());
    let status = table.status_json();
    assert_eq!(status[0]["kind"], "email_imap");
    assert_eq!(status[0]["email_imap"]["host"], "imap.acme.example");
    assert!(!status.to_string().contains("imap_password"));
    assert_eq!(table.email_entries().count(), 1);
}
