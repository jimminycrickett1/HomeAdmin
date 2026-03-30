CREATE TABLE IF NOT EXISTS plan_state_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plan_id INTEGER NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('draft', 'proposed', 'approved', 'rejected', 'executed')),
  actor TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  plan_hash TEXT NOT NULL,
  policy_checks_json TEXT NOT NULL,
  approval_token_fingerprint TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_plan_state_events_plan ON plan_state_events(plan_id, occurred_at DESC, id DESC);

CREATE TRIGGER IF NOT EXISTS trg_plan_state_events_immutable_update
BEFORE UPDATE ON plan_state_events FOR EACH ROW
BEGIN
  SELECT RAISE(FAIL, 'plan state events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_plan_state_events_immutable_delete
BEFORE DELETE ON plan_state_events FOR EACH ROW
BEGIN
  SELECT RAISE(FAIL, 'plan state events are immutable');
END;
