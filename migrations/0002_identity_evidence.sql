CREATE TABLE IF NOT EXISTS identity_evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  identity_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  evidence_type TEXT NOT NULL,
  weight REAL NOT NULL,
  contribution REAL NOT NULL,
  score REAL NOT NULL,
  detail TEXT NOT NULL,
  provenance TEXT NOT NULL,
  source_collector TEXT NOT NULL,
  raw_artifact_path TEXT,
  raw_artifact_hash TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(identity_id, run_id, evidence_type),
  FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE,
  FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_identity_evidence_identity ON identity_evidence(identity_id, run_id);

CREATE TRIGGER IF NOT EXISTS trg_identity_evidence_updated_at
AFTER UPDATE ON identity_evidence FOR EACH ROW
BEGIN
  UPDATE identity_evidence SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
