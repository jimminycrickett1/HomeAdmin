CREATE TABLE IF NOT EXISTS recommendations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  recommendation_uid TEXT NOT NULL UNIQUE,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  rationale TEXT NOT NULL,
  impact_score REAL NOT NULL,
  risk_score REAL NOT NULL,
  effort_score REAL NOT NULL,
  confidence REAL NOT NULL,
  priority_rank INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS recommendation_evidence_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  recommendation_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  discrepancy_id INTEGER,
  asset_id INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (recommendation_id) REFERENCES recommendations(id) ON DELETE CASCADE,
  FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
  FOREIGN KEY (discrepancy_id) REFERENCES discrepancies(id) ON DELETE SET NULL,
  FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_recommendations_rank
  ON recommendations(priority_rank, risk_score DESC, impact_score DESC);
CREATE INDEX IF NOT EXISTS idx_recommendations_category
  ON recommendations(category, priority_rank);
CREATE INDEX IF NOT EXISTS idx_recommendation_evidence_lookup
  ON recommendation_evidence_links(recommendation_id, run_id);
CREATE INDEX IF NOT EXISTS idx_recommendation_evidence_discrepancy
  ON recommendation_evidence_links(discrepancy_id);
CREATE INDEX IF NOT EXISTS idx_recommendation_evidence_asset
  ON recommendation_evidence_links(asset_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_recommendation_evidence_natural_key
  ON recommendation_evidence_links(
    recommendation_id,
    run_id,
    ifnull(discrepancy_id, -1),
    ifnull(asset_id, -1)
  );

CREATE TRIGGER IF NOT EXISTS trg_recommendations_updated_at
AFTER UPDATE ON recommendations FOR EACH ROW
BEGIN
  UPDATE recommendations SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_recommendation_evidence_links_updated_at
AFTER UPDATE ON recommendation_evidence_links FOR EACH ROW
BEGIN
  UPDATE recommendation_evidence_links SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
