CREATE TABLE IF NOT EXISTS plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plan_key TEXT NOT NULL,
  version INTEGER NOT NULL,
  parent_plan_id INTEGER,
  title TEXT NOT NULL,
  recommendation_rule_id TEXT NOT NULL,
  asset_uid TEXT NOT NULL,
  priority TEXT NOT NULL,
  source_run_id INTEGER NOT NULL,
  blast_radius_estimate TEXT NOT NULL,
  required_privilege_level TEXT NOT NULL,
  plan_hash TEXT NOT NULL,
  generated_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(plan_key, version),
  UNIQUE(plan_hash),
  FOREIGN KEY (parent_plan_id) REFERENCES plans(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS plan_steps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plan_id INTEGER NOT NULL,
  step_order INTEGER NOT NULL,
  step_kind TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(plan_id, step_kind, step_order),
  FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS plan_approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plan_id INTEGER NOT NULL,
  approver TEXT NOT NULL,
  decision TEXT NOT NULL,
  rationale TEXT,
  decided_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_plans_lookup ON plans(plan_key, version DESC);
CREATE INDEX IF NOT EXISTS idx_plan_steps_plan ON plan_steps(plan_id, step_kind, step_order);
CREATE INDEX IF NOT EXISTS idx_plan_approvals_plan ON plan_approvals(plan_id, decided_at DESC);

CREATE TRIGGER IF NOT EXISTS trg_plans_immutable_update
BEFORE UPDATE ON plans FOR EACH ROW
BEGIN
  SELECT RAISE(FAIL, 'plans are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_plans_immutable_delete
BEFORE DELETE ON plans FOR EACH ROW
BEGIN
  SELECT RAISE(FAIL, 'plans are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_plan_steps_immutable_update
BEFORE UPDATE ON plan_steps FOR EACH ROW
BEGIN
  SELECT RAISE(FAIL, 'plan steps are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_plan_steps_immutable_delete
BEFORE DELETE ON plan_steps FOR EACH ROW
BEGIN
  SELECT RAISE(FAIL, 'plan steps are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_plan_approvals_immutable_update
BEFORE UPDATE ON plan_approvals FOR EACH ROW
BEGIN
  SELECT RAISE(FAIL, 'plan approvals are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_plan_approvals_immutable_delete
BEFORE DELETE ON plan_approvals FOR EACH ROW
BEGIN
  SELECT RAISE(FAIL, 'plan approvals are immutable');
END;
