CREATE TABLE IF NOT EXISTS execution_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plan_id INTEGER NOT NULL,
  plan_hash TEXT NOT NULL,
  dry_run INTEGER NOT NULL DEFAULT 1,
  actor TEXT NOT NULL,
  status TEXT NOT NULL,
  policy_checks_json TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(plan_id, plan_hash, dry_run),
  FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS execution_step_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  execution_run_id INTEGER NOT NULL,
  step_order INTEGER NOT NULL,
  step_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  target_scope TEXT NOT NULL,
  command TEXT NOT NULL,
  args_json TEXT NOT NULL,
  environment_policy_json TEXT NOT NULL,
  stdout TEXT NOT NULL,
  stderr TEXT NOT NULL,
  exit_code INTEGER NOT NULL,
  artifact_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(execution_run_id, step_order),
  FOREIGN KEY (execution_run_id) REFERENCES execution_runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_execution_runs_plan
  ON execution_runs(plan_id, created_at DESC);

CREATE TRIGGER IF NOT EXISTS trg_execution_step_results_immutable_update
BEFORE UPDATE ON execution_step_results FOR EACH ROW
BEGIN
  SELECT RAISE(FAIL, 'execution step results are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_execution_step_results_immutable_delete
BEFORE DELETE ON execution_step_results FOR EACH ROW
BEGIN
  SELECT RAISE(FAIL, 'execution step results are immutable');
END;
