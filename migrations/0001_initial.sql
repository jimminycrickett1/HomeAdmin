PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_uuid TEXT NOT NULL UNIQUE,
  source_collector TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  raw_artifact_path TEXT,
  raw_artifact_hash TEXT,
  confidence REAL NOT NULL DEFAULT 1.0,
  status TEXT NOT NULL DEFAULT 'completed',
  is_partial INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS collection_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL,
  job_key TEXT NOT NULL,
  source_collector TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  raw_artifact_path TEXT,
  raw_artifact_hash TEXT,
  confidence REAL NOT NULL DEFAULT 1.0,
  status TEXT NOT NULL DEFAULT 'completed',
  is_retry INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(run_id, job_key),
  FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_uid TEXT NOT NULL UNIQUE,
  mac_address TEXT,
  ip_address TEXT,
  hostname TEXT,
  first_seen_at TEXT,
  last_seen_at TEXT,
  source_collector TEXT NOT NULL,
  raw_artifact_path TEXT,
  raw_artifact_hash TEXT,
  confidence REAL NOT NULL DEFAULT 1.0,
  status TEXT NOT NULL DEFAULT 'active',
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS identities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  identity_uid TEXT NOT NULL UNIQUE,
  asset_id INTEGER,
  identity_type TEXT NOT NULL,
  identity_value TEXT NOT NULL,
  first_seen_at TEXT,
  last_seen_at TEXT,
  source_collector TEXT NOT NULL,
  raw_artifact_path TEXT,
  raw_artifact_hash TEXT,
  confidence REAL NOT NULL DEFAULT 1.0,
  status TEXT NOT NULL DEFAULT 'active',
  is_verified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(identity_type, identity_value),
  FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  service_uid TEXT NOT NULL UNIQUE,
  asset_id INTEGER,
  service_name TEXT NOT NULL,
  protocol TEXT NOT NULL,
  port INTEGER NOT NULL,
  fingerprint TEXT NOT NULL,
  first_seen_at TEXT,
  last_seen_at TEXT,
  source_collector TEXT NOT NULL,
  raw_artifact_path TEXT,
  raw_artifact_hash TEXT,
  confidence REAL NOT NULL DEFAULT 1.0,
  status TEXT NOT NULL DEFAULT 'active',
  is_exposed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(asset_id, protocol, port, fingerprint),
  FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL,
  collection_job_id INTEGER,
  asset_id INTEGER,
  identity_id INTEGER,
  service_id INTEGER,
  observed_at TEXT NOT NULL,
  observation_type TEXT NOT NULL,
  observation_key TEXT NOT NULL,
  observation_value TEXT,
  source_collector TEXT NOT NULL,
  raw_artifact_path TEXT,
  raw_artifact_hash TEXT,
  confidence REAL NOT NULL DEFAULT 1.0,
  status TEXT NOT NULL DEFAULT 'observed',
  is_deleted INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(run_id, observation_type, observation_key),
  FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
  FOREIGN KEY (collection_job_id) REFERENCES collection_jobs(id) ON DELETE SET NULL,
  FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL,
  FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE SET NULL,
  FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS baselines (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  baseline_key TEXT NOT NULL UNIQUE,
  asset_id INTEGER,
  service_id INTEGER,
  expected_fingerprint TEXT,
  expected_state TEXT,
  valid_from TEXT,
  valid_to TEXT,
  source_collector TEXT NOT NULL,
  raw_artifact_path TEXT,
  raw_artifact_hash TEXT,
  confidence REAL NOT NULL DEFAULT 1.0,
  status TEXT NOT NULL DEFAULT 'active',
  is_current INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL,
  FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS discrepancies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL,
  asset_id INTEGER,
  service_id INTEGER,
  baseline_id INTEGER,
  discrepancy_type TEXT NOT NULL,
  fingerprint TEXT,
  details TEXT,
  detected_at TEXT NOT NULL,
  resolved_at TEXT,
  source_collector TEXT NOT NULL,
  raw_artifact_path TEXT,
  raw_artifact_hash TEXT,
  confidence REAL NOT NULL DEFAULT 1.0,
  status TEXT NOT NULL DEFAULT 'open',
  is_acknowledged INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
  FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL,
  FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE SET NULL,
  FOREIGN KEY (baseline_id) REFERENCES baselines(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_mac_address ON assets(mac_address);
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_ip_last_seen ON assets(ip_address, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_observations_ip_window ON observations(observation_key, observed_at) WHERE observation_type = 'ip';
CREATE INDEX IF NOT EXISTS idx_services_fingerprint ON services(fingerprint, service_name, protocol, port);
CREATE INDEX IF NOT EXISTS idx_discrepancies_fingerprint ON discrepancies(fingerprint);
CREATE UNIQUE INDEX IF NOT EXISTS idx_discrepancies_natural_key
  ON discrepancies(
    run_id,
    discrepancy_type,
    ifnull(asset_id, -1),
    ifnull(service_id, -1),
    ifnull(baseline_id, -1),
    ifnull(fingerprint, '')
  );

CREATE TRIGGER IF NOT EXISTS trg_runs_updated_at
AFTER UPDATE ON runs FOR EACH ROW
BEGIN
  UPDATE runs SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_collection_jobs_updated_at
AFTER UPDATE ON collection_jobs FOR EACH ROW
BEGIN
  UPDATE collection_jobs SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_assets_updated_at
AFTER UPDATE ON assets FOR EACH ROW
BEGIN
  UPDATE assets SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_identities_updated_at
AFTER UPDATE ON identities FOR EACH ROW
BEGIN
  UPDATE identities SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_services_updated_at
AFTER UPDATE ON services FOR EACH ROW
BEGIN
  UPDATE services SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_observations_updated_at
AFTER UPDATE ON observations FOR EACH ROW
BEGIN
  UPDATE observations SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_baselines_updated_at
AFTER UPDATE ON baselines FOR EACH ROW
BEGIN
  UPDATE baselines SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_discrepancies_updated_at
AFTER UPDATE ON discrepancies FOR EACH ROW
BEGIN
  UPDATE discrepancies SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
