CREATE INDEX IF NOT EXISTS idx_discrepancies_unknown_backlog_status
  ON discrepancies(discrepancy_type, status, fingerprint, detected_at);
