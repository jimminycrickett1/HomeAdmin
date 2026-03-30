"""Database storage primitives for HomeAdmin."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path


class Storage:
    """Thin SQLite storage layer with migrations and idempotent upserts."""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._conn: sqlite3.Connection | None = None

    @property
    def connection(self) -> sqlite3.Connection:
        """Return an open connection, creating one if needed."""
        if self._conn is None:
            self._conn = sqlite3.connect(self._db_path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA journal_mode = WAL")
        return self._conn

    def close(self) -> None:
        """Close the active database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run statements inside an explicit transaction boundary."""
        conn = self.connection
        conn.execute("BEGIN")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def initialize(self) -> None:
        """Apply SQL migrations in migrations/ exactly once."""
        migration_dir = Path(__file__).resolve().parents[3] / "migrations"
        if not migration_dir.exists():
            return

        with self.transaction() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                  version TEXT PRIMARY KEY,
                  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            applied = {
                row["version"]
                for row in conn.execute("SELECT version FROM schema_migrations")
            }
            for migration in sorted(migration_dir.glob("*.sql")):
                if migration.name in applied:
                    continue
                conn.executescript(migration.read_text(encoding="utf-8"))
                conn.execute(
                    "INSERT INTO schema_migrations(version) VALUES (?)",
                    (migration.name,),
                )

    def upsert_run(self, payload: Mapping[str, object]) -> int:
        """Insert or update a run record by run_uuid and return id."""
        query = """
            INSERT INTO runs (
              run_uuid, source_collector, started_at, finished_at,
              raw_artifact_path, raw_artifact_hash, confidence, status, is_partial
            ) VALUES (
              :run_uuid, :source_collector, :started_at, :finished_at,
              :raw_artifact_path, :raw_artifact_hash, :confidence, :status, :is_partial
            )
            ON CONFLICT(run_uuid) DO UPDATE SET
              source_collector = excluded.source_collector,
              finished_at = excluded.finished_at,
              raw_artifact_path = excluded.raw_artifact_path,
              raw_artifact_hash = excluded.raw_artifact_hash,
              confidence = excluded.confidence,
              status = excluded.status,
              is_partial = excluded.is_partial
            RETURNING id
        """
        row = self.connection.execute(query, payload).fetchone()
        if row is None:
            raise RuntimeError("Failed to upsert run")
        return int(row["id"])

    def upsert_asset(self, payload: Mapping[str, object]) -> int:
        """Insert or update an asset record by asset_uid and return id."""
        query = """
            INSERT INTO assets (
              asset_uid, mac_address, ip_address, hostname, first_seen_at, last_seen_at,
              source_collector, raw_artifact_path, raw_artifact_hash,
              confidence, status, is_active
            ) VALUES (
              :asset_uid, :mac_address, :ip_address, :hostname, :first_seen_at, :last_seen_at,
              :source_collector, :raw_artifact_path, :raw_artifact_hash,
              :confidence, :status, :is_active
            )
            ON CONFLICT(asset_uid) DO UPDATE SET
              mac_address = excluded.mac_address,
              ip_address = excluded.ip_address,
              hostname = excluded.hostname,
              last_seen_at = excluded.last_seen_at,
              source_collector = excluded.source_collector,
              raw_artifact_path = excluded.raw_artifact_path,
              raw_artifact_hash = excluded.raw_artifact_hash,
              confidence = excluded.confidence,
              status = excluded.status,
              is_active = excluded.is_active
            RETURNING id
        """
        row = self.connection.execute(query, payload).fetchone()
        if row is None:
            raise RuntimeError("Failed to upsert asset")
        return int(row["id"])

    def upsert_identity(self, payload: Mapping[str, object]) -> int:
        """Insert or update an identity record by identity_uid and return id."""
        query = """
            INSERT INTO identities (
              identity_uid, asset_id, identity_type, identity_value,
              first_seen_at, last_seen_at, source_collector,
              raw_artifact_path, raw_artifact_hash, confidence, status, is_verified
            ) VALUES (
              :identity_uid, :asset_id, :identity_type, :identity_value,
              :first_seen_at, :last_seen_at, :source_collector,
              :raw_artifact_path, :raw_artifact_hash, :confidence, :status, :is_verified
            )
            ON CONFLICT(identity_uid) DO UPDATE SET
              asset_id = excluded.asset_id,
              identity_type = excluded.identity_type,
              identity_value = excluded.identity_value,
              last_seen_at = excluded.last_seen_at,
              source_collector = excluded.source_collector,
              raw_artifact_path = excluded.raw_artifact_path,
              raw_artifact_hash = excluded.raw_artifact_hash,
              confidence = excluded.confidence,
              status = excluded.status,
              is_verified = excluded.is_verified
            RETURNING id
        """
        row = self.connection.execute(query, payload).fetchone()
        if row is None:
            raise RuntimeError("Failed to upsert identity")
        return int(row["id"])

    def upsert_service(self, payload: Mapping[str, object]) -> int:
        """Insert or update a service record by service_uid and return id."""
        query = """
            INSERT INTO services (
              service_uid, asset_id, service_name, protocol, port, fingerprint,
              first_seen_at, last_seen_at, source_collector, raw_artifact_path,
              raw_artifact_hash, confidence, status, is_exposed
            ) VALUES (
              :service_uid, :asset_id, :service_name, :protocol, :port, :fingerprint,
              :first_seen_at, :last_seen_at, :source_collector, :raw_artifact_path,
              :raw_artifact_hash, :confidence, :status, :is_exposed
            )
            ON CONFLICT(service_uid) DO UPDATE SET
              asset_id = excluded.asset_id,
              service_name = excluded.service_name,
              protocol = excluded.protocol,
              port = excluded.port,
              fingerprint = excluded.fingerprint,
              last_seen_at = excluded.last_seen_at,
              source_collector = excluded.source_collector,
              raw_artifact_path = excluded.raw_artifact_path,
              raw_artifact_hash = excluded.raw_artifact_hash,
              confidence = excluded.confidence,
              status = excluded.status,
              is_exposed = excluded.is_exposed
            RETURNING id
        """
        row = self.connection.execute(query, payload).fetchone()
        if row is None:
            raise RuntimeError("Failed to upsert service")
        return int(row["id"])

    def upsert_observation(self, payload: Mapping[str, object]) -> int:
        """Insert or update an observation using run/type/key identity."""
        query = """
            INSERT INTO observations (
              run_id, collection_job_id, asset_id, identity_id, service_id,
              observed_at, observation_type, observation_key, observation_value,
              source_collector, raw_artifact_path, raw_artifact_hash,
              confidence, status, is_deleted
            ) VALUES (
              :run_id, :collection_job_id, :asset_id, :identity_id, :service_id,
              :observed_at, :observation_type, :observation_key, :observation_value,
              :source_collector, :raw_artifact_path, :raw_artifact_hash,
              :confidence, :status, :is_deleted
            )
            ON CONFLICT(run_id, observation_type, observation_key) DO UPDATE SET
              collection_job_id = excluded.collection_job_id,
              asset_id = excluded.asset_id,
              identity_id = excluded.identity_id,
              service_id = excluded.service_id,
              observed_at = excluded.observed_at,
              observation_value = excluded.observation_value,
              source_collector = excluded.source_collector,
              raw_artifact_path = excluded.raw_artifact_path,
              raw_artifact_hash = excluded.raw_artifact_hash,
              confidence = excluded.confidence,
              status = excluded.status,
              is_deleted = excluded.is_deleted
            RETURNING id
        """
        row = self.connection.execute(query, payload).fetchone()
        if row is None:
            raise RuntimeError("Failed to upsert observation")
        return int(row["id"])

    def upsert_collection_job(self, payload: Mapping[str, object]) -> int:
        """Insert or update a collection job by run and job key."""
        query = """
            INSERT INTO collection_jobs (
              run_id, job_key, source_collector, started_at, finished_at,
              raw_artifact_path, raw_artifact_hash, confidence, status, is_retry
            ) VALUES (
              :run_id, :job_key, :source_collector, :started_at, :finished_at,
              :raw_artifact_path, :raw_artifact_hash, :confidence, :status, :is_retry
            )
            ON CONFLICT(run_id, job_key) DO UPDATE SET
              source_collector = excluded.source_collector,
              finished_at = excluded.finished_at,
              raw_artifact_path = excluded.raw_artifact_path,
              raw_artifact_hash = excluded.raw_artifact_hash,
              confidence = excluded.confidence,
              status = excluded.status,
              is_retry = excluded.is_retry
            RETURNING id
        """
        row = self.connection.execute(query, payload).fetchone()
        if row is None:
            raise RuntimeError("Failed to upsert collection job")
        return int(row["id"])

    def upsert_baseline(self, payload: Mapping[str, object]) -> int:
        """Insert or update a baseline record by baseline_key."""
        query = """
            INSERT INTO baselines (
              baseline_key, asset_id, service_id, expected_fingerprint, expected_state,
              valid_from, valid_to, source_collector, raw_artifact_path,
              raw_artifact_hash, confidence, status, is_current
            ) VALUES (
              :baseline_key, :asset_id, :service_id, :expected_fingerprint, :expected_state,
              :valid_from, :valid_to, :source_collector, :raw_artifact_path,
              :raw_artifact_hash, :confidence, :status, :is_current
            )
            ON CONFLICT(baseline_key) DO UPDATE SET
              asset_id = excluded.asset_id,
              service_id = excluded.service_id,
              expected_fingerprint = excluded.expected_fingerprint,
              expected_state = excluded.expected_state,
              valid_from = excluded.valid_from,
              valid_to = excluded.valid_to,
              source_collector = excluded.source_collector,
              raw_artifact_path = excluded.raw_artifact_path,
              raw_artifact_hash = excluded.raw_artifact_hash,
              confidence = excluded.confidence,
              status = excluded.status,
              is_current = excluded.is_current
            RETURNING id
        """
        row = self.connection.execute(query, payload).fetchone()
        if row is None:
            raise RuntimeError("Failed to upsert baseline")
        return int(row["id"])

    def upsert_discrepancy(self, payload: Mapping[str, object]) -> int:
        """Insert or update discrepancy by run and fingerprinting dimensions."""
        query = """
            INSERT INTO discrepancies (
              run_id, asset_id, service_id, baseline_id, discrepancy_type,
              fingerprint, details, detected_at, resolved_at, source_collector,
              raw_artifact_path, raw_artifact_hash, confidence, status, is_acknowledged
            ) VALUES (
              :run_id, :asset_id, :service_id, :baseline_id, :discrepancy_type,
              :fingerprint, :details, :detected_at, :resolved_at, :source_collector,
              :raw_artifact_path, :raw_artifact_hash, :confidence, :status, :is_acknowledged
            )
            ON CONFLICT DO NOTHING
            RETURNING id
        """
        row = self.connection.execute(query, payload).fetchone()
        if row is not None:
            return int(row["id"])

        existing = self.connection.execute(
            """
            SELECT id FROM discrepancies
            WHERE run_id = :run_id
              AND discrepancy_type = :discrepancy_type
              AND ifnull(asset_id, -1) = ifnull(:asset_id, -1)
              AND ifnull(service_id, -1) = ifnull(:service_id, -1)
              AND ifnull(baseline_id, -1) = ifnull(:baseline_id, -1)
              AND ifnull(fingerprint, '') = ifnull(:fingerprint, '')
            LIMIT 1
            """,
            payload,
        ).fetchone()
        if existing is None:
            raise RuntimeError("Failed to insert discrepancy")
        return int(existing["id"])

    def upsert_identity_evidence(self, payload: Mapping[str, object]) -> int:
        """Insert or update identity evidence by identity/run/evidence type."""
        query = """
            INSERT INTO identity_evidence (
              identity_id, run_id, evidence_type, weight, contribution, score, detail,
              provenance, source_collector, raw_artifact_path, raw_artifact_hash
            ) VALUES (
              :identity_id, :run_id, :evidence_type, :weight, :contribution, :score, :detail,
              :provenance, :source_collector, :raw_artifact_path, :raw_artifact_hash
            )
            ON CONFLICT(identity_id, run_id, evidence_type) DO UPDATE SET
              weight = excluded.weight,
              contribution = excluded.contribution,
              score = excluded.score,
              detail = excluded.detail,
              provenance = excluded.provenance,
              source_collector = excluded.source_collector,
              raw_artifact_path = excluded.raw_artifact_path,
              raw_artifact_hash = excluded.raw_artifact_hash
            RETURNING id
        """
        row = self.connection.execute(query, payload).fetchone()
        if row is None:
            raise RuntimeError("Failed to upsert identity evidence")
        return int(row["id"])
