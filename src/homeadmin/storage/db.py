"""Database storage primitives for HomeAdmin."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
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


    def insert_plan(self, payload: Mapping[str, object]) -> int:
        """Insert a new immutable plan version and return id."""
        row = self.connection.execute(
            """
            INSERT INTO plans (
              plan_key, version, parent_plan_id, title, recommendation_rule_id,
              asset_uid, priority, source_run_id, blast_radius_estimate,
              required_privilege_level, plan_hash, generated_at, created_by
            ) VALUES (
              :plan_key, :version, :parent_plan_id, :title, :recommendation_rule_id,
              :asset_uid, :priority, :source_run_id, :blast_radius_estimate,
              :required_privilege_level, :plan_hash, :generated_at, :created_by
            )
            RETURNING id
            """,
            payload,
        ).fetchone()
        if row is None:
            raise RuntimeError("Failed to insert plan")
        return int(row["id"])

    def insert_plan_step(self, payload: Mapping[str, object]) -> int:
        """Insert an immutable plan step and return id."""
        row = self.connection.execute(
            """
            INSERT INTO plan_steps (plan_id, step_order, step_kind, content)
            VALUES (:plan_id, :step_order, :step_kind, :content)
            RETURNING id
            """,
            payload,
        ).fetchone()
        if row is None:
            raise RuntimeError("Failed to insert plan step")
        return int(row["id"])

    def insert_plan_approval(self, payload: Mapping[str, object]) -> int:
        """Insert an immutable plan approval and return id."""
        row = self.connection.execute(
            """
            INSERT INTO plan_approvals (plan_id, approver, decision, rationale, decided_at)
            VALUES (:plan_id, :approver, :decision, :rationale, :decided_at)
            RETURNING id
            """,
            payload,
        ).fetchone()
        if row is None:
            raise RuntimeError("Failed to insert plan approval")
        return int(row["id"])

    def insert_plan_state_event(self, payload: Mapping[str, object]) -> int:
        """Insert an immutable plan state transition event and return id."""
        row = self.connection.execute(
            """
            INSERT INTO plan_state_events (
              plan_id, event_type, actor, occurred_at, plan_hash,
              policy_checks_json, approval_token_fingerprint, metadata_json
            ) VALUES (
              :plan_id, :event_type, :actor, :occurred_at, :plan_hash,
              :policy_checks_json, :approval_token_fingerprint, :metadata_json
            )
            RETURNING id
            """,
            payload,
        ).fetchone()
        if row is None:
            raise RuntimeError("Failed to insert plan state event")
        return int(row["id"])

    def latest_plan_version(self, plan_key: str) -> sqlite3.Row | None:
        """Fetch the latest plan row for a plan key."""
        return self.connection.execute(
            """
            SELECT * FROM plans
            WHERE plan_key = ?
            ORDER BY version DESC
            LIMIT 1
            """,
            (plan_key,),
        ).fetchone()

    def get_plan(self, plan_id: int) -> dict[str, object] | None:
        """Fetch a plan with structured steps and approvals."""
        row = self.connection.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
        if row is None:
            return None

        steps = self.connection.execute(
            """
            SELECT step_kind, step_order, content
            FROM plan_steps
            WHERE plan_id = ?
            ORDER BY step_kind, step_order
            """,
            (plan_id,),
        ).fetchall()
        approvals = self.connection.execute(
            """
            SELECT approver, decision, rationale, decided_at
            FROM plan_approvals
            WHERE plan_id = ?
            ORDER BY decided_at ASC, id ASC
            """,
            (plan_id,),
        ).fetchall()
        state_events = self.connection.execute(
            """
            SELECT event_type, actor, occurred_at, plan_hash, policy_checks_json,
                   approval_token_fingerprint, metadata_json
            FROM plan_state_events
            WHERE plan_id = ?
            ORDER BY occurred_at ASC, id ASC
            """,
            (plan_id,),
        ).fetchall()

        step_groups: dict[str, list[str]] = {
            "prerequisites": [],
            "ordered_steps": [],
            "expected_outcomes": [],
            "rollback_steps": [],
            "verification_checks": [],
        }
        for step in steps:
            kind = str(step["step_kind"])
            if kind in step_groups:
                step_groups[kind].append(str(step["content"]))
        provenance: object = {}
        for approval in approvals:
            if str(approval["decision"]) != "generated":
                continue
            rationale_value = approval["rationale"]
            if rationale_value is None:
                continue
            try:
                metadata = json.loads(str(rationale_value))
            except json.JSONDecodeError:
                continue
            provenance = metadata.get("provenance", {})
            break

        parsed_events: list[dict[str, object]] = []
        for event in state_events:
            policy_checks_value = event["policy_checks_json"]
            metadata_value = event["metadata_json"]
            parsed_events.append(
                {
                    "event_type": str(event["event_type"]),
                    "actor": str(event["actor"]),
                    "occurred_at": str(event["occurred_at"]),
                    "plan_hash": str(event["plan_hash"]),
                    "policy_checks": json.loads(str(policy_checks_value))
                    if policy_checks_value is not None
                    else {"passed": [], "failed": []},
                    "approval_token_fingerprint": event["approval_token_fingerprint"],
                    "metadata": json.loads(str(metadata_value))
                    if metadata_value is not None
                    else {},
                }
            )

        return {
            "id": int(row["id"]),
            "plan_key": str(row["plan_key"]),
            "version": int(row["version"]),
            "parent_plan_id": row["parent_plan_id"],
            "title": str(row["title"]),
            "recommendation_rule_id": str(row["recommendation_rule_id"]),
            "asset_uid": str(row["asset_uid"]),
            "priority": str(row["priority"]),
            "source_run_id": int(row["source_run_id"]),
            "blast_radius_estimate": str(row["blast_radius_estimate"]),
            "required_privilege_level": str(row["required_privilege_level"]),
            "plan_hash": str(row["plan_hash"]),
            "generated_at": str(row["generated_at"]),
            "created_by": str(row["created_by"]),
            "provenance": provenance,
            **step_groups,
            "approvals": [dict(item) for item in approvals],
            "state_events": parsed_events,
            "approval_state": self._derive_plan_state(parsed_events),
        }

    def get_plan_state(self, plan_id: int) -> str | None:
        """Return the latest state for a plan id."""
        row = self.connection.execute(
            """
            SELECT event_type
            FROM plan_state_events
            WHERE plan_id = ?
            ORDER BY occurred_at DESC, id DESC
            LIMIT 1
            """,
            (plan_id,),
        ).fetchone()
        if row is None:
            return None
        return str(row["event_type"])

    def verify_plan_hash(self, plan_id: int, expected_plan_hash: str) -> bool:
        """Verify a plan hash against the immutable persisted value."""
        row = self.connection.execute(
            "SELECT plan_hash FROM plans WHERE id = ?",
            (plan_id,),
        ).fetchone()
        if row is None:
            return False
        return str(row["plan_hash"]) == expected_plan_hash

    def append_plan_state_event(
        self,
        *,
        plan_id: int,
        event_type: str,
        actor: str,
        plan_hash: str,
        policy_checks: Mapping[str, object] | None = None,
        approval_token_fingerprint: str | None = None,
        metadata: Mapping[str, object] | None = None,
        occurred_at: str | None = None,
    ) -> int:
        """Append validated plan state transition event."""
        current = self.get_plan_state(plan_id)
        if not self._is_valid_transition(current=current, new_state=event_type):
            raise ValueError(f"invalid state transition: {current!r} -> {event_type!r}")
        if not self.verify_plan_hash(plan_id, plan_hash):
            raise ValueError("plan hash mismatch")

        policy_payload = policy_checks or {"passed": [], "failed": []}
        if occurred_at is None:
            occurred_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return self.insert_plan_state_event(
            {
                "plan_id": plan_id,
                "event_type": event_type,
                "actor": actor,
                "occurred_at": occurred_at,
                "plan_hash": plan_hash,
                "policy_checks_json": json.dumps(policy_payload, sort_keys=True),
                "approval_token_fingerprint": approval_token_fingerprint,
                "metadata_json": json.dumps(dict(metadata or {}), sort_keys=True),
            }
        )

    def assert_plan_approved_for_execution(self, plan_id: int, plan_hash: str) -> None:
        """Raise ValueError if plan is not approved and hash-verified."""
        if not self.verify_plan_hash(plan_id, plan_hash):
            raise ValueError("plan hash mismatch")
        current = self.get_plan_state(plan_id)
        if current != "approved":
            raise ValueError(f"plan is not approved for execution; current_state={current}")

    def get_previous_plan(self, plan_id: int) -> dict[str, object] | None:
        """Fetch the previous version of the supplied plan id."""
        row = self.connection.execute(
            "SELECT parent_plan_id FROM plans WHERE id = ?",
            (plan_id,),
        ).fetchone()
        if row is None or row["parent_plan_id"] is None:
            return None
        return self.get_plan(int(row["parent_plan_id"]))

    def insert_execution_run(self, payload: Mapping[str, object]) -> int:
        """Insert a plan execution run and return id."""
        row = self.connection.execute(
            """
            INSERT INTO execution_runs (
              plan_id, plan_hash, dry_run, actor, status, policy_checks_json, started_at, finished_at
            ) VALUES (
              :plan_id, :plan_hash, :dry_run, :actor, :status, :policy_checks_json, :started_at, :finished_at
            )
            RETURNING id
            """,
            payload,
        ).fetchone()
        if row is None:
            raise RuntimeError("Failed to insert execution run")
        return int(row["id"])

    def update_execution_run_status(self, run_id: int, *, status: str, finished_at: str) -> None:
        """Update mutable execution run status fields."""
        self.connection.execute(
            """
            UPDATE execution_runs
            SET status = ?, finished_at = ?
            WHERE id = ?
            """,
            (status, finished_at, run_id),
        )

    def insert_execution_step_result(self, payload: Mapping[str, object]) -> int:
        """Insert one immutable execution step result and return id."""
        row = self.connection.execute(
            """
            INSERT INTO execution_step_results (
              execution_run_id, step_order, step_id, action_type, target_scope, command,
              args_json, environment_policy_json, stdout, stderr, exit_code, artifact_hash
            ) VALUES (
              :execution_run_id, :step_order, :step_id, :action_type, :target_scope, :command,
              :args_json, :environment_policy_json, :stdout, :stderr, :exit_code, :artifact_hash
            )
            RETURNING id
            """,
            payload,
        ).fetchone()
        if row is None:
            raise RuntimeError("Failed to insert execution step result")
        return int(row["id"])

    def get_execution_run(self, *, plan_id: int, plan_hash: str, dry_run: bool) -> sqlite3.Row | None:
        """Fetch one execution run by idempotency key."""
        return self.connection.execute(
            """
            SELECT * FROM execution_runs
            WHERE plan_id = ? AND plan_hash = ? AND dry_run = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (plan_id, plan_hash, 1 if dry_run else 0),
        ).fetchone()

    def count_execution_steps(self, execution_run_id: int) -> int:
        """Count persisted execution steps for a run id."""
        row = self.connection.execute(
            "SELECT COUNT(*) AS count FROM execution_step_results WHERE execution_run_id = ?",
            (execution_run_id,),
        ).fetchone()
        if row is None:
            return 0
        return int(row["count"])

    def count_running_apply_executions(self) -> int:
        """Return active non-dry-run executions currently marked running."""
        row = self.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM execution_runs
            WHERE dry_run = 0 AND status = 'running'
            """
        ).fetchone()
        if row is None:
            return 0
        return int(row["count"])

    def persist_compiled_plan(
        self,
        plan: Mapping[str, object],
        *,
        source_run_id: int,
        generated_at: str,
        plan_hash: str,
        created_by: str,
    ) -> tuple[int, int, bool]:
        """Persist one plan with immutable versioning; returns (id, version, created_new)."""
        plan_key = str(plan["plan_key"])
        latest = self.latest_plan_version(plan_key)
        if latest is not None and str(latest["plan_hash"]) == plan_hash:
            return int(latest["id"]), int(latest["version"]), False

        next_version = 1
        parent_plan_id = None
        if latest is not None:
            next_version = int(latest["version"]) + 1
            parent_plan_id = int(latest["id"])

        plan_id = self.insert_plan(
            {
                "plan_key": plan_key,
                "version": next_version,
                "parent_plan_id": parent_plan_id,
                "title": str(plan["title"]),
                "recommendation_rule_id": str(plan["recommendation_rule_id"]),
                "asset_uid": str(plan["asset_uid"]),
                "priority": str(plan["priority"]),
                "source_run_id": source_run_id,
                "blast_radius_estimate": str(plan["blast_radius_estimate"]),
                "required_privilege_level": str(plan["required_privilege_level"]),
                "plan_hash": plan_hash,
                "generated_at": generated_at,
                "created_by": created_by,
            }
        )

        for step_kind in (
            "prerequisites",
            "ordered_steps",
            "expected_outcomes",
            "rollback_steps",
            "verification_checks",
        ):
            values = plan.get(step_kind, [])
            if not isinstance(values, list):
                continue
            for index, content in enumerate(values, start=1):
                self.insert_plan_step(
                    {
                        "plan_id": plan_id,
                        "step_order": index,
                        "step_kind": step_kind,
                        "content": str(content),
                    }
                )

        metadata = {"provenance": plan.get("provenance")}
        self.insert_plan_approval(
            {
                "plan_id": plan_id,
                "approver": "system",
                "decision": "generated",
                "rationale": json.dumps(metadata, sort_keys=True),
                "decided_at": generated_at,
            }
        )
        self.append_plan_state_event(
            plan_id=plan_id,
            event_type="draft",
            actor="system",
            plan_hash=plan_hash,
            policy_checks={"passed": ["plan_generated"], "failed": []},
            metadata={"source": "plan-generate"},
            occurred_at=generated_at,
        )
        self.append_plan_state_event(
            plan_id=plan_id,
            event_type="proposed",
            actor="system",
            plan_hash=plan_hash,
            policy_checks={"passed": ["plan_generated"], "failed": []},
            metadata={"source": "plan-generate"},
            occurred_at=generated_at,
        )

        return plan_id, next_version, True

    @staticmethod
    def _derive_plan_state(events: list[dict[str, object]]) -> str:
        if not events:
            return "unknown"
        return str(events[-1]["event_type"])

    @staticmethod
    def _is_valid_transition(*, current: str | None, new_state: str) -> bool:
        allowed: dict[str | None, set[str]] = {
            None: {"draft"},
            "draft": {"proposed"},
            "proposed": {"approved", "rejected"},
            "approved": {"executed", "rejected"},
            "rejected": {"proposed"},
            "executed": set(),
        }
        return new_state in allowed.get(current, set())
