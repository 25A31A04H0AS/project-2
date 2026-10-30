"""Evaluate the audit engine against public samples and synthetic invariants."""

from __future__ import annotations

import csv
from collections import Counter
import json
import sys
from pathlib import Path
from typing import Any

CODE_DIR = Path(__file__).resolve().parents[1]
ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

import main as audit  # noqa: E402


def load_csv(path: Path) -> list[dict[str, str]]:
	with path.open("r", encoding="utf-8-sig", newline="") as handle:
		return list(csv.DictReader(handle))


def compare_samples() -> dict[str, Any]:
	expected = load_csv(ROOT / "dataset" / "sample_output.csv")
	requests = load_csv(ROOT / "dataset" / "sample_deletion_requests.csv")
	identities, audit_rows = audit.identity_index()
	evidence, warnings = audit.load_evidence()
	manifest_times = {row["file_id"]: row.get("captured_at", "") for row in load_csv(ROOT / "dataset" / "evidence_files.csv")}
	actual_rows: list[dict[str, str]] = []
	for request in sorted(requests, key=lambda row: row["case_id"]):
		status, steps = audit.audit_case(request, identities, audit_rows, evidence, manifest_times)
		actual_rows.append({"case_id": request["case_id"], "deletion_status": status, "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
	actual_by_id = {row["case_id"]: row for row in actual_rows}
	expected_by_id = {row["case_id"]: row for row in expected}
	request_by_id = {row["case_id"]: row for row in requests}
	status_correct = 0
	exact_steps = 0
	sequences_correct = 0
	step_correct = 0
	step_total = 0
	field_correct = 0
	field_total = 0
	evidence_correct = 0
	evidence_total = 0
	details: list[str] = []
	for case_id in sorted(expected_by_id):
		expected_row = expected_by_id[case_id]
		actual_row = actual_by_id.get(case_id)
		if not actual_row:
			details.append(f"{case_id}: missing actual output")
			continue
		if actual_row["deletion_status"] == expected_row["deletion_status"]:
			status_correct += 1
		expected_steps = json.loads(expected_row["steps_json"])
		actual_steps = json.loads(actual_row["steps_json"])
		if actual_steps == expected_steps:
			exact_steps += 1
			sequences_correct += 1
		elif [(item.get("phase"), item.get("system_id"), item.get("resource_id"), item.get("operation")) for item in actual_steps] == [
			(item.get("phase"), item.get("system_id"), item.get("resource_id"), item.get("operation")) for item in expected_steps
		]:
			sequences_correct += 1
		for index in range(max(len(expected_steps), len(actual_steps))):
			left = expected_steps[index] if index < len(expected_steps) else {}
			right = actual_steps[index] if index < len(actual_steps) else {}
			step_total += 1
			step_correct += left == right
			for key in audit.STEP_FIELDS:
				field_total += 1
				field_correct += left.get(key) == right.get(key)
			if "evidence_id" in left or "evidence_id" in right:
				evidence_total += 1
				evidence_correct += left.get("evidence_id") == right.get("evidence_id")
		if actual_row["deletion_status"] != expected_row["deletion_status"] or actual_steps != expected_steps:
			signature = lambda item: (item.get("phase"), item.get("system_id"), item.get("resource_id"), item.get("operation"), item.get("state"), item.get("evidence_id"))
			expected_counts = Counter(signature(item) for item in expected_steps)
			actual_counts = Counter(signature(item) for item in actual_steps)
			missing = list((expected_counts - actual_counts).elements())
			extra = list((actual_counts - expected_counts).elements())
			diagnostic = ""
			if missing:
				request = request_by_id[case_id]
				user_ids, aliases = audit.resolve_subject(request, identities, audit_rows)
				cutoff = audit.parse_time(request.get("audit_at"))
				matched = [record for record in evidence if audit.record_time_allowed(record, cutoff, manifest_times) and audit.record_matches(record, user_ids, aliases)]
				unique_matches = sorted({(record.evidence_id, record.system_id, record.resource_id, record.category, str(audit.policy_violation(record, aliases, cutoff) or audit.compliant_verification(record, aliases, cutoff))) for record in matched})
				diagnostic = f"; matched={unique_matches[:12]}"
			details.append(f"{case_id}: status {expected_row['deletion_status']}->{actual_row['deletion_status']}; missing={missing}; extra={extra}{diagnostic}")
	total = len(expected)
	return {
		"total": total,
		"status_correct": status_correct,
		"step_arrays_exact": exact_steps,
		"sequence_correct": sequences_correct,
		"step_correct": step_correct,
		"step_total": step_total,
		"field_correct": field_correct,
		"field_total": field_total,
		"evidence_correct": evidence_correct,
		"evidence_total": evidence_total,
		"warnings": warnings,
		"details": details,
	}


def run_synthetic_tests() -> list[tuple[str, bool, str]]:
	checks: list[tuple[str, bool, str]] = []

	identities = {
		"user_42": {
			"email": {"current@example.test"},
			"phone": {"+1 555 123 4567"},
			"email_hash": {"abc123"},
			"name": {"Sample Person"},
		}
	}
	audit_rows = [{
		"user_id": "user_42",
		"field_name": "email",
		"old_value": "previous@example.test",
		"new_value": "current@example.test",
		"event_time": "2026-01-01T00:00:00Z",
	}]
	user_ids, aliases = audit.resolve_subject(
		{"email": "PREVIOUS@example.test", "audit_at": "2026-01-02T00:00:00Z"}, identities, audit_rows
	)
	checks.append(("historical email resolves to stable user", user_ids == {"user_42"} and "current@example.test" in aliases["email"], str(user_ids)))

	tombstone = audit.EvidenceRecord(
		"evidence_test", "2026-01-01T00:00:00Z", "identity_service", "tombstone_42", "ACCOUNT_TOMBSTONE",
		{"resource_id": "tombstone_42", "subject_reference": "user_42", "email": "previous@example.test", "name": "Sample Person"},
	)
	tombstone_action = audit.policy_violation(tombstone, aliases, audit.parse_time("2026-01-02T00:00:00Z"))
	checks.append(("tombstone preserves stable ref but redacts PII", tombstone_action == ("REPORT_EXPOSED_PII", "REDACT_RECORD"), str(tombstone_action)))

	flow = audit.EvidenceRecord(
		"evidence_test", "2026-01-01T00:00:00Z", "integration_service", "data_flow_42", "DATA_FLOW",
		{"resource_id": "data_flow_42", "enabled": True, "customer_email": "current@example.test"},
	)
	flow_action = audit.policy_violation(flow, aliases, audit.parse_time("2026-01-02T00:00:00Z"))
	checks.append(("active connector is stopped before cleanup", flow_action == ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW"), str(flow_action)))

	backup = audit.EvidenceRecord(
		"evidence_test", "2026-01-01T00:00:00Z", "backup_service", "backup_42", "BACKUP_ARCHIVE",
		{"resource_id": "backup_42", "restore_allowed": True, "customer_reference": "user_42"},
	)
	backup_action = audit.policy_violation(backup, aliases, audit.parse_time("2026-01-02T00:00:00Z"))
	checks.append(("restorable archive is blocked", backup_action == ("REPORT_RESTORE_RISK", "BLOCK_RESTORE"), str(backup_action)))

	security = audit.EvidenceRecord(
		"evidence_test", "2026-01-01T00:00:00Z", "security_service", "audit_record_42", "SECURITY_AUDIT_LOG",
		{"resource_id": "audit_record_42", "subject_reference": "user_42", "retention_until": "2027-01-01T00:00:00Z"},
	)
	policy = audit.load_policy()
	security_action = audit.policy_violation(security, aliases, audit.parse_time("2026-06-01T00:00:00Z"), policy)
	checks.append(("in-retention security audit is preserved", security_action is None, str(security_action)))

	non_delete = audit.authorized_deletion("Please stop promotional emails only; I still use the account.")
	checks.append(("marketing opt-out is not deletion", not non_delete, str(non_delete)))
	return checks


def main() -> int:
	sample = compare_samples()
	tests = run_synthetic_tests()
	full_rows = load_csv(ROOT / "output.csv") if (ROOT / "output.csv").is_file() else []
	full_requests = load_csv(ROOT / "dataset" / "deletion_requests.csv")
	valid_ids = {row["file_id"] for row in load_csv(ROOT / "dataset" / "evidence_files.csv")}
	valid_ids.update(row["activity_id"] for row in load_csv(ROOT / "dataset" / "system_activity.csv"))
	valid_ids.update(row["audit_id"] for row in load_csv(ROOT / "dataset" / "user_audit_log.csv"))
	full_errors = audit.validate_rows(full_rows, [row["case_id"] for row in full_requests], valid_ids) if full_rows else ["root output.csv has not been generated"]
	unverified_complete = sum(row["deletion_status"] == "COMPLETE" and not json.loads(row["steps_json"]) for row in full_rows)
	print(f"Sample cases: {sample['total']}")
	print(f"Status accuracy: {sample['status_correct']}/{sample['total']}")
	print(f"Exact step arrays: {sample['step_arrays_exact']}/{sample['total']}")
	print(f"Sequence accuracy: {sample['sequence_correct']}/{sample['total']}")
	print(f"Position-level step accuracy: {sample['step_correct']}/{sample['step_total']}")
	print(f"Field accuracy: {sample['field_correct']}/{sample['field_total']}")
	print(f"Evidence-reference accuracy: {sample['evidence_correct']}/{sample['evidence_total']}")
	print(f"Extractor warnings: {len(sample['warnings'])}")
	print(f"Full output schema checks: {'PASS' if not full_errors else 'FAIL'} ({len(full_rows)} rows; {len(full_errors)} errors)")
	print(f"COMPLETE rows without verification evidence: {unverified_complete}")
	for error in full_errors[:10]:
		print(f"OUTPUT ERROR: {error}")
	print("Synthetic checks:")
	for name, passed, detail in tests:
		print(f"{'PASS' if passed else 'FAIL'} {name}: {detail}")
	print("Sample differences (first 20):")
	for detail in sample["details"][:20]:
		print(f"- {detail}")
	return 0 if all(check[1] for check in tests) and not full_errors else 1


if __name__ == "__main__":
	raise SystemExit(main())
