"""Deterministic deletion audit pipeline for the Orchestrate challenge."""

from __future__ import annotations

import csv
import functools
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
OUTPUT = ROOT / "output.csv"
OUTPUT_FIELDS = ["case_id", "deletion_status", "steps_json"]
STEP_FIELDS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = {
	"REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2,
	"REPORT_RESTORE_RISK": 3, "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1,
	"DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
	"VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2,
	"VERIFY_RECORD_ANONYMIZED": 3, "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,
}
ALLOWED = {
	("FINDING", "REPORT_REMAINING_RECORD", "PRESENT"), ("FINDING", "REPORT_EXPOSED_PII", "PRESENT"),
	("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"), ("FINDING", "REPORT_RESTORE_RISK", "ACTIVE"),
	("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED"), ("REMEDIATION", "BLOCK_RESTORE", "BLOCKED"),
	("REMEDIATION", "DELETE_RECORD", "ABSENT"), ("REMEDIATION", "REDACT_RECORD", "REDACTED"),
	("REMEDIATION", "ANONYMIZE_RECORD", "ANONYMIZED"), ("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
	("VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"), ("VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED"),
	("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"), ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
	("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
}
EMAIL_PATTERN = re.compile(r"(?i)\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
RESOURCE_PATTERN = re.compile(
	r"\b(?:account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|"
	r"marketing|cache|email_delivery|object|telemetry|legal_hold)_\d+\b", re.IGNORECASE
)
USER_PATTERN = re.compile(r"\buser_\d+\b", re.IGNORECASE)
TIME_FIELDS = {"captured_at", "recorded_at", "observed_at", "updated_at", "event_time", "event_at", "exported_at", "created_at", "timestamp", "snapshot_time"}


@dataclass
class EvidenceRecord:
	evidence_id: str
	captured_at: str
	system_id: str
	resource_id: str
	category: str
	fields: dict[str, Any] = field(default_factory=dict)
	raw_text: str = ""

	def searchable_text(self) -> str:
		values = [self.raw_text, self.system_id, self.resource_id, self.category]
		values.extend(str(value) for value in self.fields.values() if value is not None)
		return " ".join(values)


def read_csv(path: Path) -> list[dict[str, str]]:
	with path.open("r", encoding="utf-8-sig", newline="") as handle:
		return list(csv.DictReader(handle))


def parse_time(value: Any) -> datetime | None:
	if not value:
		return None
	try:
		parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
		if parsed.tzinfo is None:
			parsed = parsed.replace(tzinfo=timezone.utc)
		return parsed.astimezone(timezone.utc)
	except (TypeError, ValueError):
		return None


def truthy(value: Any) -> bool:
	return str(value).strip().casefold() in {"1", "true", "yes", "enabled", "active", "allowed"}


def normalize_email(value: str) -> str:
	return value.strip().casefold()


def normalize_text(value: str) -> str:
	decomposed = unicodedata.normalize("NFKD", value.casefold())
	return "".join(character for character in decomposed if not unicodedata.combining(character))


def normalize_phone(value: str) -> str:
	return "".join(character for character in value if character.isdigit())


@functools.lru_cache(maxsize=None)
def find_tool(name: str) -> str | None:
	found = shutil.which(name)
	if found:
		return found
	if os.name != "nt":
		return None
	local_app_data = os.environ.get("LOCALAPPDATA")
	if not local_app_data:
		return None
	package_root = Path(local_app_data) / "Microsoft" / "WinGet" / "Packages"
	if package_root.is_dir():
		for package in package_root.glob("*"):
			is_requested_tool = name.casefold() in package.name.casefold()
			if name.casefold() == "pdftotext":
				is_requested_tool = is_requested_tool or "poppler" in package.name.casefold()
			if is_requested_tool:
				for executable in package.rglob(name + ".exe"):
					return str(executable)
	return None


def derive_category(system: str, resource: str, values: dict[str, Any], context: str = "") -> str:
	hints = " ".join([system, resource, context] + [str(values.get(key, "")) for key in ("record_type", "data_category", "collection", "table", "origin_system")]).casefold()
	explicit = str(values.get("record_type") or values.get("data_category") or "").upper()
	known = {"USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "ANALYTICS_PROFILE", "PRODUCT_TELEMETRY", "USER_EXPORT", "MARKETING_PROFILE", "EMAIL_DELIVERY_LOG", "SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE", "ACCOUNT_TOMBSTONE"}
	if explicit in known:
		return explicit
	if str(values.get("event", "")).casefold().startswith("contact_query_") or str(values.get("event", "")).casefold() == "contact_lookup_completed":
		return "SECONDARY_IDENTIFIER"
	if "support_replica.log" in context.casefold() and resource.startswith("support_"):
		return "SECONDARY_IDENTIFIER"
	if resource.startswith("tombstone_"):
		return "ACCOUNT_TOMBSTONE"
	if resource.startswith("data_flow_"):
		return "DATA_FLOW"
	if resource.startswith("backup_"):
		return "BACKUP_ARCHIVE"
	if resource.startswith("audit_record_"):
		return "SECURITY_AUDIT_LOG"
	if resource.startswith("account_"):
		return "USER_PROFILE"
	if resource.startswith("search_"):
		return "SEARCH_INDEX_ENTRY"
	if resource.startswith("analytics_"):
		return "ANALYTICS_PROFILE"
	if resource.startswith("export_"):
		return "USER_EXPORT"
	if resource.startswith("marketing_"):
		return "MARKETING_PROFILE"
	if resource.startswith("cache_"):
		return "CACHE_ENTRY"
	if resource.startswith("support_") and "attachment" in hints:
		return "SUPPORT_ATTACHMENT"
	if resource.startswith("support_"):
		return "SUPPORT_MESSAGE"
	if resource.startswith("object_") and "attachment" in hints:
		return "SUPPORT_ATTACHMENT"
	for hint, category in (
		("tombstone", "ACCOUNT_TOMBSTONE"), ("deleted_customer_references", "ACCOUNT_TOMBSTONE"),
		("backup", "BACKUP_ARCHIVE"), ("restore", "BACKUP_ARCHIVE"), ("security_audit", "SECURITY_AUDIT_LOG"),
		("audit_record", "SECURITY_AUDIT_LOG"), ("security_service", "SECURITY_AUDIT_LOG"), ("legal_hold", "LEGAL_HOLD_RECORD"),
		("email_delivery", "EMAIL_DELIVERY_LOG"), ("delivery_log", "EMAIL_DELIVERY_LOG"), ("marketing", "MARKETING_PROFILE"),
		("export", "USER_EXPORT"), ("telemetry", "PRODUCT_TELEMETRY"), ("product_event", "PRODUCT_TELEMETRY"),
		("analytics", "ANALYTICS_PROFILE"), ("support_attachment", "SUPPORT_ATTACHMENT"), ("attachment", "SUPPORT_ATTACHMENT"),
		("support_message", "SUPPORT_MESSAGE"), ("support_records", "SUPPORT_MESSAGE"), ("search", "SEARCH_INDEX_ENTRY"),
		("cache", "CACHE_ENTRY"), ("customer_profiles", "USER_PROFILE"),
	):
		if hint in hints:
			return category
	return "SECONDARY_IDENTIFIER"


def derive_system(resource: str, values: dict[str, Any], context: str = "") -> str:
	for key in ("system", "data_store", "origin_system", "source_system", "target_system"):
		value = values.get(key)
		if value and str(value).strip().casefold() not in {"none", "null"}:
			candidate = str(value).strip()
			return "support_platform" if candidate == "support_replica" else candidate
	category = derive_category("", resource, values, context)
	systems = {
		"USER_PROFILE": "account_service", "SECONDARY_IDENTIFIER": "identity_service", "SEARCH_INDEX_ENTRY": "search_service",
		"CACHE_ENTRY": "cache_service", "SUPPORT_MESSAGE": "support_platform", "SUPPORT_ATTACHMENT": "support_platform",
		"ANALYTICS_PROFILE": "analytics_platform", "PRODUCT_TELEMETRY": "analytics_platform", "USER_EXPORT": "export_service",
		"MARKETING_PROFILE": "marketing_platform", "EMAIL_DELIVERY_LOG": "email_delivery_service", "SECURITY_AUDIT_LOG": "security_service",
		"LEGAL_HOLD_RECORD": "legal_service", "BACKUP_ARCHIVE": "backup_service", "ACCOUNT_TOMBSTONE": "identity_service",
		"DATA_FLOW": "integration_service",
	}
	return systems.get(category, "unknown_system")


def timestamp_in_record(values: dict[str, Any], fallback: str) -> str:
	for name, value in values.items():
		if name.casefold() in TIME_FIELDS and parse_time(value):
			return str(value)
	return fallback


def make_record(evidence_id: str, file_time: str, values: dict[str, Any], context: str = "", raw_text: str = "") -> EvidenceRecord | None:
	resource = str(values.get("resource_id") or values.get("resource") or "").strip()
	if not resource:
		match = RESOURCE_PATTERN.search(raw_text)
		resource = match.group(0) if match else ""
	if not resource:
		return None
	system = derive_system(resource, values, context)
	category = derive_category(system, resource, values, context)
	return EvidenceRecord(evidence_id, timestamp_in_record(values, file_time), system, resource, category, dict(values), raw_text)


def walk_json(value: Any, evidence_id: str, file_time: str, context: str, records: list[EvidenceRecord], inherited: dict[str, Any] | None = None, parent_key: str = "") -> None:
	if isinstance(value, list):
		for child in value:
			walk_json(child, evidence_id, file_time, context, records, inherited, parent_key)
		return
	if not isinstance(value, dict):
		return
	local = dict(inherited or {})
	known_systems = {"account_service", "analytics_platform", "backup_service", "export_service", "integration_service", "search_service", "security_service", "support_platform", "identity_service", "marketing_platform", "email_delivery_service", "object_storage", "cache_service"}
	if parent_key in known_systems:
		local["system"] = parent_key
	for key in ("data_store", "system", "origin_system", "collection", "record_type", "captured_at", "exported_at"):
		if value.get(key) is not None:
			local[key] = value[key]
	if value.get("resource_id") or value.get("status_code") or value.get("http_status"):
		candidate = dict(local)
		candidate.update(value)
		record = make_record(evidence_id, file_time, candidate, context, json.dumps(candidate, ensure_ascii=False))
		if record:
			records.append(record)
	for key, child in value.items():
		if isinstance(child, (dict, list)):
			walk_json(child, evidence_id, file_time, context, records, local, key)


def parse_sql(path: Path, evidence_id: str, file_time: str, records: list[EvidenceRecord]) -> None:
	connection = sqlite3.connect(":memory:")
	try:
		connection.executescript(path.read_text(encoding="utf-8", errors="replace"))
		tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
		for (table_name,) in tables:
			try:
				cursor = connection.execute('SELECT * FROM "' + table_name.replace('"', '""') + '"')
				columns = [item[0] for item in cursor.description or []]
				for row in cursor.fetchall():
					values = dict(zip(columns, row))
					values["table"] = table_name
					record = make_record(evidence_id, file_time, values, table_name, json.dumps(values, default=str))
					if record:
						records.append(record)
			except sqlite3.Error:
				continue
	except (sqlite3.Error, OSError):
		return
	finally:
		connection.close()


def extract_text(path: Path) -> tuple[str, str]:
	suffix = path.suffix.casefold()
	commands: list[list[str]] = []
	if suffix == ".pdf":
		pdftotext = find_tool("pdftotext")
		mutool = find_tool("mutool")
		if pdftotext:
			commands.append([pdftotext, "-layout", str(path), "-"])
		if mutool:
			commands.append([mutool, "draw", "-F", "txt", "-o", "-", str(path)])
	elif suffix in {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".webp"}:
		tesseract = find_tool("tesseract")
		if tesseract:
			commands.append([tesseract, str(path), "stdout"])
	for command in commands:
		try:
			result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
			if result.returncode == 0 and result.stdout.strip():
				return result.stdout, ""
		except (OSError, subprocess.SubprocessError):
			continue
	if suffix in {".pdf", ".png", ".jpg", ".jpeg", ".tif", ".tiff", ".webp"}:
		return "", f"No supported local extractor succeeded for {path.name}"
	return path.read_text(encoding="utf-8", errors="replace"), ""


def parse_text_records(text: str, evidence_id: str, file_time: str, context: str) -> list[EvidenceRecord]:
	records: list[EvidenceRecord] = []
	lines = text.splitlines()
	chunks: list[list[str]] = []
	if context.casefold().endswith(".pdf"):
		chunks = [lines]
	else:
		by_trace: dict[str, list[str]] = {}
		for line in lines:
			trace_match = re.search(r"\btrace_id=([a-zA-Z0-9_-]+)", line)
			if trace_match:
				by_trace.setdefault(trace_match.group(1), []).append(line)
			else:
				chunks.append([line])
		chunks.extend(by_trace.values())
	for chunk in chunks:
		chunk_text = "\n".join(chunk)
		resource_ids = list(dict.fromkeys(match.group(0) for match in RESOURCE_PATTERN.finditer(chunk_text)))
		if not resource_ids:
			continue
		values: dict[str, Any] = {}
		for line in chunk:
			pipe_fields = [part.strip() for part in line.split("|")]
			if len(pipe_fields) >= 5 and RESOURCE_PATTERN.fullmatch(pipe_fields[2]):
				values.update({"system": pipe_fields[1], "resource_id": pipe_fields[2], "record_type": pipe_fields[3], "result": pipe_fields[4]})
				if pipe_fields[3] == "BACKUP_ARCHIVE":
					values["restore_allowed"] = pipe_fields[4].casefold() == "active"
				elif pipe_fields[3] in {"DATA_FLOW", "INTEGRATION"}:
					values["enabled"] = pipe_fields[4].casefold() == "active"
				if len(pipe_fields) > 5:
					values["subject_reference"] = pipe_fields[5]
			time_match = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)", line)
			if time_match:
				values["event_time"] = time_match.group(1)
			for key, value in re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)=([^\s]+|"[^"]*")', line):
				values[key] = value.strip('"')
			for key in ("service", "system", "function"):
				system_match = re.search(r"\b" + key + r"=([a-zA-Z_][a-zA-Z0-9_]*)", line)
				if system_match:
					values["system"] = system_match.group(1)
		for resource_id in resource_ids:
			row_values = dict(values)
			row_values["resource_id"] = resource_id
			record = make_record(evidence_id, file_time, row_values, context, chunk_text)
			if record:
				records.append(record)
	return records


def load_evidence() -> tuple[list[EvidenceRecord], list[str]]:
	records: list[EvidenceRecord] = []
	warnings: list[str] = []
	for item in read_csv(DATASET / "evidence_files.csv"):
		path = DATASET / item["file_path"]
		if not path.is_file():
			warnings.append(f"Missing evidence file: {item['file_path']}")
			continue
		try:
			if path.suffix.casefold() == ".sql":
				parse_sql(path, item["file_id"], item.get("captured_at", ""), records)
			elif path.suffix.casefold() == ".json":
				payload = json.loads(path.read_text(encoding="utf-8-sig"))
				walk_json(payload, item["file_id"], item.get("captured_at", ""), item["file_path"], records)
			else:
				text, warning = extract_text(path)
				if warning:
					warnings.append(f"{item['file_id']}: {warning}")
				records.extend(parse_text_records(text, item["file_id"], item.get("captured_at", ""), item["file_path"]))
		except (OSError, UnicodeError, json.JSONDecodeError, sqlite3.Error) as error:
			warnings.append(f"{item['file_id']}: unreadable evidence ({type(error).__name__})")
	for activity in read_csv(DATASET / "system_activity.csv"):
		event_time = activity.get("event_time", "")
		event_type = activity.get("event_type", "")
		resource = activity.get("resource_id", "")
		if not resource or event_type != "LINK_RESOURCE_IDENTITY":
			continue
		details = activity.get("details", "")
		values: dict[str, Any] = {"resource_id": resource, "system": activity.get("target_system", ""), "identity_link": True}
		user_match = USER_PATTERN.search(details)
		if user_match:
			values["subject_reference"] = user_match.group(0)
		email_match = EMAIL_PATTERN.search(details)
		if email_match:
			values["email"] = email_match.group(0)
		if activity.get("target_system") == "object_storage":
			values["record_type"] = "SUPPORT_ATTACHMENT"
		record = make_record(activity["activity_id"], event_time, values, activity.get("target_system", ""), details)
		if record:
			records.append(record)
	return records, warnings


def identity_index() -> tuple[dict[str, dict[str, set[str]]], list[dict[str, str]]]:
	identities: dict[str, dict[str, set[str]]] = {}
	for row in read_csv(DATASET / "user_identities.csv"):
		user_id = row["user_id"]
		identities[user_id] = {key: set() for key in ("email", "phone", "email_hash", "name", "_updated_at")}
		identities[user_id]["_updated_at"].add(row.get("updated_at", ""))
		for key in ("email", "phone", "email_hash", "name"):
			if row.get(key):
				identities[user_id][key].add(row[key])
	audit_rows = read_csv(DATASET / "user_audit_log.csv")
	for row in audit_rows:
		user_id = row.get("user_id", "")
		field_name = row.get("field_name", "").casefold()
		if user_id in identities and field_name in identities[user_id]:
			identities[user_id][field_name].update(value for value in (row.get("old_value", ""), row.get("new_value", "")) if value)
	return identities, audit_rows


def authorized_deletion(text: str) -> bool:
	normalized = normalize_text(text)
	non_delete = re.compile(
		r"\b(?:not asking for deletion|not a request to erase|do not delete|don't delete|dont delete|"
		r"please don't delete|please do not delete|leave (?:the )?account|keep (?:the )?account|"
		r"keep my account|still need the account|still use it|still want the account|without removing|"
		r"without deleting|not delete|remove me from (?:the )?marketing|stop (?:the )?promotional|"
		r"unsubscribe|opt out|download (?:my|the) (?:account|personal|data)|information request|"
		r"correct (?:my|the) (?:name|email|phone|address)|change (?:my|the) (?:email|phone)|"
		r"reset (?:my|the) login|no estoy solicitando|no solicito la eliminacion|"
		r"pas une demande de suppression|ne demande pas la suppression|nao estou pedindo.*exclusao)\b"
	)
	if non_delete.search(normalized):
		return False
	if any(token in normalized for token in ("削除", "消去", "退会", "解約")):
		return True
	deletion = re.compile(
		r"\b(?:delet\w*|erase|erasure|remov(?:e|ed|al)|close|closure|wipe|purge|eliminat\w*|"
		r"suppression|supprimer|effacer|borrar|eliminar|excluir|exclusao|apag\w*|削除|消去|退会|解約)\b"
	)
	return deletion.search(normalized) is not None or re.search(r"\b(?:verify|audit|check|investigate)\b.{0,100}\b(?:profile|account|data)\b.{0,80}\b(?:gone|missing|no longer exists)\b", normalized) is not None


def resolve_subject(request: dict[str, str], identities: dict[str, dict[str, set[str]]], audit_rows: list[dict[str, str]]) -> tuple[set[str], dict[str, set[str]]]:
	requested_email = normalize_email(request.get("email", ""))
	cutoff = parse_time(request.get("audit_at"))
	user_ids: set[str] = set()
	aliases: dict[str, set[str]] = {key: set() for key in ("email", "phone", "email_hash", "name")}
	for user_id, values in identities.items():
		snapshot_times = [parse_time(value) for value in values.get("_updated_at", set())]
		snapshot_times = [value for value in snapshot_times if value is not None]
		snapshot_time = max(snapshot_times) if snapshot_times else None
		if (cutoff is None or snapshot_time is None or snapshot_time <= cutoff) and requested_email in {normalize_email(value) for value in values["email"]}:
			user_ids.add(user_id)
	for audit in audit_rows:
		if audit.get("field_name", "").casefold() != "email":
			continue
		event_time = parse_time(audit.get("event_time"))
		if cutoff and event_time and event_time > cutoff:
			continue
		if requested_email in {normalize_email(audit.get("old_value", "")), normalize_email(audit.get("new_value", ""))}:
			user_ids.add(audit.get("user_id", ""))
	user_ids.discard("")
	for user_id in user_ids:
		values = identities.get(user_id, {})
		snapshot_times = [parse_time(value) for value in values.get("_updated_at", set())]
		snapshot_times = [value for value in snapshot_times if value is not None]
		snapshot_time = max(snapshot_times) if snapshot_times else None
		if cutoff is None or snapshot_time is None or snapshot_time <= cutoff:
			for field_name in aliases:
				aliases[field_name].update(values.get(field_name, set()))
		for audit in audit_rows:
			if audit.get("user_id") != user_id:
				continue
			event_time = parse_time(audit.get("event_time"))
			if cutoff and event_time and event_time > cutoff:
				continue
			field_name = audit.get("field_name", "").casefold()
			if field_name in aliases:
				aliases[field_name].update(value for value in (audit.get("old_value", ""), audit.get("new_value", "")) if value)
	aliases["email"].add(request.get("email", ""))
	return user_ids, aliases


def record_matches(record: EvidenceRecord, user_ids: set[str], aliases: dict[str, set[str]]) -> bool:
	text = record.searchable_text()
	emails = {normalize_email(value) for value in EMAIL_PATTERN.findall(text)}
	if emails & {normalize_email(value) for value in aliases["email"] if value}:
		return True
	users = {value.casefold() for value in USER_PATTERN.findall(text)}
	if users & {value.casefold() for value in user_ids}:
		return True
	if any(value and value.casefold() in text.casefold() for value in aliases["email_hash"]):
		return True
	for key in ("name", "full_name", "display_name", "requester_name", "customer_name"):
		value = get_field(record, key)
		if value and normalize_text(str(value).strip()) in {normalize_text(name.strip()) for name in aliases["name"]}:
			return True
	digits = normalize_phone(text)
	return any(len(normalize_phone(value)) >= 8 and re.search(r"(?<!\d)" + re.escape(normalize_phone(value)) + r"(?!\d)", digits) for value in aliases["phone"])


def resource_links_for_subject(evidence: list[EvidenceRecord], user_ids: set[str], aliases: dict[str, set[str]], cutoff: datetime, manifest_times: dict[str, str]) -> set[str]:
	return {
		record.resource_id
		for record in evidence
		if truthy(get_field(record, "identity_link"))
		and record_time_allowed(record, cutoff, manifest_times)
		and record_matches(record, user_ids, aliases)
	}


def record_time_allowed(record: EvidenceRecord, cutoff: datetime, manifest_times: dict[str, str]) -> bool:
	file_time = parse_time(manifest_times.get(record.evidence_id))
	observed = parse_time(record.captured_at)
	return not ((file_time and file_time > cutoff) or (observed and observed > cutoff))


def get_field(record: EvidenceRecord, *names: str) -> Any:
	fields = {str(key).casefold(): value for key, value in record.fields.items()}
	for name in names:
		value = fields.get(name.casefold())
		if value is not None and str(value).strip().casefold() not in {"", "none", "null"}:
			return value
	return None


def has_direct_identifier(record: EvidenceRecord, aliases: dict[str, set[str]]) -> bool:
	text = record.searchable_text()
	emails = {normalize_email(value) for value in EMAIL_PATTERN.findall(text)}
	if emails & {normalize_email(value) for value in aliases["email"] if value}:
		return True
	if any(value and value.casefold() in text.casefold() for value in aliases["email_hash"]):
		return True
	for key in ("name", "full_name", "display_name", "requester_name", "customer_name"):
		value = get_field(record, key)
		if value and normalize_text(str(value).strip()) in {normalize_text(name.strip()) for name in aliases["name"]}:
			return True
	digits = normalize_phone(text)
	return any(len(normalize_phone(value)) >= 8 and normalize_phone(value) in digits for value in aliases["phone"])


def load_policy() -> dict[str, dict[str, str]]:
	return {
		row["data_category"]: {"condition": row.get("condition", ""), "required_action": row.get("required_action", "")}
		for row in read_csv(DATASET / "deletion_rules.csv")
	}


def policy_violation(record: EvidenceRecord, aliases: dict[str, set[str]], cutoff: datetime, policy: dict[str, dict[str, str]] | None = None) -> tuple[str, str] | None:
	category = record.category
	if category == "DATA_FLOW":
		enabled = get_field(record, "enabled", "active", "scheduler_registered")
		if enabled is not None and truthy(enabled):
			return "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW"
	rule = (policy or load_policy()).get(category)
	if rule is None:
		return None
	action = rule["required_action"]
	if action == "DELETE" and category in {"USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "USER_EXPORT", "MARKETING_PROFILE", "SUPPORT_ATTACHMENT"}:
		return "REPORT_REMAINING_RECORD", "DELETE_RECORD"
	if category == "SUPPORT_MESSAGE" and action == "REDACT" and has_direct_identifier(record, aliases):
		return "REPORT_EXPOSED_PII", "REDACT_RECORD"
	if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"} and action == "ANONYMIZE":
		linked = bool(get_field(record, "customer_reference", "user_id", "subject_reference"))
		if has_direct_identifier(record, aliases) or linked:
			return "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD"
	if category == "EMAIL_DELIVERY_LOG" and action == "REDACT" and has_direct_identifier(record, aliases):
		return "REPORT_EXPOSED_PII", "REDACT_RECORD"
	if category == "SECURITY_AUDIT_LOG" and action == "RETAIN":
		retention = parse_time(get_field(record, "retention_until"))
		if retention is not None and retention < cutoff:
			return "REPORT_REMAINING_RECORD", "DELETE_RECORD"
	if category == "LEGAL_HOLD_RECORD" and action == "RETAIN" and not truthy(get_field(record, "active", "legal_hold_active", "hold_active")):
		return "REPORT_REMAINING_RECORD", "DELETE_RECORD"
	if category == "BACKUP_ARCHIVE" and action == "RETAIN":
		restore_allowed = get_field(record, "restore_allowed", "restore_access", "restore_allowed_for_subject")
		if restore_allowed is None and truthy(get_field(record, "eligible")) and not truthy(get_field(record, "deletion_block")):
			restore_allowed = True
		if restore_allowed is not None and truthy(restore_allowed):
			return "REPORT_RESTORE_RISK", "BLOCK_RESTORE"
	if category == "ACCOUNT_TOMBSTONE" and action == "REDACT":
		if any(get_field(record, key) for key in ("name", "full_name", "email", "phone", "email_hash")):
			return "REPORT_EXPOSED_PII", "REDACT_RECORD"
	return None


def compliant_verification(record: EvidenceRecord, aliases: dict[str, set[str]], cutoff: datetime) -> tuple[str, str] | None:
	category = record.category
	raw = normalize_text(record.searchable_text())
	if category == "USER_PROFILE":
		status = get_field(record, "status_code", "http_status", "result", "lookup_result", "account_status")
		if str(status).casefold() in {"404", "not_found", "absent", "deleted"} or "rows=0" in raw or "not_found" in raw:
			return "VERIFY_RECORD_ABSENT", "ABSENT"
	if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"} and not has_direct_identifier(record, aliases):
		if not get_field(record, "customer_reference", "user_id", "subject_reference"):
			return "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
	if category == "SUPPORT_MESSAGE" and not has_direct_identifier(record, aliases):
		return "VERIFY_RECORD_REDACTED", "REDACTED"
	if category == "EMAIL_DELIVERY_LOG" and not has_direct_identifier(record, aliases):
		return "VERIFY_RECORD_REDACTED", "REDACTED"
	if category == "ACCOUNT_TOMBSTONE":
		stable = get_field(record, "subject_reference", "user_id", "customer_reference")
		if stable and not any(get_field(record, key) for key in ("name", "full_name", "email", "phone", "email_hash")):
			return "VERIFY_RECORD_REDACTED", "REDACTED"
	if category == "SECURITY_AUDIT_LOG":
		retention = parse_time(get_field(record, "retention_until"))
		if retention is None or retention >= cutoff:
			return "VERIFY_RECORD_PRESENT", "PRESENT"
	if category == "LEGAL_HOLD_RECORD" and truthy(get_field(record, "active", "legal_hold_active", "hold_active")):
		return "VERIFY_RECORD_PRESENT", "PRESENT"
	if category == "BACKUP_ARCHIVE":
		restore_allowed = get_field(record, "restore_allowed", "restore_access", "restore_allowed_for_subject")
		if restore_allowed is None and truthy(get_field(record, "eligible")) and not truthy(get_field(record, "deletion_block")):
			restore_allowed = True
		if restore_allowed is not None and not truthy(restore_allowed):
			return "VERIFY_RESTORE_BLOCKED", "BLOCKED"
	if category == "DATA_FLOW":
		enabled = get_field(record, "enabled", "active", "scheduler_registered")
		if enabled is not None and not truthy(enabled):
			return "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
	return None


def explicit_absent(record: EvidenceRecord) -> bool:
	raw = normalize_text(record.searchable_text())
	status = get_field(record, "status_code", "http_status", "result", "lookup_result")
	return str(status).casefold() in {"404", "not_found", "absent", "deleted"} or "rows=0" in raw or "not_found" in raw or "result=miss" in raw


def make_step(phase: str, system: str, resource: str, operation: str, state: str, evidence_id: str) -> dict[str, Any]:
	return {"step_no": 0, "phase": phase, "system_id": system, "resource_id": resource, "operation": operation, "state": state, "evidence_id": evidence_id}


def sort_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
	unique: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
	for item in steps:
		key = (item["phase"], item["system_id"], item["resource_id"], item["operation"], item["state"])
		previous = unique.get(key)
		if previous is None or (not previous["evidence_id"] and item["evidence_id"]):
			unique[key] = item
	ordered = sorted(unique.values(), key=lambda item: (PHASE_ORDER[item["phase"]], OPERATION_ORDER[item["operation"]], item["system_id"], item["resource_id"], item["evidence_id"]))
	for number, item in enumerate(ordered, start=1):
		item["step_no"] = number
	return ordered


def audit_case(request: dict[str, str], identities: dict[str, dict[str, set[str]]], audit_rows: list[dict[str, str]], evidence: list[EvidenceRecord], manifest_times: dict[str, str], policy: dict[str, dict[str, str]] | None = None) -> tuple[str, list[dict[str, Any]]]:
	if not authorized_deletion(request.get("request_text", "")):
		return "NOT_APPLICABLE", []
	cutoff = parse_time(request.get("audit_at")) or datetime.max.replace(tzinfo=timezone.utc)
	user_ids, aliases = resolve_subject(request, identities, audit_rows)
	linked_resources = resource_links_for_subject(evidence, user_ids, aliases, cutoff, manifest_times)
	relevant = [
		record for record in evidence
		if not truthy(get_field(record, "identity_link"))
		and record_time_allowed(record, cutoff, manifest_times)
		and (record.resource_id in linked_resources or record_matches(record, user_ids, aliases))
	]
	latest: dict[tuple[str, str, str], EvidenceRecord] = {}
	for record in relevant:
		key = (record.system_id, record.resource_id, record.category)
		current_time = parse_time(record.captured_at) or datetime.min.replace(tzinfo=timezone.utc)
		old = latest.get(key)
		old_time = parse_time(old.captured_at) if old else None
		if old is None or current_time >= (old_time or datetime.min.replace(tzinfo=timezone.utc)):
			latest[key] = record
	records = list(latest.values())
	findings: list[dict[str, Any]] = []
	remediation: list[dict[str, Any]] = []
	verification: list[dict[str, Any]] = []
	violations: set[tuple[str, str]] = set()
	remediation_state = {"DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED", "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED"}
	verify_operation = {"DELETE_RECORD": "VERIFY_RECORD_ABSENT", "REDACT_RECORD": "VERIFY_RECORD_REDACTED", "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED", "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED", "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED"}
	for record in records:
		if truthy(get_field(record, "identity_link")):
			continue
		if record.category == "USER_PROFILE" and explicit_absent(record):
			verification.append(make_step("VERIFICATION", record.system_id, record.resource_id, "VERIFY_RECORD_ABSENT", "ABSENT", record.evidence_id))
			continue
		violation = policy_violation(record, aliases, cutoff, policy)
		if violation:
			finding_operation, remediation_operation = violation
			finding_state = "ACTIVE" if finding_operation in {"REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"} else "PRESENT"
			findings.append(make_step("FINDING", record.system_id, record.resource_id, finding_operation, finding_state, record.evidence_id))
			remediation.append(make_step("REMEDIATION", record.system_id, record.resource_id, remediation_operation, remediation_state[remediation_operation], ""))
			verification.append(make_step("VERIFICATION", record.system_id, record.resource_id, verify_operation[remediation_operation], remediation_state[remediation_operation], ""))
			violations.add((record.system_id, record.resource_id))
			source_resource = get_field(record, "source_resource_id", "source_resource", "origin_resource_id")
			if source_resource and str(source_resource).startswith("account_") and remediation_operation != "DELETE_RECORD":
				verification.append(make_step("VERIFICATION", "account_service", str(source_resource), "VERIFY_RECORD_ABSENT", "ABSENT", ""))
			continue
		compliant = compliant_verification(record, aliases, cutoff)
		if compliant:
			verification.append(make_step("VERIFICATION", record.system_id, record.resource_id, compliant[0], compliant[1], record.evidence_id))
	if findings:
		absent_profiles = [record for record in records if record.category == "USER_PROFILE" and explicit_absent(record) and (record.system_id, record.resource_id) not in violations]
		if absent_profiles:
			latest_absence = max(absent_profiles, key=lambda record: parse_time(record.captured_at) or datetime.min.replace(tzinfo=timezone.utc))
			verification.append(make_step("VERIFICATION", latest_absence.system_id, latest_absence.resource_id, "VERIFY_RECORD_ABSENT", "ABSENT", ""))
		for record in records:
			if record.category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
				compliant = compliant_verification(record, aliases, cutoff)
				if compliant:
					verification.append(make_step("VERIFICATION", record.system_id, record.resource_id, compliant[0], compliant[1], ""))
		for item in verification:
			item["evidence_id"] = ""
		return "INCOMPLETE", sort_steps(findings + remediation + verification)
	return "COMPLETE", sort_steps(verification)


def build_output(requests: list[dict[str, str]]) -> tuple[list[dict[str, str]], list[str]]:
	identities, audit_rows = identity_index()
	evidence, warnings = load_evidence()
	manifest_times = {row["file_id"]: row.get("captured_at", "") for row in read_csv(DATASET / "evidence_files.csv")}
	policy = load_policy()
	rows: list[dict[str, str]] = []
	for request in sorted(requests, key=lambda row: row["case_id"]):
		status, steps = audit_case(request, identities, audit_rows, evidence, manifest_times, policy)
		rows.append({"case_id": request["case_id"], "deletion_status": status, "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
	return rows, warnings


def validate_rows(rows: list[dict[str, str]], expected_ids: list[str], valid_evidence_ids: set[str]) -> list[str]:
	errors: list[str] = []
	if len(rows) != len(expected_ids):
		errors.append(f"row count {len(rows)} does not match request count {len(expected_ids)}")
	if [row.get("case_id") for row in rows] != sorted(expected_ids):
		errors.append("case IDs are missing, duplicated, or not sorted")
	for row in rows:
		case_id = row.get("case_id", "?")
		if row.get("deletion_status") not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
			errors.append(f"{case_id}: invalid deletion status")
		try:
			steps = json.loads(row.get("steps_json", ""))
		except json.JSONDecodeError:
			errors.append(f"{case_id}: invalid steps_json")
			continue
		if not isinstance(steps, list):
			errors.append(f"{case_id}: steps_json is not an array")
			continue
		if row["deletion_status"] == "NOT_APPLICABLE" and steps:
			errors.append(f"{case_id}: NOT_APPLICABLE steps must be empty")
		for number, item in enumerate(steps, start=1):
			if not isinstance(item, dict) or set(item) != STEP_FIELDS:
				errors.append(f"{case_id}: step {number} fields do not match the schema")
				continue
			if item["step_no"] != number:
				errors.append(f"{case_id}: step numbers are not consecutive")
			if (item["phase"], item["operation"], item["state"]) not in ALLOWED:
				errors.append(f"{case_id}: disallowed phase/operation/state")
			if item["evidence_id"] and item["evidence_id"] not in valid_evidence_ids:
				errors.append(f"{case_id}: evidence reference is unknown")
			if row["deletion_status"] == "COMPLETE" and (item["phase"] != "VERIFICATION" or not item["evidence_id"]):
				errors.append(f"{case_id}: COMPLETE steps require cited verification evidence")
			if row["deletion_status"] == "INCOMPLETE" and item["phase"] == "FINDING" and not item["evidence_id"]:
				errors.append(f"{case_id}: findings require cited evidence")
			if row["deletion_status"] == "INCOMPLETE" and item["phase"] != "FINDING" and item["evidence_id"]:
				errors.append(f"{case_id}: future steps must have blank evidence")
		sort_key = lambda item: (PHASE_ORDER.get(item["phase"], 99), OPERATION_ORDER.get(item["operation"], 99), item["system_id"], item["resource_id"], item["evidence_id"])
		if steps != sorted(steps, key=sort_key):
			errors.append(f"{case_id}: operation ordering is invalid")
	return errors


def write_output(path: Path, rows: list[dict[str, str]]) -> None:
	with path.open("w", encoding="utf-8", newline="") as handle:
		writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS, lineterminator="\n")
		writer.writeheader()
		writer.writerows(rows)


def main() -> int:
	requests = read_csv(DATASET / "deletion_requests.csv")
	rows, warnings = build_output(requests)
	evidence_ids = {row["file_id"] for row in read_csv(DATASET / "evidence_files.csv")}
	evidence_ids.update(row["activity_id"] for row in read_csv(DATASET / "system_activity.csv"))
	evidence_ids.update(row["audit_id"] for row in read_csv(DATASET / "user_audit_log.csv"))
	errors = validate_rows(rows, [row["case_id"] for row in requests], evidence_ids)
	if errors:
		print("Output validation failed:", file=sys.stderr)
		for error in errors[:25]:
			print(f"- {error}", file=sys.stderr)
		return 1
	write_output(OUTPUT, rows)
	counts: dict[str, int] = {}
	for row in rows:
		counts[row["deletion_status"]] = counts.get(row["deletion_status"], 0) + 1
	unverified_complete = sum(row["deletion_status"] == "COMPLETE" and not json.loads(row["steps_json"]) for row in rows)
	print(f"Wrote {len(rows)} rows to {OUTPUT.relative_to(ROOT)}")
	print("Statuses: " + ", ".join(f"{key}={value}" for key, value in sorted(counts.items())))
	print(f"COMPLETE rows without an evidence-backed verification step: {unverified_complete}")
	print(f"Unreadable/missing evidence warnings: {len(warnings)}")
	for warning in warnings:
		print(f"WARNING: {warning}", file=sys.stderr)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
