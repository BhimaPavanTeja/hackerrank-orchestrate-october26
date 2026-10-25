from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from ai_agent import AIIntentReviewer

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
OUTPUT_FIELDS = ["case_id", "deletion_status", "steps_json"]

SYSTEM_ALIASES = {
    "account": "account_service", "profile": "account_service", "identity": "identity_service",
    "search": "search_service", "index": "search_service", "cache": "cache_service",
    "support": "support_platform", "analytics": "analytics_platform", "telemetry": "analytics_platform",
    "export": "export_service", "marketing": "marketing_service", "email": "notification_service",
    "notification": "notification_service", "security": "security_service", "legal": "legal_service",
    "backup": "backup_service", "restore": "backup_service", "integration": "integration_service",
    "connector": "integration_service", "replica": "account_service", "customer_data": "account_service",
}
CATEGORY_TERMS = {
    "ACCOUNT_TOMBSTONE": ("tombstone",),
    "SECURITY_AUDIT_LOG": ("security_audit", "audit_record", "audit_ledger", "security_audit_log"),
    "LEGAL_HOLD_RECORD": ("legal_hold", "legal_retention", "hold_record"),
    "BACKUP_ARCHIVE": ("backup", "archive", "restore"),
    "SUPPORT_ATTACHMENT": ("support_attachment", "attachment"),
    "SUPPORT_MESSAGE": ("support_message", "support_ticket", "conversation", "ticket"),
    "ANALYTICS_PROFILE": ("analytics_profile", "customer_analytics", "analytics_record"),
    "PRODUCT_TELEMETRY": ("telemetry", "product_event", "event_stream"),
    "USER_EXPORT": ("user_export", "customer_export", "export_job", "export_manifest"),
    "MARKETING_PROFILE": ("marketing_profile", "marketing_contact", "audience_member"),
    "EMAIL_DELIVERY_LOG": ("email_delivery", "delivery_log", "notification_log", "email_log"),
    "SEARCH_INDEX_ENTRY": ("search", "index_document", "index_entry"),
    "CACHE_ENTRY": ("cache", "cached_profile"),
    "SECONDARY_IDENTIFIER": ("secondary_identifier", "identifier_record", "identity_alias"),
    "USER_PROFILE": ("customer_profile", "user_profile", "account_profile", "profile"),
}
RULE_ACTIONS = {
    "USER_PROFILE": "DELETE", "SECONDARY_IDENTIFIER": "DELETE", "SEARCH_INDEX_ENTRY": "DELETE",
    "CACHE_ENTRY": "DELETE", "SUPPORT_MESSAGE": "REDACT", "SUPPORT_ATTACHMENT": "DELETE",
    "ANALYTICS_PROFILE": "ANONYMIZE", "PRODUCT_TELEMETRY": "ANONYMIZE", "USER_EXPORT": "DELETE",
    "MARKETING_PROFILE": "DELETE", "EMAIL_DELIVERY_LOG": "REDACT", "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN", "BACKUP_ARCHIVE": "RETAIN", "ACCOUNT_TOMBSTONE": "REDACT",
}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3, "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3, "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,
}


@dataclass
class Evidence:
    file_id: str
    path: Path
    captured_at: dt.datetime | None


@dataclass
class Observation:
    file_id: str
    timestamp: dt.datetime | None
    system: str
    resource: str
    category: str
    data: dict[str, Any]
    text: str
    source: str


def parse_time(value: Any) -> dt.datetime | None:
    if not value:
        return None
    text = str(value).strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = dt.datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)
    except (ValueError, TypeError):
        return None


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def normalized(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().casefold())


def phone_key(value: Any) -> str:
    return re.sub(r"\D", "", str(value or ""))


def flatten_values(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for child in value.values():
            yield from flatten_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from flatten_values(child)
    elif value is not None and isinstance(value, (str, int, float, bool)):
        yield str(value)


def field_value(record: dict[str, Any], names: Iterable[str]) -> str:
    wanted = {name.casefold() for name in names}
    for key, value in record.items():
        if key.casefold() in wanted and value not in (None, ""):
            return str(value)
    return ""


def system_for(*hints: str) -> str:
    text = " ".join(hints).casefold().replace("-", "_")
    priorities = [
        ("integration", "integration_service"), ("connector", "integration_service"),
        ("backup", "backup_service"), ("restore", "backup_service"), ("security", "security_service"),
        ("legal", "legal_service"), ("support", "support_platform"), ("attachment", "support_platform"),
        ("ticket", "support_platform"), ("analytics", "analytics_platform"),
        ("telemetry", "analytics_platform"), ("marketing", "marketing_service"), ("export", "export_service"),
        ("search", "search_service"), ("index", "search_service"), ("cache", "cache_service"),
        ("email", "notification_service"), ("notification", "notification_service"),
        ("identity", "identity_service"), ("account", "account_service"), ("profile", "account_service"),
        ("customer_data", "account_service"),
    ]
    for token, system in priorities:
        if token in text:
            return system
    return "account_service"


def category_for(*hints: str) -> str:
    text = " ".join(hints).casefold().replace("-", "_")
    for category, terms in CATEGORY_TERMS.items():
        if any(term in text for term in terms):
            return category
    return "USER_PROFILE"


def record_id(record: dict[str, Any], fallback: str = "") -> str:
    value = field_value(record, ("resource_id", "record_id", "resource", "id", "key", "object_id", "document_id"))
    if value:
        return value
    for key, item in record.items():
        if key.casefold().endswith("_id") and item not in (None, ""):
            return str(item)
    return fallback


def dump_text(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def run_optional_text_extractor(path: Path) -> str:
    if path.suffix.casefold() == ".pdf":
        executable = shutil.which("pdftotext")
        if executable:
            try:
                result = subprocess.run([executable, "-layout", str(path), "-"], capture_output=True, text=True, timeout=20, check=False)
                return result.stdout if result.returncode == 0 else ""
            except (OSError, subprocess.TimeoutExpired):
                return ""
    if path.suffix.casefold() in {".png", ".jpg", ".jpeg", ".tif", ".tiff"}:
        executable = shutil.which("tesseract")
        if executable:
            try:
                result = subprocess.run([executable, str(path), "stdout"], capture_output=True, text=True, timeout=20, check=False)
                return result.stdout if result.returncode == 0 else ""
            except (OSError, subprocess.TimeoutExpired):
                return ""
    return ""


def extract_pdf_text(path: Path) -> str:
    raw = path.read_bytes()
    pieces = []
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
        data = match.group(1).strip(b"\r\n")
        object_start = raw.rfind(b" obj", 0, match.start())
        header_start = raw.rfind(b"\n", 0, object_start)
        header = raw[header_start:match.start()]
        filters = re.findall(rb"/([A-Za-z0-9]+Decode)", header)
        try:
            for filter_name in filters:
                if filter_name in {b"ASCII85Decode", b"A85"}:
                    data = base64.a85decode(data.rstrip(b"~>\r\n") + b"~>", adobe=True)
                elif filter_name in {b"FlateDecode", b"Fl"}:
                    data = __import__("zlib").decompress(data)
        except (ValueError, __import__("zlib").error):
            continue
        if b" Tj" not in data and b" TJ" not in data:
            continue
        for text_match in re.finditer(rb"\(((?:\\.|[^\\)])*)\)\s*Tj", data, re.S):
            value = text_match.group(1)
            value = re.sub(rb"\\([nrtbf()\\])", lambda m: {b"\\n": b" ", b"\\r": b" ", b"\\t": b" ", b"\\b": b" ", b"\\f": b" ", b"\\(": b"(", b"\\)": b")", b"\\\\": b"\\"}.get(m.group(0), m.group(0)), value)
            value = re.sub(rb"\\([0-7]{1,3})", lambda m: bytes([int(m.group(1), 8)]), value)
            pieces.append(value.decode("latin1", "replace"))
    return "\n".join(pieces)


class EvidenceCorpus:
    def __init__(self, dataset: Path):
        self.dataset = dataset
        policy_path = dataset / "deletion_rules.csv"
        policy_rows = read_csv(policy_path) if policy_path.is_file() else []
        self.rule_actions = {row["data_category"]: row["required_action"].strip().upper()
                             for row in policy_rows if row.get("data_category") and row.get("required_action")}
        if not self.rule_actions:
            self.rule_actions = dict(RULE_ACTIONS)
        self.evidence: list[Evidence] = []
        self.observations: list[Observation] = []
        self.absence_observations: list[Observation] = []
        self.account_snapshots: list[Evidence] = []
        manifest = read_csv(dataset / "evidence_files.csv")
        for row in manifest:
            path = dataset / row["file_path"]
            if not path.is_file():
                continue
            evidence = Evidence(row["file_id"], path, parse_time(row.get("captured_at")))
            self.evidence.append(evidence)
            self._parse(evidence)

    def _parse(self, evidence: Evidence) -> None:
        suffix = evidence.path.suffix.casefold()
        try:
            if suffix == ".json":
                self._parse_json(evidence)
            elif suffix == ".sql":
                self._parse_sql(evidence)
            elif suffix in {".log", ".txt"}:
                self._parse_lines(evidence, evidence.path.read_text(encoding="utf-8", errors="replace"))
            elif suffix == ".pdf":
                text = extract_pdf_text(evidence.path)
                if text:
                    self._parse_pdf(evidence, text)
            elif suffix in {".png", ".jpg", ".jpeg", ".tif", ".tiff"}:
                text = run_optional_text_extractor(evidence.path)
                if text:
                    self._parse_lines(evidence, text)
        except (OSError, sqlite3.Error, json.JSONDecodeError, UnicodeError):
            return

    def _parse_pdf(self, evidence: Evidence, text: str) -> None:
        category = category_for(evidence.path.name)
        resource_ids = list(dict.fromkeys(re.findall(r"\b(?:account|support|search|analytics|audit_record|backup|export|marketing|cache|data_flow|legal)[_-][A-Za-z0-9]+\b", text, re.IGNORECASE)))
        if not resource_ids:
            return
        emails = list(dict.fromkeys(re.findall(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)))
        phones = list(dict.fromkeys(re.findall(r"(?<!\w)(?:\+?\d[\d ().-]{6,}\d)(?!\w)", text)))
        names = []
        for match in re.finditer(r"(?im)^\s*(?:customer|requester|account holder|name)\s*[:|]\s*([^\n|]{2,80})", text):
            names.append(match.group(1).strip())
        data = {"resource_id": resource_ids[0], "text": text}
        if emails:
            data["email"] = emails[0]
        if phones:
            data["phone"] = phones[0]
        if names:
            data["name"] = names[0]
        system = system_for(category, evidence.path.name)
        self.observations.append(Observation(evidence.file_id, evidence.captured_at, system, resource_ids[0],
                                             category, data, text, "pdf"))

    def _parse_json(self, evidence: Evidence) -> None:
        obj = json.loads(evidence.path.read_text(encoding="utf-8-sig"))
        service_names = {"account_service", "identity_service", "search_service", "cache_service", "support_platform",
                         "analytics_platform", "export_service", "marketing_service", "notification_service",
                         "security_service", "legal_service", "backup_service", "integration_service"}

        def visit(value: Any, system_hint: str = "", category_hint: str = "", timestamp: dt.datetime | None = None):
            if isinstance(value, dict):
                explicit_system = value.get("data_store", value.get("system_id", value.get("source_system")))
                sys_hint = str(explicit_system or system_hint)
                cat_hint = str(value.get("data_category", value.get("category", value.get("collection", category_hint))))
                time = parse_time(value.get("captured_at") or value.get("snapshot_at") or value.get("observed_at")
                                  or value.get("event_time") or value.get("updated_at")) or timestamp
                if record_id(value):
                    data = dict(value)
                    resource = record_id(value)
                    system = sys_hint if sys_hint in service_names else system_for(sys_hint, cat_hint, evidence.path.name)
                    category = category_for(cat_hint)
                    if system == "account_service" and category == "USER_PROFILE":
                        self.account_snapshots.append(Evidence(evidence.file_id, evidence.path, time or evidence.captured_at))
                    observation = Observation(evidence.file_id, time or evidence.captured_at, system, resource,
                                              category, data, dump_text(value), "json")
                    missing = (str(value.get("status_code", "")) == "404" or value.get("profile", object()) is None
                               and str(value.get("status_code", "")) in {"404", "NOT_FOUND"})
                    if missing:
                        observation.source = "absence"
                        self.absence_observations.append(observation)
                    else:
                        self.observations.append(observation)
                for key, child in value.items():
                    if isinstance(child, (dict, list)):
                        next_system = str(key) if key in service_names else sys_hint
                        next_category = cat_hint
                        if key not in {"snapshots", "records", "data", "results", "items", "service_exports"}:
                            next_category = f"{cat_hint} {key}"
                        visit(child, next_system, next_category, time)
            elif isinstance(value, list):
                for child in value:
                    visit(child, system_hint, category_hint, timestamp)
        visit(obj)

    def _parse_sql(self, evidence: Evidence) -> None:
        text = evidence.path.read_text(encoding="utf-8-sig", errors="replace")
        database = sqlite3.connect(":memory:")
        try:
            database.executescript(text)
            names = [row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for table in names:
                table_q = '"' + table.replace('"', '""') + '"'
                cursor = database.execute(f"SELECT * FROM {table_q}")
                columns = [d[0] for d in cursor.description or []]
                for number, values in enumerate(cursor.fetchall()):
                    row = dict(zip(columns, values))
                    data = dict(row)
                    record_json = row.get("record_json")
                    if isinstance(record_json, str):
                        try:
                            nested = json.loads(record_json)
                            if isinstance(nested, dict):
                                data.update(nested)
                        except json.JSONDecodeError:
                            pass
                    resource = str(row.get("resource_id") or record_id(data, f"{table}_{number}"))
                    origin = str(row.get("origin_system", ""))
                    collection = str(row.get("collection_name", ""))
                    system = system_for(origin, collection, table, evidence.path.name)
                    category = category_for(collection, table, origin)
                    if category == "USER_PROFILE" and system == "account_service":
                        self.account_snapshots.append(evidence)
                    self.observations.append(Observation(evidence.file_id, parse_time(row.get("updated_at")) or evidence.captured_at,
                        system, resource, category, data, dump_text(data), "sql"))
        finally:
            database.close()

    def _parse_lines(self, evidence: Evidence, text: str) -> None:
        lines = text.splitlines()
        lookup_by_trace = {}
        for source_line in lines:
            source_fields = {key.casefold(): value.strip('"\' ,') for key, value in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=([^\s,]+)", source_line)}
            subject_value = source_fields.get("lookup_key") or source_fields.get("subject_key") or source_fields.get("subject_ref") or source_fields.get("customer_email")
            if source_fields.get("trace_id") and subject_value:
                lookup_by_trace[source_fields["trace_id"]] = subject_value
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            parsed_time = None
            match_time = re.search(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", line)
            if match_time:
                parsed_time = parse_time(match_time.group(0))
            fields = {key.casefold(): value.strip('"\' ,') for key, value in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=([^\s,]+)", line)}
            json_start = line.find("{")
            if json_start >= 0:
                try:
                    maybe = json.loads(line[json_start:])
                    if isinstance(maybe, dict):
                        fields.update({str(k).casefold(): str(v) for k, v in maybe.items() if v is not None})
                except json.JSONDecodeError:
                    pass
            if fields.get("trace_id") and not any(fields.get(k) for k in ("lookup_key", "subject_key", "subject_ref", "customer_email")) and fields["trace_id"] in lookup_by_trace:
                fields["lookup_key"] = lookup_by_trace[fields["trace_id"]]
            resource = field_value(fields, ("resource_id", "record_id", "resource", "object_id", "backup_id", "export_id"))
            service = field_value(fields, ("service", "system", "source_system", "target_system")) or evidence.path.name
            hint = " ".join([line, evidence.path.name])
            category = category_for(hint)
            if not resource and "|" in line:
                pieces = [part.strip(" -") for part in line.split("|")]
                if len(pieces) >= 5 and parse_time(pieces[0]):
                    parsed_time = parse_time(pieces[0])
                    service, resource, category_name, status = pieces[1:5]
                    category = category_for(category_name, evidence.path.name)
                    detail = pieces[5] if len(pieces) > 5 else ""
                    fields = {"system_id": service, "resource_id": resource, "data_category": category_name,
                              "status": status, "details": detail}
                    if "@" in detail:
                        fields["customer_email"] = detail
                    elif detail.casefold().startswith("user_"):
                        fields["customer_reference"] = detail
                    elif "no direct identifier" in detail.casefold():
                        fields["customer_reference"] = ""
            if not resource or re.search(r"(?:event=[^ ]*started|_started)(?:\s|$)", line, re.IGNORECASE):
                continue
            observation = Observation(evidence.file_id, parsed_time or evidence.captured_at,
                system_for(service, hint), resource, category, fields, line, "text")
            absence = (fields.get("rows") == "0" or fields.get("http_status") == "404"
                       or fields.get("result", "").casefold() in {"miss", "not_found", "not-found", "none"}
                       or fields.get("status", "").casefold() in {"not_found", "not-found", "absent"})
            if absence:
                observation.source = "absence"
                self.absence_observations.append(observation)
            else:
                self.observations.append(observation)


def build_identity_context(request: dict[str, str], identities: list[dict[str, str]], audits: list[dict[str, str]], audit_at: dt.datetime) -> tuple[str, set[str], set[str]]:
    request_email = normalized(request.get("email"))
    eligible_identities = [row for row in identities if not parse_time(row.get("updated_at")) or parse_time(row.get("updated_at")) <= audit_at]
    candidates: set[str] = set()
    for row in identities:
        if normalized(row.get("email")) == request_email:
            candidates.add(row["user_id"])
    eligible_audits = [row for row in audits if not parse_time(row.get("event_time")) or parse_time(row.get("event_time")) <= audit_at]
    for row in eligible_audits:
        if row.get("field_name", "").casefold() == "email" and request_email in {normalized(row.get("old_value")), normalized(row.get("new_value"))}:
            candidates.add(row["user_id"])
    user_id = sorted(candidates)[0] if candidates else ""
    aliases: set[str] = {request_email} if request_email else set()
    phone_aliases: set[str] = set()
    if user_id:
        for row in eligible_identities:
            if row.get("user_id") == user_id:
                for key in ("email", "email_hash", "name", "phone"):
                    if row.get(key):
                        aliases.add(normalized(row[key]))
                        if key == "phone":
                            phone_aliases.add(phone_key(row[key]))
        for row in eligible_audits:
            if row.get("user_id") == user_id:
                value = row.get("old_value", "")
                if value:
                    aliases.add(normalized(value))
                    if row.get("field_name", "").casefold() == "phone":
                        phone_aliases.add(phone_key(value))
                value = row.get("new_value", "")
                if value:
                    aliases.add(normalized(value))
                    if row.get("field_name", "").casefold() == "phone":
                        phone_aliases.add(phone_key(value))
        aliases.add(normalized(user_id))
    aliases.discard("")
    phone_aliases.discard("")
    return user_id, aliases, phone_aliases


def is_authorized(text: str) -> bool:
    value = normalized(text)
    negative = (
        r"\b(?:do not|don't|dont|never|not)\s+(?:delete|erase|remove|close|cancel)",
        r"\bnot\s+(?:requesting|asking for)\s+(?:a\s+)?(?:deletion|erasure|removal)",
        r"\bkeep\s+(?:my|the)\s+account\b", r"\bno\s+(?:deletion|erasure|removal)\b",
        r"\bno borre[sn]?\b", r"\bno elimine[sn]?\b", r"\bne pas supprimer\b",
        r"\bnicht löschen\b", r"\bnao (?:apague|exclua)\b", r"\bnão (?:apague|exclua)\b",
    )
    if any(re.search(pattern, value, re.IGNORECASE) for pattern in negative):
        return False
    explicit_delete = any(term in value for term in (
        "delet", "delete", "eras", "erase", "erasure", "right to be forgotten", "forget me",
        "elimin", "borr", "suprim", "exclu", "apag", "cancell", "suppression", "effac", "l\u00f6schen",
        "entfernen", "verwijder", "cancellare", "annullare", "silin", "silmek", "\u0443\u0434\u0430\u043b",
        "\uc0ad\uc81c", "\uc9c0\uc6cc", "\u524a\u9664", "\u6d88\u53bb", "\u5220\u9664",
        "\u522a\u9664", "\u062d\u0630\u0641", "\u0625\u0632\u0627\u0644\u0629",
        "\u0939\u091f\u093e\u0928\u093e", "\u092e\u093f\u091f\u093e\u0928\u093e",
        "exclus\u00e3o", "exclusao",
    ))
    if explicit_delete:
        return True
    non_deletion = (
        ("marketing" in value and any(word in value for word in ("remove", "unsubscribe", "opt out", "opt-out", "stop"))),
        any(word in value for word in ("access my data", "copy of the information", "send me a copy", "export my data", "download my data")),
        any(word in value for word in ("correct", "correction", "update", "change", "rectify", "fix"))
        and any(word in value for word in ("account", "profile", "email", "address", "surname", "name")),
    )
    if any(non_deletion):
        return False
    guarded_removal = (
        "remove my account", "remove the account", "remove this account", "remove the profile",
        "remove my profile", "remove records", "remove the search result", "remove that search result",
        "remove my personal details", "remove my personal data", "remove my information",
        "remove all personal data", "permanent removal", "removal of my data", "requested removal",
    )
    terms = (
        "close my account", "close this account", "close the account", "account closure", "account to be closed",
        "permanently closed", "account is gone", "profile is gone", "profile gone", "already been removed",
        "already been deleted", "cannot identify me", "request my data to be removed",
        "supprimer le compte", "demande la suppression", "suppression d\u00e9finitive", "compte associ\u00e9",
        "\u524a\u9664", "\uc0ad\uc81c", "\u5220\u9664", "\u522a\u9664",
    )
    return any(term in value for term in guarded_removal + terms)


def is_explicitly_non_deletion(text: str) -> bool:
    value = normalized(text)
    negative = (
        r"\b(?:do not|don't|dont|never|not)\s+(?:delete|erase|remove|close|cancel)",
        r"\bnot\s+(?:requesting|asking for)\s+(?:a\s+)?(?:deletion|erasure|removal)",
        r"\bkeep\s+(?:my|the)\s+account\b", r"\bno\s+(?:deletion|erasure|removal)\b",
        r"\bno borre[sn]?\b", r"\bno elimine[sn]?\b", r"\bne pas supprimer\b",
        r"\bnicht löschen\b", r"\bnao (?:apague|exclua)\b", r"\bnão (?:apague|exclua)\b",
    )
    if any(re.search(pattern, value, re.IGNORECASE) for pattern in negative):
        return True
    return (
        ("marketing" in value and any(word in value for word in ("remove", "unsubscribe", "opt out", "opt-out", "stop")))
        or any(word in value for word in ("access my data", "copy of the information", "send me a copy",
                                           "export my data", "download my data"))
        or (any(word in value for word in ("correct", "correction", "update", "change", "rectify", "fix"))
            and any(word in value for word in ("account", "profile", "email", "address", "surname", "name")))
    )


def observation_matches(observation: Observation, aliases: set[str], phones: set[str]) -> bool:
    values = list(flatten_values(observation.data))
    values.append(observation.text)
    for value in values:
        key = normalized(value)
        if key and key in aliases:
            return True
        digits = phone_key(value)
        if len(digits) >= 7 and digits in phones:
            return True
    return False


def direct_identifiers(record: dict[str, Any], aliases: set[str], phones: set[str]) -> bool:
    identity_fields = {"email", "email_address", "phone", "phone_number", "full_name", "name", "email_hash",
                       "customer_email", "requester_email", "requester_name", "requester_phone"}

    def values(value: Any):
        if isinstance(value, dict):
            for key, child in value.items():
                if key.casefold() in identity_fields and child not in (None, ""):
                    yield child
                yield from values(child)
        elif isinstance(value, list):
            for child in value:
                yield from values(child)

    for value in values(record):
        if normalized(value) in aliases:
            return True
        digits = phone_key(value)
        if len(digits) >= 7 and digits in phones:
            return True
    return False


def classify_observation(observation: Observation) -> tuple[str, str] | None:
    category = observation.category
    data = {str(k).casefold(): v for k, v in observation.data.items()}
    combined = (observation.text + " " + observation.resource).casefold()
    category = category_for(category, combined)
    if "data_flow" in combined or "connector" in combined or observation.system == "integration_service":
        enabled = data.get("enabled")
        state = str(data.get("status", data.get("state", data.get("flow_status", "")))).casefold()
        if enabled is True or str(enabled).casefold() in {"true", "1", "yes"} or state in {"active", "enabled", "running", "delivered"}:
            return "DATA_FLOW", "ACTIVE"
        if enabled is False or str(enabled).casefold() in {"false", "0", "no"} or state in {"disabled", "stopped", "inactive"}:
            return "DATA_FLOW", "DISABLED"
    if category == "BACKUP_ARCHIVE" or observation.system == "backup_service":
        allowed = data.get("restore_allowed", data.get("restore_access", data.get("can_restore", data.get("eligible"))))
        state = str(data.get("status", data.get("state", ""))).casefold()
        deletion_block = str(data.get("deletion_block", "")).casefold()
        if allowed is True or str(allowed).casefold() in {"true", "1", "yes", "allowed"} or state in {"active", "restorable", "allowed"} or deletion_block in {"false", "0", "no"}:
            return "BACKUP_ARCHIVE", "ACTIVE"
        if allowed is False or str(allowed).casefold() in {"false", "0", "no", "blocked"} or state in {"blocked", "disabled", "unavailable"}:
            return "BACKUP_ARCHIVE", "BLOCKED"
    if "tombstone" in combined:
        return "ACCOUNT_TOMBSTONE", "PRESENT"
    return category, "PRESENT"


def record_steps(observation: Observation, evidence_id: str, status: str, operation: str, state: str) -> dict[str, Any]:
    return {"phase": status, "system_id": observation.system, "resource_id": observation.resource,
            "operation": operation, "state": state, "evidence_id": evidence_id}


def add_unique(target: Any, step: dict[str, Any], key_extra: str = "") -> None:
    key = (step["system_id"], step["resource_id"], step["operation"] + key_extra)
    if isinstance(target, list):
        for index, existing in enumerate(target):
            existing_key = (existing["system_id"], existing["resource_id"], existing["operation"] + key_extra)
            if existing_key == key:
                target[index] = step
                return
        target.append(step)
    else:
        target[key] = step


def violation_plan(observations: list[Observation], aliases: set[str], phones: set[str], user_id: str,
                   rule_actions: dict[str, str] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: dict[tuple[str, str, str], dict[str, Any]] = {}
    repairs: dict[tuple[str, str, str], dict[str, Any]] = {}
    for obs in observations:
        classified = classify_observation(obs)
        if not classified:
            continue
        category, resource_state = classified
        action = (rule_actions or RULE_ACTIONS).get(category, RULE_ACTIONS.get(category, "DELETE"))
        identifiers = direct_identifiers(obs.data, aliases, phones)
        # A stable internal reference makes analytics and telemetry records attributable even after direct fields are removed.
        stable_link = any(normalized(v) in {normalized(user_id)} for k, v in obs.data.items()
                          if k.casefold() in {"user_id", "customer_reference", "subject_reference", "customer_id"} and v)
        issue = None
        operation = None
        state = None
        if category == "DATA_FLOW":
            if resource_state == "ACTIVE":
                issue, operation, state = "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "ACTIVE"
            else:
                add_unique(repairs, record_steps(obs, "", "VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"))
        elif category == "BACKUP_ARCHIVE":
            if resource_state == "ACTIVE":
                issue, operation, state = "REPORT_RESTORE_RISK", "BLOCK_RESTORE", "ACTIVE"
            else:
                add_unique(repairs, record_steps(obs, "", "VERIFICATION", "VERIFY_RESTORE_BLOCKED", "BLOCKED"))
        elif action == "DELETE":
            issue, operation, state = "REPORT_REMAINING_RECORD", "DELETE_RECORD", "PRESENT"
        elif action == "REDACT":
            if identifiers:
                issue, operation, state = "REPORT_EXPOSED_PII", "REDACT_RECORD", "PRESENT"
            else:
                verify = record_steps(obs, "", "VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED")
                add_unique(repairs, verify)
        elif action == "ANONYMIZE":
            if identifiers or stable_link:
                issue, operation, state = "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "PRESENT"
            else:
                add_unique(repairs, record_steps(obs, "", "VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"))
        elif action == "RETAIN":
            add_unique(repairs, record_steps(obs, "", "VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"))
        if issue:
            finding = record_steps(obs, obs.file_id, "FINDING", issue, state)
            add_unique(findings, finding)
            repair_state = {"DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
                            "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED"}[operation]
            repair = record_steps(obs, "", "REMEDIATION", operation, repair_state)
            add_unique(repairs, repair)
            verify_operation = {"DELETE_RECORD": "VERIFY_RECORD_ABSENT", "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
                                "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED", "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED",
                                "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED"}[operation]
            verify = record_steps(obs, "", "VERIFICATION", verify_operation, repair_state)
            add_unique(repairs, verify)
            if category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"} and action == "RETAIN":
                add_unique(repairs, record_steps(obs, "", "VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"), ":retained")
    return list(findings.values()), list(repairs.values())


def find_absence_evidence(corpus: EvidenceCorpus, cutoff: dt.datetime) -> str:
    candidates = [e for e in corpus.account_snapshots if e.captured_at and e.captured_at <= cutoff]
    if candidates:
        return max(candidates, key=lambda e: e.captured_at or dt.datetime.min.replace(tzinfo=dt.timezone.utc)).file_id
    return ""


def identify_user_from_evidence(request: dict[str, str], corpus: EvidenceCorpus, audit_at: dt.datetime,
                                user_id: str, aliases: set[str], phones: set[str]) -> tuple[str, set[str], set[str]]:
    if user_id:
        return user_id, aliases, phones
    request_aliases = {normalized(request.get("email"))}
    request_aliases.discard("")
    matches = [o for o in corpus.observations if o.timestamp is None or o.timestamp <= audit_at
               if observation_matches(o, request_aliases, set())]
    discovered: set[str] = set()
    for obs in matches:
        for key, value in obs.data.items():
            if key.casefold() in {"user_id", "customer_reference", "subject_reference", "customer_id"} and value:
                discovered.add(str(value))
    if discovered:
        user_id = sorted(discovered)[0]
        aliases = set(request_aliases) | {normalized(user_id)}
        phones = set()
        for obs in corpus.observations:
            if obs.timestamp and obs.timestamp > audit_at:
                continue
            if any(normalized(value) == normalized(user_id) for key, value in obs.data.items()
                   if key.casefold() in {"user_id", "customer_reference", "subject_reference", "customer_id"} and value):
                for key, value in obs.data.items():
                    if key.casefold() in {"email", "email_address", "customer_email", "requester_email"} and value:
                        aliases.add(normalized(value))
                    if key.casefold() in {"phone", "phone_number", "requester_phone"} and value:
                        phones.add(phone_key(value))
    return user_id, aliases, phones


def effective_observations(observations: list[Observation], absences: list[Observation]) -> list[Observation]:
    grouped: dict[tuple[str, str], list[Observation]] = defaultdict(list)
    for observation in observations + absences:
        grouped[(observation.system, observation.resource)].append(observation)
    effective = []
    for records in grouped.values():
        latest_time = max((record.timestamp or dt.datetime.min.replace(tzinfo=dt.timezone.utc)) for record in records)
        latest = [record for record in records if (record.timestamp or dt.datetime.min.replace(tzinfo=dt.timezone.utc)) == latest_time]
        positive = [record for record in latest if record.source != "absence"]
        if positive:
            effective.extend(positive)
    return effective


def audit_case(request: dict[str, str], identities: list[dict[str, str]], audits: list[dict[str, str]],
               corpus: EvidenceCorpus, authorized_override: bool | None = None) -> tuple[str, list[dict[str, Any]]]:
    cutoff = parse_time(request.get("audit_at")) or dt.datetime.max.replace(tzinfo=dt.timezone.utc)
    authorized = is_authorized(request.get("request_text", "")) if authorized_override is None else authorized_override
    if not authorized:
        return "NOT_APPLICABLE", []
    user_id, aliases, phones = build_identity_context(request, identities, audits, cutoff)
    user_id, aliases, phones = identify_user_from_evidence(request, corpus, cutoff, user_id, aliases, phones)
    observations = [o for o in corpus.observations if (o.timestamp is None or o.timestamp <= cutoff)
                    and observation_matches(o, aliases, phones)]
    absences = [o for o in corpus.absence_observations if (o.timestamp is None or o.timestamp <= cutoff)
                and observation_matches(o, aliases, phones)]
    linked_resources = {(o.system, o.resource) for o in observations + absences}
    if linked_resources:
        observations.extend(o for o in corpus.observations if (o.timestamp is None or o.timestamp <= cutoff)
                            and (o.system, o.resource) in linked_resources and o not in observations)
        absences.extend(o for o in corpus.absence_observations if (o.timestamp is None or o.timestamp <= cutoff)
                        and (o.system, o.resource) in linked_resources and o not in absences)
    observations = effective_observations(observations, absences)
    findings, plans = violation_plan(observations, aliases, phones, user_id, corpus.rule_actions)
    account_checks = [o for o in observations + absences if o.system == "account_service" and o.category == "USER_PROFILE"]
    suffix = user_id.removeprefix("user_") if user_id.startswith("user_") else ""
    fallback_account = f"account_{int(suffix):03d}" if suffix.isdigit() else "account_unknown"
    account_resource = account_checks[0].resource if account_checks else fallback_account
    account_evidence = next((o.file_id for o in sorted(absences, key=lambda o: o.timestamp or cutoff, reverse=True)
                             if o.system == "account_service"), "") or find_absence_evidence(corpus, cutoff)
    if account_evidence:
        add_unique(plans, {"phase": "VERIFICATION", "system_id": "account_service", "resource_id": account_resource,
                           "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
    if not findings:
        evidence = account_evidence
        verifies: dict[tuple[str, str, str], dict[str, Any]] = {}
        if evidence:
            step = {"phase": "VERIFICATION", "system_id": "account_service", "resource_id": account_resource,
                    "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": evidence}
            add_unique(verifies, step)
        for plan in plans:
            if plan["phase"] == "VERIFICATION":
                step = dict(plan)
                step["evidence_id"] = next((o.file_id for o in observations if o.system == step["system_id"] and o.resource == step["resource_id"]), evidence)
                add_unique(verifies, step)
        steps = sorted(verifies.values(), key=step_sort_key)
        return "COMPLETE", number_steps(steps)
    # For incomplete cases, future verification applies to every remediation; retain-only checks remain evidence-backed findings.
    sorted_steps = sorted(findings, key=step_sort_key)
    remediations = sorted((s for s in plans if s["phase"] == "REMEDIATION"), key=step_sort_key)
    verifications = sorted((s for s in plans if s["phase"] == "VERIFICATION"), key=step_sort_key)
    for step in verifications:
        step["evidence_id"] = ""
    steps = sorted_steps + remediations + verifications
    return "INCOMPLETE", number_steps(steps)


def step_sort_key(step: dict[str, Any]) -> tuple[Any, ...]:
    return (PHASE_ORDER.get(step["phase"], 99), OP_ORDER.get(step["operation"], 99), step["system_id"], step["resource_id"], step["evidence_id"])


def number_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
    result = []
    for i, step in enumerate(steps, 1):
        result.append({"step_no": i, **{key: step[key] for key in fields if key != "step_no"}})
    return result


def solve(input_path: Path, output_path: Path, dataset: Path = DATASET,
          ai_reviewer: AIIntentReviewer | None = None) -> None:
    requests = read_csv(input_path)
    identities = read_csv(dataset / "user_identities.csv")
    audits = read_csv(dataset / "user_audit_log.csv")
    corpus = EvidenceCorpus(dataset)
    results = []
    for request in requests:
        request_text = request.get("request_text", "")
        authorized = is_authorized(request_text)
        if ai_reviewer and not authorized and not is_explicitly_non_deletion(request_text):
            cutoff = parse_time(request.get("audit_at")) or dt.datetime.max.replace(tzinfo=dt.timezone.utc)
            _, aliases, _ = build_identity_context(request, identities, audits, cutoff)
            authorized = ai_reviewer.classify_deletion_intent(request_text, aliases)
        status, steps = audit_case(request, identities, audits, corpus, authorized_override=authorized)
        results.append({"case_id": request["case_id"], "deletion_status": status,
                        "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
    results.sort(key=lambda row: row["case_id"])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=OUTPUT_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(results)


def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid AI-assisted deletion audit over participant-facing evidence")
    parser.add_argument("--input", type=Path, default=DATASET / "deletion_requests.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "output.csv")
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--ai-assist", action="store_true",
                        help="Use the configured AI model only for ambiguous deletion-intent requests.")
    parser.add_argument("--ai-provider", choices=("openai", "nvidia"),
                        help="API provider; defaults to AI_PROVIDER or openai.")
    parser.add_argument("--ai-model", help="Model identifier; defaults to the selected provider's model setting.")
    parser.add_argument("--ai-base-url", help="OpenAI-compatible API base URL; defaults to provider configuration.")
    args = parser.parse_args()
    try:
        reviewer = AIIntentReviewer(model=args.ai_model, base_url=args.ai_base_url,
                                    provider=args.ai_provider) if args.ai_assist else None
    except ValueError as error:
        parser.error(str(error))
    solve(args.input.resolve(), args.output.resolve(), args.dataset.resolve(), ai_reviewer=reviewer)
    print(f"Wrote {args.output.resolve()}")


if __name__ == "__main__":
    main()
