from __future__ import annotations

import calendar
import gzip
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


SAMPLE_BASE = (
    Path.home()
    / "OneDrive"
    / "Desktop"
    / "\uc5c5\ubb34"
    / "4. \ub85c\uadf8"
    / "2. \uad6c\uc131 \ub85c\uadf8"
    / "\ud558\ub098\ud380\ub4dc\uc11c\ube44\uc2a4_\uad6c\uc131\ub3c4 \ub85c\uadf8"
    / "20260730"
)

DEFAULT_NODE_DIRS = [
    SAMPLE_BASE / "20260730_A400_node1",
    SAMPLE_BASE / "20260730_A400_node2",
]


def text_file(folder: Path, name: str) -> str:
    path = folder / name
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace").strip()


def local_name(tag: str) -> str:
    return tag.split("}", 1)[-1]


def xml_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return []

    rows: list[dict[str, Any]] = []
    for elem in root.iter():
        if not elem.tag.endswith("ROW"):
            continue
        row: dict[str, Any] = {}
        for child in elem:
            key = local_name(child.tag)
            values = [li.text or "" for li in child.iter() if local_name(li.tag) == "li"]
            row[key] = values if values else (child.text or "")
        rows.append(row)
    return rows


def asup_rows(folder: Path, name: str) -> list[dict[str, Any]]:
    path = folder / name
    if not path.exists():
        path = next((item for item in folder.iterdir() if item.is_file() and item.name.lower() == name.lower()), path)
    return xml_rows(path)


def first(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return rows[0] if rows else {}


def clean(value: Any, fallback: str = "-") -> str:
    if isinstance(value, list):
        value = ", ".join(str(v).strip() for v in value if str(v).strip())
    value = str(value or "").strip()
    return value if value else fallback


def as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if value in (None, ""):
        return []
    return [str(value).strip()]


def bytes_human(value: Any) -> str:
    try:
        size = float(value)
    except (TypeError, ValueError):
        return clean(value)
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    return f"{size:.2f} {units[idx]}"


def bytes_human_total(value: int | float | None) -> str:
    if value is None:
        return "-"
    return bytes_human(value)


def bytes_value(value: Any) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = clean(value, "").replace(",", "")
    if not text:
        return None
    try:
        return int(float(text))
    except ValueError:
        pass
    match = re.fullmatch(r"([0-9.]+)\s*([kmgtpe]?i?b?)", text, re.I)
    if not match:
        return None
    units = {
        "": 1,
        "b": 1,
        "k": 1024,
        "kb": 1024,
        "kib": 1024,
        "m": 1024**2,
        "mb": 1024**2,
        "mib": 1024**2,
        "g": 1024**3,
        "gb": 1024**3,
        "gib": 1024**3,
        "t": 1024**4,
        "tb": 1024**4,
        "tib": 1024**4,
        "p": 1024**5,
        "pb": 1024**5,
        "pib": 1024**5,
        "e": 1024**6,
        "eb": 1024**6,
        "eib": 1024**6,
    }
    return int(float(match.group(1)) * units.get(match.group(2).lower(), 1))


def mb_human(value: Any) -> str:
    try:
        return bytes_human(float(value) * 1024 * 1024)
    except (TypeError, ValueError):
        return clean(value)


def snapshot_size(value: Any) -> str:
    text = clean(value)
    if re.fullmatch(r"\d+", text):
        return bytes_human(int(text))
    return text


def unique(rows: list[dict[str, Any]], *keys: str) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for row in rows:
        ident = tuple(clean(row.get(k), "") for k in keys)
        if ident in seen:
            continue
        seen.add(ident)
        out.append(row)
    return out


def rows_for(all_rows: dict[str, list[dict[str, Any]]], names: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name in names:
        rows.extend(all_rows[name])
    return rows


def cifs_auth_type(row: dict[str, Any]) -> str:
    auth_style = first_present(row, ["auth_style", "auth-style", "authentication-style"], "").lower()
    domain = first_present(row, ["domain", "domain-name", "windows-domain", "realm"], "")
    workgroup = first_present(row, ["workgroup", "workgroup-name"], "")

    if auth_style == "workgroup" or workgroup:
        return "Workgroup"
    if auth_style == "domain" or domain:
        return "AD"
    return "-"


def parse_model(sysconfig_a: str) -> str:
    match = re.search(r"Model Name:\s*([^\r\n]+)", sysconfig_a)
    return match.group(1).strip() if match else "-"


EVENT_SEVERITIES = {"alert", "error", "emergency", "emerg"}
EVENT_FILE_RE = re.compile(r"(event|ems|messages)", re.IGNORECASE)
TEXT_EVENT_RE = re.compile(r"\b(alert|error|emergency|emerg)\b", re.IGNORECASE)
ISO_DATETIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")


def event_candidate_files(folder: Path) -> list[Path]:
    files: list[Path] = []
    for path in folder.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        if path.suffix.lower() not in {".xml", ".txt", ".log", ".gz", ""}:
            continue
        if EVENT_FILE_RE.search(name):
            files.append(path)
    return sorted(files, key=lambda item: str(item).lower())


def first_present(row: dict[str, Any], names: list[str], fallback: str = "-") -> str:
    lowered = {key.lower().replace("_", "-"): value for key, value in row.items()}
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return clean(value, fallback)
        value = lowered.get(name.lower().replace("_", "-"))
        if value not in (None, ""):
            return clean(value, fallback)
    return fallback


def normalize_event_severity(value: str) -> str:
    severity = value.strip().lower()
    return "emergency" if severity == "emerg" else severity


def normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is not None:
        return value.astimezone().replace(tzinfo=None)
    return value


def parse_event_datetime(value: Any, reference_year: int | None = None) -> datetime | None:
    text = clean(value, "")
    if not text:
        return None

    iso_match = ISO_DATETIME_RE.search(text)
    if iso_match:
        token = iso_match.group(0).replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", token):
            token = token[:-2] + ":" + token[-2:]
        try:
            return normalize_datetime(datetime.fromisoformat(token))
        except ValueError:
            pass

    for match_text in [text, text[:31].strip(), text[:24].strip()]:
        for fmt in [
            "%a %b %d %Y %H:%M:%S %z",
            "%a %b %d %Y %H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
        ]:
            try:
                return normalize_datetime(datetime.strptime(match_text, fmt))
            except ValueError:
                continue

    if reference_year is not None:
        match = re.search(r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b", text)
        if match:
            try:
                return datetime.strptime(f"{reference_year} {match.group(1)} {match.group(2)} {match.group(3)}", "%Y %b %d %H:%M:%S")
            except ValueError:
                pass
    return None


def one_month_before(value: datetime) -> datetime:
    year = value.year
    month = value.month - 1
    if month == 0:
        year -= 1
        month = 12
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def event_in_window(event_time: datetime | None, generated_at: datetime) -> bool:
    if event_time is None:
        return False
    cutoff = one_month_before(generated_at)
    return cutoff <= event_time <= generated_at + timedelta(days=1)


def read_log_text(path: Path) -> str:
    if path.suffix.lower() == ".gz":
        try:
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
                return handle.read()
        except OSError:
            return ""
    return path.read_text(encoding="utf-8", errors="replace")


def event_message_from_row(row: dict[str, Any], event: str, source: str) -> str:
    message = first_present(
        row,
        [
            "message",
            "description",
            "text",
            "event-text",
            "event-message",
            "message-text",
            "ems-message",
            "log-message",
            "detail",
        ],
        "",
    )
    if message:
        return message

    ignored = {
        "node",
        "node-name",
        "hostname",
        "severity",
        "level",
        "ems-severity",
        "time",
        "date",
        "timestamp",
        "last-time",
        "last_occurred",
        "event",
        "event-name",
        "message-name",
        "name",
        "source",
        "source-name",
        "subsystem",
    }
    details = []
    for key, value in row.items():
        normalized = key.lower().replace("_", "-")
        if normalized in ignored:
            continue
        value_text = clean(value, "")
        if value_text:
            details.append(f"{key}={value_text}")
    if details:
        return "; ".join(details)
    return event if event != "-" else source


def parse_event_logs(folders: list[Path], generated_at: datetime) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    seen = set()
    for folder in folders:
        node = clean(first(asup_rows(folder, "system-info.xml")).get("system-hostname"), folder.name)
        for path in event_candidate_files(folder):
            if path.suffix.lower() == ".xml":
                for row in xml_rows(path):
                    severity = normalize_event_severity(first_present(row, ["severity", "level", "ems-severity"], ""))
                    if severity not in EVENT_SEVERITIES:
                        continue
                    time_text = first_present(row, ["time", "date", "timestamp", "last-time", "last_occurred", "last-occurred"], "-")
                    event_time = parse_event_datetime(time_text, generated_at.year)
                    if not event_in_window(event_time, generated_at):
                        continue
                    event = first_present(row, ["event", "event-name", "message-name", "name"], "-")
                    source = first_present(row, ["source", "source-name", "subsystem"], path.name)
                    item = {
                        "node": first_present(row, ["node", "node-name", "hostname"], node),
                        "severity": severity,
                        "time": time_text,
                        "event": event,
                        "source": source,
                        "message": event_message_from_row(row, event, source),
                    }
                    ident = tuple(item.values())
                    if ident not in seen:
                        seen.add(ident)
                        events.append(item)
                continue

            content = read_log_text(path)
            for line in content.splitlines():
                match = TEXT_EVENT_RE.search(line)
                if not match:
                    continue
                event_time = parse_event_datetime(line, generated_at.year)
                if not event_in_window(event_time, generated_at):
                    continue
                severity = normalize_event_severity(match.group(1))
                item = {
                    "node": node,
                    "severity": severity,
                    "time": event_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "event": path.name,
                    "source": path.name,
                    "message": line.strip(),
                }
                ident = tuple(item.values())
                if ident not in seen:
                    seen.add(ident)
                    events.append(item)
    return sorted(events, key=lambda item: parse_event_datetime(item.get("time")) or datetime.min, reverse=True)[:500]

def split_member_ports(value: Any) -> list[str]:
    members: list[str] = []
    for item in as_list(value):
        for token in re.split(r"[,\s]+", item):
            token = token.strip()
            if token and token not in members:
                members.append(token)
    return members


def build_ifgrp_members(ifgrps: list[dict[str, Any]]) -> dict[tuple[str, str], list[str]]:
    mapping: dict[tuple[str, str], list[str]] = defaultdict(list)
    for row in ifgrps:
        node = first_present(row, ["node", "node-name", "home-node"], "")
        ifgrp = first_present(row, ["ifgrp", "ifgrp-name", "interface-group", "name", "port"], "")
        raw_members: list[str] = []
        for key in ["ports", "port-list", "member-ports", "member_ports", "member-port", "members", "interfaces"]:
            raw_members.extend(split_member_ports(row.get(key)))

        # Some AutoSupport variants emit one ROW per member port. In that case
        # the ifgrp name is usually in ifgrp/name and the physical member is in port.
        direct_port = clean(row.get("port"), "")
        if direct_port and direct_port != ifgrp:
            raw_members.extend(split_member_ports(direct_port))

        if not node or not ifgrp:
            continue
        for member in raw_members:
            if member != ifgrp and member not in mapping[(node, ifgrp)]:
                mapping[(node, ifgrp)].append(member)
    return mapping


def display_port(node: str, port: str, ifgrp_members: dict[tuple[str, str], list[str]]) -> str:
    members = ifgrp_members.get((node, port), [])
    if members:
        return f"{port}({','.join(members)})"

    parents = [
        ifgrp
        for (parent_node, ifgrp), member_ports in sorted(ifgrp_members.items())
        if parent_node == node and port in member_ports
    ]
    if parents:
        return f"{port}({','.join(parents)})"
    return port


def parse_kv_line(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in line.strip().split(","):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def classify_spare(row: dict[str, str]) -> str:
    if row.get("spare") != "1":
        return ""
    root_size = int(row.get("root_spare_size") or "0")
    data_size = int(row.get("data_spare_size") or "0")
    partition_index = row.get("partition_index")
    if root_size > 0 or partition_index == "3":
        return "root spare"
    if data_size > 0 or partition_index in {"1", "2"}:
        return "data spare"
    return "spare"


def parse_spare_disks(folders: list[Path]) -> list[dict[str, Any]]:
    spares: list[dict[str, Any]] = []
    seen = set()
    for folder in folders:
        content = text_file(folder, "raid-info-listdisk.txt")
        node = first(asup_rows(folder, "system-info.xml")).get("system-hostname") or folder.name
        for line in content.splitlines():
            row = parse_kv_line(line)
            kind = classify_spare(row)
            if not kind:
                continue
            ident = (row.get("serialno"), row.get("name"), kind, node)
            if ident in seen:
                continue
            seen.add(ident)
            spares.append(
                {
                    "node": node,
                    "name": row.get("cluster_name") or row.get("name") or "-",
                    "kind": kind,
                    "model": row.get("model") or "-",
                    "size": mb_human(row.get("avl_mb")),
                    "serial": row.get("serialno") or "-",
                    "partition": row.get("partition_index") or "-",
                    "state": row.get("fsm_state") or "-",
                }
            )
    return spares


def policy_owner(row: dict[str, Any]) -> str:
    return first_present(row, ["v", "vserver", "vserver-name", "svm"], "")


def policy_name(row: dict[str, Any]) -> str:
    return first_present(row, ["n", "name", "policy", "policy-name", "snapshot-policy"], "")


def volume_snapshot_policy(volume: dict[str, Any]) -> str:
    return first_present(volume, ["snap_policy", "snap-policy", "snapshot_policy", "snapshot-policy", "policy"], "")


def build_policy_indexes(policies: list[dict[str, Any]]) -> tuple[dict[tuple[str, str], dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    by_owner: dict[tuple[str, str], dict[str, Any]] = {}
    by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for policy in policies:
        owner = policy_owner(policy).lower()
        name = policy_name(policy).lower()
        if not name:
            continue
        by_owner[(owner, name)] = policy
        by_name[name].append(policy)
    return by_owner, by_name


def find_snapshot_policy(
    volume: dict[str, Any],
    policy_by_owner: dict[tuple[str, str], dict[str, Any]],
    policy_by_name: dict[str, list[dict[str, Any]]],
    cluster_name: str,
) -> dict[str, Any] | None:
    name = volume_snapshot_policy(volume).lower()
    if not name:
        return None
    for owner in [clean(volume.get("vs"), ""), cluster_name]:
        policy = policy_by_owner.get((owner.lower(), name))
        if policy:
            return policy
    matches = policy_by_name.get(name, [])
    if not matches:
        return None
    for policy in matches:
        if policy_owner(policy).lower() == cluster_name.lower():
            return policy
    return matches[0]


def policy_schedules(policy: dict[str, Any] | None) -> list[dict[str, str]]:
    if not policy:
        return []
    schedules = as_list(policy.get("s") or policy.get("schedule") or policy.get("schedules"))
    counts = as_list(policy.get("c") or policy.get("count") or policy.get("counts"))
    prefixes = as_list(policy.get("p") or policy.get("prefix") or policy.get("prefixes"))
    labels = as_list(policy.get("l") or policy.get("label") or policy.get("labels"))
    rows = []
    for idx in range(max(len(schedules), len(counts), len(prefixes), len(labels))):
        schedule = schedules[idx] if idx < len(schedules) else "-"
        count = counts[idx] if idx < len(counts) else "-"
        if schedule == "-" and count == "-":
            continue
        rows.append(
            {
                "schedule": schedule,
                "count": count,
                "prefix": prefixes[idx] if idx < len(prefixes) else "-",
                "label": labels[idx] if idx < len(labels) else "-",
            }
        )
    return rows


def endpoint_vserver(path_value: Any) -> str:
    path = clean(path_value, "")
    return path.split(":", 1)[0] if ":" in path else path


def snapmirror_relationship_id(row: dict[str, Any]) -> str:
    return first_present(row, ["relationship-id", "relationship_id", "relationshipId"], "")


def snapmirror_policy_name(row: dict[str, Any]) -> str:
    return first_present(row, ["policy", "policy-name", "snapmirror-policy", "smpolicy_name"], "")


def build_snapmirror_policy_indexes(
    policies: list[dict[str, Any]],
) -> tuple[dict[tuple[str, str], dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    by_owner: dict[tuple[str, str], dict[str, Any]] = {}
    by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for policy in policies:
        owner = first_present(policy, ["vserver", "v", "svm"], "").lower()
        name = first_present(policy, ["smpolicy_name", "policy", "name", "policy-name"], "")
        if not name:
            continue
        by_owner[(owner, name.lower())] = policy
        by_name[name.lower()].append(policy)
    return by_owner, by_name


def find_snapmirror_policy(
    row: dict[str, Any],
    policy_by_owner: dict[tuple[str, str], dict[str, Any]],
    policy_by_name: dict[str, list[dict[str, Any]]],
    cluster_name: str,
) -> dict[str, Any] | None:
    name = snapmirror_policy_name(row).lower()
    if not name:
        return None
    owners = [
        first_present(row, ["vserver", "v", "svm"], ""),
        endpoint_vserver(row.get("destination_path")),
        endpoint_vserver(row.get("source_path")),
        cluster_name,
    ]
    for owner in owners:
        policy = policy_by_owner.get((owner.lower(), name))
        if policy:
            return policy
    matches = policy_by_name.get(name, [])
    if not matches:
        return None
    for policy in matches:
        if first_present(policy, ["vserver", "v", "svm"], "").lower() == cluster_name.lower():
            return policy
    return matches[0]


def snapmirror_policy_schedule(policy: dict[str, Any] | None) -> str:
    if not policy:
        return "-"
    parts = []
    transfer = first_present(policy, ["smpolicy_transfer_schedule_name", "transfer_schedule_name", "transfer-schedule", "schedule"], "")
    common = first_present(policy, ["smpolicy_common_snapshot_schedule", "common-snapshot-schedule"], "")
    rules = [
        value
        for value in as_list(policy.get("smpolicy_schedule") or policy.get("snapmirror-schedule") or policy.get("rule-schedule"))
        if value and value != "-"
    ]
    if transfer:
        parts.append(f"transfer:{transfer}")
    if common:
        parts.append(f"snapshot:{common}")
    if rules:
        parts.append("rules:" + ", ".join(dict.fromkeys(rules)))
    return ", ".join(parts) if parts else "-"


def snapmirror_policy_rules(policy: dict[str, Any] | None) -> str:
    if not policy:
        return "-"
    labels = as_list(policy.get("smpolicy_snapmirrorlabel") or policy.get("snapmirror-label"))
    keeps = as_list(policy.get("smpolicy_keep") or policy.get("keep"))
    schedules = as_list(policy.get("smpolicy_schedule") or policy.get("schedule"))
    prefixes = as_list(policy.get("smpolicy_prefix") or policy.get("prefix"))
    rules = []
    for idx in range(max(len(labels), len(keeps), len(schedules), len(prefixes))):
        label = labels[idx] if idx < len(labels) else "-"
        keep = keeps[idx] if idx < len(keeps) else "-"
        schedule = schedules[idx] if idx < len(schedules) else "-"
        prefix = prefixes[idx] if idx < len(prefixes) else "-"
        rule = f"{label}:{keep}"
        if schedule != "-":
            rule += f"@{schedule}"
        if prefix != "-":
            rule += f"/{prefix}"
        rules.append(rule)
    return ", ".join(rules) if rules else "-"


def snapmirror_key(row: dict[str, Any]) -> tuple[str, str, str]:
    rel_id = snapmirror_relationship_id(row)
    return (rel_id, clean(row.get("source_path"), ""), clean(row.get("destination_path"), ""))


def lun_space_type(row: dict[str, Any]) -> str:
    reserve = first_present(row, ["space_reserve", "space-reserve"], "").lower()
    return "thick" if reserve in {"enabled", "true", "on"} else "thin"


def protocol_label(value: Any) -> str:
    protocol = clean(value, "").lower()
    if protocol == "fcp":
        return "FCP"
    if protocol == "iscsi":
        return "iSCSI"
    return protocol.upper() if protocol else "-"


def lif_netmask(row: dict[str, Any]) -> str:
    address = first_present(row, ["address"], "")
    netmask = first_present(row, [
        "netmask",
        "netmask-length",
        "netmask_length",
        "subnet-mask",
        "subnet_mask",
        "address-netmask",
        "address_netmask",
    ], "")
    if netmask:
        return netmask
    if "/" in address:
        return address.rsplit("/", 1)[-1]
    return "-"


def is_default_route(row: dict[str, Any]) -> bool:
    destination = first_present(row, [
        "destination",
        "dest",
        "route_destination",
        "route-destination",
        "destination-address",
        "destination_address",
        "destination-subnet",
        "destination_subnet",
        "network",
        "prefix",
        "route",
    ], "").lower()
    prefix = first_present(row, ["prefix-length", "prefix_length", "prefixlen"], "").lower()
    return destination in {"default", "0.0.0.0", "0.0.0.0/0", "::", "::/0"} or prefix == "0"


def route_gateway(row: dict[str, Any]) -> str:
    return first_present(row, [
        "gateway",
        "route_gateway",
        "route-gateway",
        "gateway-address",
        "gateway_address",
        "gateway-ip",
        "gateway_ip",
        "next-hop",
        "next_hop",
        "nexthop",
    ])


def build_gateway_lookup(routes: list[dict[str, Any]]) -> dict[tuple[str, str], str]:
    grouped: dict[tuple[str, str], list[str]] = defaultdict(list)
    for route in routes:
        gateway = route_gateway(route)
        if gateway == "-":
            continue
        if not is_default_route(route):
            continue
        vserver = first_present(route, ["vserver", "vserver-name", "route_vserver", "route-vserver", "svm"], "")
        ipspace = first_present(route, ["ipspace", "ipspace-name"], "")
        key = (vserver, ipspace)
        if gateway not in grouped[key]:
            grouped[key].append(gateway)
        if vserver and gateway not in grouped[(vserver, "")]:
            grouped[(vserver, "")].append(gateway)
    return {key: ", ".join(values) for key, values in grouped.items()}


def lif_gateway(row: dict[str, Any], gateways: dict[tuple[str, str], str]) -> str:
    direct = route_gateway(row)
    if direct != "-":
        return direct
    vserver = first_present(row, ["vserver", "vserver-name", "route_vserver", "route-vserver", "svm"], "")
    ipspace = first_present(row, ["ipspace", "ipspace-name"], "")
    return gateways.get((vserver, ipspace)) or gateways.get((vserver, "")) or "-"


def volume_access_type(row: dict[str, Any]) -> str:
    value = first_present(row, [
        "type",
        "volume-type",
        "volume_type",
        "access-type",
        "access_type",
        "vol-type",
        "vol_type",
    ], "")
    text = value.lower()
    if text in {"rw", "read-write", "read_write"}:
        return "RW"
    if text in {"dp", "data-protection", "data_protection"}:
        return "DP"
    return value or "-"


def volume_security_style(row: dict[str, Any]) -> str:
    return first_present(row, [
        "security-style",
        "security_style",
        "security-style-effective",
        "security_style_effective",
        "effective-security-style",
        "effective_security_style",
    ])


def inode_percent(row: dict[str, Any]) -> str:
    direct = first_present(row, [
        "inode-percent-used",
        "inode_percent_used",
        "percent-inodes-used",
        "percent_inodes_used",
        "files-used-percent",
        "files_used_percent",
        "files-percent-used",
        "files_percent_used",
        "percent-files-used",
        "percent_files_used",
    ], "")
    if direct:
        return direct if direct.endswith("%") else f"{direct}%"
    used = first_present(row, ["files-used", "files_used", "inodes-used", "inodes_used"], "")
    total = first_present(row, ["files", "files-total", "files_total", "inodes", "inodes-total", "inodes_total"], "")
    try:
        used_num = float(used.replace(",", ""))
        total_num = float(total.replace(",", ""))
        if total_num > 0:
            return f"{used_num / total_num * 100:.0f}%"
    except ValueError:
        pass
    return "-"


def normalize_enabled(value: Any) -> str:
    text = clean(value, "").lower()
    if text in {"true", "enabled", "enable", "on", "yes", "1"}:
        return "enabled"
    if text in {"false", "disabled", "disable", "off", "no", "0"}:
        return "disabled"
    return clean(value)


def autosupport_summary(rows: list[dict[str, Any]], nodes: list[dict[str, Any]]) -> dict[str, Any]:
    node_statuses = []
    for row in rows:
        node = first_present(row, ["node", "node-name", "node_name", "owner"], "")
        status = normalize_enabled(first_present(row, [
            "is-enabled",
            "is_enabled",
            "enabled",
            "state",
            "status",
            "autosupport-enabled",
            "autosupport_enabled",
        ], ""))
        if status != "-":
            node_statuses.append({"node": node or "-", "status": status})
    if not node_statuses:
        return {"status": "-", "nodes": []}
    statuses = {item["status"] for item in node_statuses}
    if len(statuses) == 1:
        status = next(iter(statuses))
    else:
        status = ", ".join(f"{item['node']}:{item['status']}" for item in node_statuses)
    return {"status": status, "nodes": node_statuses}


def ntp_summary(rows: list[dict[str, Any]], cluster_info: dict[str, Any], node_reports: list[dict[str, Any]]) -> dict[str, str]:
    servers: list[str] = []
    timezone = first_present(cluster_info, ["timezone", "time-zone", "time_zone"], "")
    for node in node_reports:
        if not timezone:
            timezone = first_present(node, ["timezone", "time-zone", "time_zone"], "")
    for row in rows:
        server = first_present(row, [
            "server",
            "server-name",
            "server_name",
            "host",
            "address",
            "ip-address",
            "ip_address",
            "remote",
        ], "")
        if server and server not in servers:
            servers.append(server)
        if not timezone:
            timezone = first_present(row, ["timezone", "time-zone", "time_zone"], "")
    return {"servers": ", ".join(servers) if servers else "-", "timezone": timezone or "-"}


def fcp_rate_label(value: Any) -> str:
    rate = clean(value, "")
    if not rate:
        return "-"
    if re.fullmatch(r"\d+(?:\.\d+)?", rate):
        return f"{rate}G"
    return rate


def sysconfig_sp_info(text: str) -> dict[str, str]:
    match = re.search(
        r"Service Processor\s+Status:\s*([^\r\n]+).*?"
        r"Firmware Version:\s*([^\r\n]+).*?"
        r"IP Address:\s*([^\r\n]+).*?"
        r"Gateway:\s*([^\r\n]+)",
        text,
        re.S,
    )
    if not match:
        return {}
    return {
        "status": match.group(1).strip(),
        "firmware": match.group(2).strip(),
        "ip": match.group(3).strip(),
        "gateway": match.group(4).strip(),
        "source": "sysconfig-a",
    }


def sysconfig_disks(text: str, node: str) -> list[dict[str, Any]]:
    disks = []
    pattern = re.compile(
        r"^\s*(\d+(?:\.\d+)?)\s+:\s+NETAPP\s+(\S+)\s+(\S+)\s+([0-9.]+[KMGTPE]?B)\s+\S+/sect\s+\(([^)]+)\)",
        re.M,
    )
    for match in pattern.finditer(text):
        disks.append(
            {
                "node": node,
                "slot": match.group(1),
                "model": match.group(2),
                "firmware": match.group(3),
                "size": match.group(4),
                "serial": match.group(5),
                "type": "SAS" if "." in match.group(1) else "NVMe",
                "source": "sysconfig-a",
            }
        )
    return disks


def sysconfig_shelves(text: str, disk_count: int) -> list[dict[str, Any]]:
    shelves = []
    pattern = re.compile(r"Shelf\s+(\d+):\s+(\S+)\s+Firmware rev\.\s+([^\r\n]+)")
    for match in pattern.finditer(text):
        module_text = match.group(3).strip()
        modules = [
            {"id": module, "version": version, "latest": "-", "status": "-"}
            for module, version in re.findall(r"([A-Za-z0-9_-]+\s+[A-Z]):\s*([^\s]+)", module_text)
        ]
        shelves.append(
            {
                "name": f"Shelf {match.group(1)}",
                "product": match.group(2),
                "serial": "-",
                "state": "-",
                "status": "-",
                "diskCount": str(disk_count) if disk_count else "-",
                "modules": modules,
                "source": "sysconfig-a",
            }
        )
    return shelves


def sysconfig_port_speed(value: str) -> str:
    text = value.lower()
    if "1000t" in text or "1000base" in text:
        return "1G"
    match = re.search(r"(\d+(?:\.\d+)?)\s*([gm])", text)
    if match:
        return f"{match.group(1)}{match.group(2).upper()}"
    match = re.search(r"\b(2500|1000|100|10)\b", text)
    if not match:
        return "-"
    raw = match.group(1)
    if raw == "2500":
        return "2.5G"
    if raw == "1000":
        return "1G"
    return f"{raw}M"


def sysconfig_network_ports(text: str, node: str) -> list[dict[str, Any]]:
    ports = []
    pattern = re.compile(r"^\s*(e\d+[A-Za-z])\s+MAC Address:\s+(\S+)\s+\(([^)]+)\)", re.M)
    for match in pattern.finditer(text):
        details = match.group(3)
        link = "up" if details.lower().endswith("-up") else "down"
        ports.append(
            {
                "node": node,
                "port": match.group(1),
                "portDisplay": match.group(1),
                "ifgrpMembers": [],
                "role": "-",
                "link": link,
                "speed": sysconfig_port_speed(details),
                "broadcastDomain": "-",
                "ipspace": "-",
                "health": "-",
                "lifCount": 0,
                "usage": "연결됨" if link == "up" else "미사용",
                "mac": match.group(2),
                "source": "sysconfig-a",
            }
        )
    return ports


def sysconfig_fcp_blocks(text: str) -> list[str]:
    return re.findall(
        r"slot\s+\d+:\s+Fibre Channel Target Host Adapter\s+\S+.*?(?=\n\s*slot\s+\d+:|\Z)",
        text,
        re.S,
    )


def sysconfig_fcp_adapters(text: str, node: str) -> list[dict[str, Any]]:
    adapters = []
    for block in sysconfig_fcp_blocks(text):
        name = re.search(r"Fibre Channel Target Host Adapter\s+(\S+)", block)
        status = re.search(r"<([^>]+)>", block)
        firmware = re.search(r"Firmware rev:\s*([^\r\n]+)", block)
        port_id = re.search(r"Host Port Addr:\s*([^\r\n]+)", block)
        connection = re.search(r"Connection:\s*([^\r\n]+)", block)
        switch_port = re.search(r"Switch Port:\s*([^\r\n]+)", block)
        sfp_vendor = re.search(r"SFP Vendor Name:\s*([^\r\n]*)", block)
        sfp_part = re.search(r"SFP Vendor P/N:\s*([^\r\n]*)", block)
        sfp_serial = re.search(r"SFP Serial No\.:\s*([^\r\n]*)", block)

        switch_value = switch_port.group(1).strip() if switch_port else "-"
        switch_name = "-"
        switch_port_value = switch_value
        if ":" in switch_value and switch_value.lower() != "unknown":
            switch_name, switch_port_value = [part.strip() or "-" for part in switch_value.split(":", 1)]

        raw_status = status.group(1).strip() if status else "-"
        adapters.append(
            {
                "node": node,
                "adapter": name.group(1) if name else "-",
                "status": raw_status.lower(),
                "adminStatus": "-",
                "subStatus": raw_status,
                "rate": "-",
                "connection": connection.group(1).strip() if connection else "-",
                "fabricEstablished": "true" if connection and "fabric" in connection.group(1).lower() else "-",
                "fabricName": "-",
                "switchName": switch_name,
                "switchPort": switch_port_value,
                "switchWwn": "-",
                "switchVendor": "-",
                "switchRelease": "-",
                "fabricPortName": "-",
                "portId": port_id.group(1).strip() if port_id else "-",
                "firmware": firmware.group(1).strip() if firmware else "-",
                "sfpVendor": sfp_vendor.group(1).strip() if sfp_vendor else "-",
                "sfpPart": sfp_part.group(1).strip() if sfp_part else "-",
                "sfpSerial": sfp_serial.group(1).strip() if sfp_serial else "-",
                "source": "sysconfig-a",
            }
        )
    return adapters


def sysconfig_ca_slots(text: str, node: str) -> list[dict[str, str]]:
    slots = []
    pattern = re.compile(
        r"^\s*(?:sysconfig:\s*)?slot\s+(\S+)(?:\s+(\S+))?:\s*([^\r\n]*)(.*?)(?=^\s*(?:sysconfig:\s*)?slot\s+\S+(?:\s+\S+)?:|\Z)",
        re.M | re.S,
    )
    for match in pattern.finditer(text):
        detail_lines = [line.strip() for line in match.group(4).splitlines() if line.strip()]
        slots.append(
            {
                "node": node,
                "slot": match.group(1),
                "status": clean(match.group(2)),
                "device": clean(match.group(3)),
                "detail": " | ".join(detail_lines) if detail_lines else "-",
            }
        )
    return slots


def vol_status_fractional_reserves(text: str) -> dict[tuple[str, str], str]:
    reserves: dict[tuple[str, str], str] = {}
    if not text:
        return reserves
    blocks = re.split(r"(?=^Volume name:\s*)", text, flags=re.M)
    for block in blocks:
        name_match = re.search(r"^Volume name:\s*([^\r\n]+)", block, re.M)
        reserve_match = re.search(r"\bfractional_reserve\s*=\s*([0-9]+)", block)
        if not name_match or not reserve_match:
            continue
        volume = name_match.group(1).strip()
        reserve = f"{reserve_match.group(1)}%"
        aggr_match = re.search(r"Containing aggregate:\s*'([^']+)'", block)
        aggregate = aggr_match.group(1).strip() if aggr_match else ""
        reserves[(volume, aggregate)] = reserve
        reserves[(volume, "")] = reserve
    return reserves


def volume_fractional_reserve(row: dict[str, Any], vol_status_reserves: dict[tuple[str, str], str]) -> str:
    direct = first_present(
        row,
        [
            "fractional-reserve",
            "fractional_reserve",
            "fractional-reserve-percent",
            "fractional_reserve_percent",
        ],
        "",
    )
    if direct:
        return direct if direct.endswith("%") else f"{direct}%"
    volume = first_present(row, ["vol", "volume", "name"], "")
    aggregate = first_present(row, ["aggr", "aggregate"], "")
    return vol_status_reserves.get((volume, aggregate)) or vol_status_reserves.get((volume, "")) or "-"


def vserver_allowed_protocols(rows: list[dict[str, Any]]) -> list[str]:
    protocols: set[str] = set()
    for row in rows:
        if first_present(row, ["vserver_type", "vserver-type", "type"], "").lower() not in {"data", ""}:
            continue
        for protocol in as_list(row.get("allowed_protocols") or row.get("allowed-protocols")):
            for token in re.split(r"[,\s]+", protocol):
                label = protocol_label(token)
                if label == "CIFS":
                    label = "CIFS/SMB"
                if label != "-":
                    protocols.add(label)
    return sorted(protocols)


def join_unique(values: list[Any]) -> str:
    output: list[str] = []
    for value in values:
        for item in as_list(value):
            if item and item not in output:
                output.append(item)
    return ", ".join(output) if output else "-"


def lun_key(row: dict[str, Any]) -> str:
    return first_present(row, ["uuid", "vdisk_uuid", "vdisk-uuid"], "")


def lun_map_lun_key(row: dict[str, Any]) -> str:
    return first_present(row, ["vdisk_uuid", "vdisk-uuid"], "")


def fcp_adapter_zoned_row(
    adapter: dict[str, Any],
    zoned_by_port: dict[tuple[str, str, str], dict[str, Any]],
    zoned_by_adapter: dict[tuple[str, str], list[dict[str, Any]]],
) -> dict[str, Any]:
    node = first_present(adapter, ["node"], "")
    port = first_present(adapter, ["adapter"], "")
    port_id = first_present(adapter, ["adapter_host_port_addr", "host-port-addr", "port_id"], "")
    if port_id:
        row = zoned_by_port.get((node, port, port_id))
        if row:
            return row
    needle = f"{node}:{port}".lower()
    for row in zoned_by_adapter.get((node, port), []):
        symbolic = first_present(row, ["symbolic_port_name", "symbolic-port-name"], "").lower()
        port_type = first_present(row, ["port_type", "port-type"], "").lower()
        if needle in symbolic or port_type == "target":
            return row
    return {}


def build_report(folders: list[Path]) -> dict[str, Any]:
    generated_at = datetime.now()
    node_reports = []
    all_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    sysconfig_disk_rows: list[dict[str, Any]] = []
    sysconfig_shelf_rows: list[dict[str, Any]] = []
    sysconfig_network_port_rows: list[dict[str, Any]] = []
    sysconfig_fcp_adapter_rows: list[dict[str, Any]] = []
    sysconfig_slot_rows: list[dict[str, str]] = []
    vol_status_reserves: dict[tuple[str, str], str] = {}

    for folder in folders:
        sysinfo = first(asup_rows(folder, "system-info.xml"))
        cluster_info = first(asup_rows(folder, "CLUSTER-INFO.xml"))
        sysconfig_a = text_file(folder, "SYSCONFIG-A.txt")
        sysconfig_ca = text_file(folder, "SYSCONFIG-AC.txt")
        vol_status_v = text_file(folder, "VOL-STATUS-V.txt")
        sp = first(asup_rows(folder, "sp-network-info.xml"))
        sp_info = first(asup_rows(folder, "sp-info.xml"))
        node_name = clean(sysinfo.get("system-hostname"), folder.name)
        sys_sp = sysconfig_sp_info(sysconfig_a)
        node_sysconfig_disks = sysconfig_disks(sysconfig_a, node_name)
        sysconfig_disk_rows.extend(node_sysconfig_disks)
        sysconfig_shelf_rows.extend(sysconfig_shelves(sysconfig_a, len(node_sysconfig_disks)))
        sysconfig_network_port_rows.extend(sysconfig_network_ports(sysconfig_a, node_name))
        sysconfig_fcp_adapter_rows.extend(sysconfig_fcp_adapters(sysconfig_a, node_name))
        sysconfig_slot_rows.extend(sysconfig_ca_slots(sysconfig_ca, node_name))
        vol_status_reserves.update(vol_status_fractional_reserves(vol_status_v))

        node_reports.append(
            {
                "folder": str(folder),
                "hostname": node_name,
                "serial": clean(sysinfo.get("system-serial-number")),
                "systemId": clean(sysinfo.get("system-id")),
                "model": parse_model(sysconfig_a),
                "ontap": clean(sysinfo.get("ontap-version")),
                "spIp": clean(sp.get("ip-address") or sys_sp.get("ip")),
                "spStatus": clean(sp.get("status") or sp_info.get("status") or sys_sp.get("status")),
                "spGateway": clean(sp.get("gateway-ip-address") or sys_sp.get("gateway")),
                "spFirmware": clean(sp_info.get("firmware-version") or sp_info.get("device-revision") or sys_sp.get("firmware")),
                "spType": clean(sp_info.get("service-processor-type") or sp.get("service-processor-type")),
                "spSource": "xml" if sp or sp_info else clean(sys_sp.get("source")),
                "sysconfigA": sysconfig_a or "sysconfig -a output not found",
                "sysconfigCa": sysconfig_ca or "sysconfig -ca output not found",
                "clusterName": clean(cluster_info.get("cluster-name")),
            }
        )

        for filename in [
            "CLUSTER-INFO.xml",
            "network-interface.xml",
            "network-ports.xml",
            "ifgrps.xml",
            "vs-failover-groups.xml",
            "aggr-info.xml",
            "storage-disk.xml",
            "storage-shelf.xml",
            "volume.xml",
            "snapshot_policy.xml",
            "snapshot.xml",
            "snapshots.xml",
            "snapshot-info.xml",
            "snapshot-list.xml",
            "snapshot-show.xml",
            "volume-snapshot.xml",
            "volume-snapshots.xml",
            "volume-snapshot-show.xml",
            "snapmirror.xml",
            "snapmirror-destination.xml",
            "snapmirror-policy.xml",
            "clusterPeer-itable.xml",
            "clusterPeer-atable.xml",
            "vserver-peer.xml",
            "licenses.xml",
            "nfs_servers_byname.xml",
            "export-policy.xml",
            "export-policies.xml",
            "export_policy.xml",
            "export-rule.xml",
            "export-rules.xml",
            "export_rule.xml",
            "export_rules.xml",
            "export-policy-rule.xml",
            "export-policy-rules.xml",
            "export_rule_table.xml",
            "export_ruleset_ui_table.xml",
            "nfs-export-policy.xml",
            "nfs-export-rules.xml",
            "cifs_server_byname.xml",
            "cifs_share_byname.xml",
            "vserver-info.xml",
            "lun.xml",
            "lun_maps.xml",
            "igroup.xml",
            "fcp.xml",
            "fcp_adapter.xml",
            "fcp_initiator.xml",
            "fcp-topology-switches.xml",
            "fcp-topology-zoned-devices.xml",
            "network-routes.xml",
            "network-cdb-routes.xml",
            "network-route.xml",
            "routes.xml",
            "route.xml",
            "net-routes.xml",
            "ip-routes.xml",
            "route-active.xml",
            "autosupport.xml",
            "autosupport-config.xml",
            "autosupport-status.xml",
            "system-node-autosupport.xml",
            "ntp.xml",
            "ntp-server.xml",
            "ntp-servers.xml",
            "cluster-time-service-ntp-server.xml",
            "clock.xml",
            "timezone.xml",
        ]:
            all_rows[filename].extend(asup_rows(folder, filename))

    lifs = unique(all_rows["network-interface.xml"], "vserver", "vif", "address")
    ports = unique(all_rows["network-ports.xml"], "node", "port")
    ifgrps = unique(all_rows["ifgrps.xml"], "node", "ifgrp", "ifgrp-name", "name", "port")
    ifgrp_members = build_ifgrp_members(ifgrps)
    failover_groups = unique(all_rows["vs-failover-groups.xml"], "vserver", "failover-group", "broadcast-domain")
    aggrs = unique(all_rows["aggr-info.xml"], "node", "name")
    disks = unique(all_rows["storage-disk.xml"], "serial-number")
    shelves = unique(all_rows["storage-shelf.xml"], "shelf_name", "serial_number")
    volumes = unique(all_rows["volume.xml"], "vs", "vol")
    policies = unique(all_rows["snapshot_policy.xml"], "v", "n")
    snapshot_rows = rows_for(
        all_rows,
        [
            "snapshot.xml",
            "snapshots.xml",
            "snapshot-info.xml",
            "snapshot-list.xml",
            "snapshot-show.xml",
            "volume-snapshot.xml",
            "volume-snapshots.xml",
            "volume-snapshot-show.xml",
        ],
    )
    snapmirror_shows = unique(all_rows["snapmirror.xml"], "relationship-id", "relationship_id", "source_path", "destination_path")
    snapmirror_destinations = unique(all_rows["snapmirror-destination.xml"], "relationship_id", "relationship-id", "source_path", "destination_path")
    snapmirror_policies = unique(all_rows["snapmirror-policy.xml"], "vserver", "smpolicy_name")
    cluster_peers = unique(all_rows["clusterPeer-itable.xml"], "cluster_UUID", "cluster")
    cluster_peer_health_rows = unique(all_rows["clusterPeer-atable.xml"], "cluster_uuid")
    vserver_peers = unique(all_rows["vserver-peer.xml"], "local_vserver_name", "peer_vserver_name")
    licenses = unique(all_rows["licenses.xml"], "serialno", "package")
    cifs_servers = unique(rows_for(all_rows, ["cifs_server_byname.xml"]), "vserver", "name", "cifs-server")
    cifs_shares = unique(rows_for(all_rows, ["cifs_share_byname.xml"]), "vserver", "share_name", "share-name", "path")
    nfs_servers = unique(rows_for(all_rows, ["nfs_servers_byname.xml"]), "vserver", "vserver-name", "vs")
    nfs_export_rule_rows = rows_for(
        all_rows,
        [
            "export-policy.xml",
            "export-policies.xml",
            "export_policy.xml",
            "export-rule.xml",
            "export-rules.xml",
            "export_rule.xml",
            "export_rules.xml",
            "export-policy-rule.xml",
            "export-policy-rules.xml",
            "export_rule_table.xml",
            "export_ruleset_ui_table.xml",
            "nfs-export-policy.xml",
            "nfs-export-rules.xml",
        ],
    )
    luns = unique(all_rows["lun.xml"], "vserver", "path", "uuid")
    lun_maps = unique(all_rows["lun_maps.xml"], "vdisk_uuid", "igroup_uuid", "lun_id")
    igroups = unique(all_rows["igroup.xml"], "vserver", "name", "uuid")
    fcp_adapters = unique(all_rows["fcp_adapter.xml"], "node", "adapter")
    fcp_lifs = unique(all_rows["fcp.xml"], "vserver", "lif", "lif-name", "interface-name", "vif", "port-name", "wwpn")
    fcp_initiators = unique(all_rows["fcp_initiator.xml"], "initiator_name", "initiator-name", "wwpn", "name")
    fcp_switches = unique(all_rows["fcp-topology-switches.xml"], "node", "adapter", "wwn")
    fcp_zoned = unique(all_rows["fcp-topology-zoned-devices.xml"], "node", "adapter", "port_id", "switch_port", "port_name")
    vserver_info = unique(all_rows["vserver-info.xml"], "vserver-name", "vserver_type", "id")
    route_rows = unique(
        rows_for(all_rows, ["network-routes.xml", "network-cdb-routes.xml", "network-route.xml", "routes.xml", "route.xml", "net-routes.xml", "ip-routes.xml", "route-active.xml"]),
        "vserver",
        "vserver-name",
        "route_vserver",
        "route-vserver",
        "ipspace",
        "destination",
        "route_destination",
        "route-destination",
        "destination-address",
        "gateway",
        "route_gateway",
        "route-gateway",
        "gateway-address",
        "next-hop",
    )
    autosupport_rows = unique(
        rows_for(all_rows, ["autosupport.xml", "autosupport-config.xml", "autosupport-status.xml", "system-node-autosupport.xml"]),
        "node",
        "node-name",
        "owner",
        "is-enabled",
        "autosupport-enabled",
        "enabled",
    )
    ntp_rows = unique(
        rows_for(all_rows, ["ntp.xml", "ntp-server.xml", "ntp-servers.xml", "cluster-time-service-ntp-server.xml", "clock.xml", "timezone.xml"]),
        "server",
        "server-name",
        "address",
        "ip-address",
        "remote",
        "timezone",
    )

    cluster_name = next((n["clusterName"] for n in node_reports if n["clusterName"] != "-"), "-")
    cluster_info = first(all_rows["CLUSTER-INFO.xml"])
    lif_gateways = build_gateway_lookup(route_rows)
    autosupport = autosupport_summary(autosupport_rows, node_reports)
    ntp = ntp_summary(ntp_rows, cluster_info, node_reports)
    policy_by_owner, policy_by_name = build_policy_indexes(policies)
    sm_policy_by_owner, sm_policy_by_name = build_snapmirror_policy_indexes(snapmirror_policies)
    lif_ports = Counter(clean(l.get("curr_node"), "") + "/" + clean(l.get("curr_port"), "") for l in lifs)
    lif_ports.update(clean(l.get("home_node"), "") + "/" + clean(l.get("home_port"), "") for l in lifs)

    management = {
        "cluster": [
            {"lif": clean(l.get("vif")), "ip": clean(l.get("address")), "port": clean(l.get("curr_port"))}
            for l in lifs
            if l.get("role") == "cluster-mgmt"
        ],
        "nodes": [
            {
                "node": clean(l.get("home_node")),
                "lif": clean(l.get("vif")),
                "ip": clean(l.get("address")),
                "port": clean(l.get("curr_port")),
            }
            for l in lifs
            if l.get("role") == "node-mgmt"
        ],
    }

    protocols = set()
    for lif in lifs:
        for proto in as_list(lif.get("data_protocol")):
            proto_lower = proto.lower()
            if proto_lower == "cifs":
                continue
            if proto_lower and proto_lower != "none" and proto_lower != "fcache":
                protocols.add("CIFS/SMB" if proto.lower() == "cifs" else proto.upper())
    if all_rows["nfs_servers_byname.xml"]:
        protocols.add("NFS")
    if cifs_servers or cifs_shares:
        protocols.add("CIFS/SMB")
    for igroup in igroups:
        protocol = protocol_label(igroup.get("protocol_type"))
        if protocol != "-":
            protocols.add(protocol)
    if all_rows["fcp.xml"] or fcp_adapters:
        protocols.add("FCP")
    if not protocols:
        protocols.update(vserver_allowed_protocols(vserver_info))
    elif vserver_info and not (lifs or cifs_servers or cifs_shares or igroups or all_rows["fcp.xml"] or fcp_adapters):
        protocols.update(vserver_allowed_protocols(vserver_info))

    sysconfig_firmware_by_serial = {
        clean(disk.get("serial"), "").upper(): clean(disk.get("firmware"))
        for disk in sysconfig_disk_rows
        if clean(disk.get("serial"), "")
    }
    disk_summary_counter: dict[tuple[str, str, str, str], int] = Counter()
    for disk in disks:
        firmware = first_present(
            disk,
            ["firmware-version", "firmware-revision", "firmware-rev", "fw-version", "fw-revision", "fw-rev", "firmware"],
            "",
        )
        if not firmware or firmware == "-":
            serial = first_present(disk, ["serial-number", "serial"], "").upper()
            firmware = sysconfig_firmware_by_serial.get(serial, "-")
        disk_summary_counter[
            (
                clean(disk.get("disk-type")),
                clean(disk.get("model")),
                mb_human(disk.get("physical-size-mb")),
                firmware,
            )
        ] += 1
    disk_source = "xml"
    if not disks and sysconfig_disk_rows:
        disk_source = "sysconfig-a"
        for disk in unique(sysconfig_disk_rows, "serial"):
            disk_summary_counter[
                (clean(disk.get("type")), clean(disk.get("model")), clean(disk.get("size")), clean(disk.get("firmware")))
            ] += 1
    disk_total = len(disks) if disks else len(unique(sysconfig_disk_rows, "serial"))
    disk_summary = [
        {"type": k[0], "model": k[1], "size": k[2], "firmware": k[3], "count": v, "source": disk_source}
        for k, v in sorted(disk_summary_counter.items())
    ]

    aggr_report = [
        {
            "node": clean(a.get("node")),
            "name": clean(a.get("name")),
            "diskType": clean(a.get("effective_disk_type") or a.get("storage_type")),
            "diskCount": clean(a.get("diskcount")),
            "usableSize": bytes_human(a.get("size")),
            "available": bytes_human(a.get("available_size")),
            "used": bytes_human(a.get("usedsize")),
            "usedPercent": clean(a.get("percent_used")),
            "maxRaid": clean(a.get("maxraidsize")),
            "raidType": clean(a.get("raidtype")),
            "root": clean(a.get("root")),
        }
        for a in aggrs
    ]

    shelf_report = []
    if shelves:
        for shelf in shelves:
            modules = []
            ids = as_list(shelf.get("module_id"))
            versions = as_list(shelf.get("module_fw_revision"))
            latest = as_list(shelf.get("module_latest_fw_revision"))
            statuses = as_list(shelf.get("module_op_status"))
            for idx, module_id in enumerate(ids):
                modules.append(
                    {
                        "id": module_id,
                        "version": versions[idx] if idx < len(versions) else "-",
                        "latest": latest[idx] if idx < len(latest) else "-",
                        "status": statuses[idx] if idx < len(statuses) else "-",
                    }
                )
            shelf_report.append(
                {
                    "name": clean(shelf.get("shelf_name")),
                    "product": clean(shelf.get("product_id")),
                    "serial": clean(shelf.get("serial_number")),
                    "state": clean(shelf.get("state")),
                    "status": clean(shelf.get("op_status")),
                    "diskCount": clean(shelf.get("disk_count")),
                    "modules": modules,
                    "source": "xml",
                }
            )
    else:
        shelf_report = unique(sysconfig_shelf_rows, "name", "product")

    volume_report = []
    volume_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for volume in volumes:
        policy = find_snapshot_policy(volume, policy_by_owner, policy_by_name, cluster_name)
        schedules = policy_schedules(policy)
        guarantee = clean(volume.get("space_guarantee"), "none").lower()
        size_bytes = bytes_value(volume.get("size"))
        item = {
            "aggregate": clean(volume.get("aggr")),
            "vserver": clean(volume.get("vs")),
            "volume": clean(volume.get("vol")),
            "junctionPath": first_present(volume, ["junction-path", "junction_path", "junction-pathname", "junction_pathname", "j_path", "j-path", "junction"]),
            "size": bytes_human(volume.get("size")),
            "sizeBytes": size_bytes,
            "type": "thick" if guarantee not in {"none", "-"} else "thin",
            "volumeType": volume_access_type(volume),
            "exportPolicy": first_present(volume, ["export-policy", "export_policy", "export-policy-name", "export_policy_name", "policy"]),
            "securityStyle": volume_security_style(volume),
            "inodePercent": inode_percent(volume),
            "usedPercent": clean(volume.get("pcnt_used")),
            "fractionalReserve": volume_fractional_reserve(volume, vol_status_reserves),
            "snapshotPolicy": clean(volume_snapshot_policy(volume)),
            "snapshotSpace": clean(volume.get("pcnt_snap_space")),
            "schedules": schedules,
            "state": clean(volume.get("state")),
        }
        volume_report.append(item)
        volume_by_key[(item["vserver"], item["volume"])] = item

    snapshot_report = []
    snapshot_seen: set[tuple[str, str, str]] = set()
    for snapshot in snapshot_rows:
        vserver = first_present(snapshot, ["vserver", "vserver-name", "svm", "vs", "v"])
        volume = first_present(snapshot, ["volume", "volume-name", "vol", "vo"])
        name = first_present(snapshot, ["snapshot", "snapshot-name", "name", "snap", "s"], "")
        if not name:
            continue
        identity = (vserver, volume, name)
        if identity in snapshot_seen:
            continue
        snapshot_seen.add(identity)
        snapshot_report.append(
            {
                "vserver": vserver,
                "volume": volume,
                "snapshot": name,
                "createTime": first_present(snapshot, ["create-time", "creation-time", "create_time", "creation_time", "access-time", "ct"]),
                "state": first_present(snapshot, ["state", "snapshot-state"]),
                "size": snapshot_size(first_present(snapshot, ["size", "snapshot-size", "total", "cumulative-total", "sz"])),
                "totalPercent": first_present(snapshot, ["percent-total-blocks", "percentage-of-total-blocks", "total-percent"]),
                "usedPercent": first_present(snapshot, ["percent-used-blocks", "percentage-of-used-blocks", "used-percent"]),
                "busy": first_present(snapshot, ["busy", "snapshot-busy"]),
                "owners": first_present(snapshot, ["owners", "owner", "snapshot-owners", "o"]),
                "snapmirrorLabel": first_present(snapshot, ["snapmirror-label", "snapmirror_label", "label"]),
                "comment": first_present(snapshot, ["comment", "snapshot-comment"]),
                "expiryTime": first_present(snapshot, ["expiry-time", "expiry_time", "snaplock-expiry-time", "sl_exp"]),
            }
        )

    igroup_by_uuid = {first_present(row, ["uuid"], ""): row for row in igroups if first_present(row, ["uuid"], "")}
    maps_by_lun_uuid: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for lun_map in lun_maps:
        key = lun_map_lun_key(lun_map)
        if key:
            maps_by_lun_uuid[key].append(lun_map)

    map_count_by_igroup_uuid = Counter(first_present(row, ["igroup_uuid", "igroup-uuid"], "") for row in lun_maps)
    initiator_status_by_name: dict[str, str] = {}
    for row in fcp_initiators:
        initiator = first_present(row, ["initiator_name", "initiator-name", "initiator", "initiators", "wwpn", "name"], "")
        status = normalize_enabled(first_present(row, [
            "logged-in",
            "logged_in",
            "is-logged-in",
            "is_logged_in",
            "is_online",
            "online",
            "status",
            "state",
        ], ""))
        if status == "enabled":
            status = "logged in"
        elif status == "disabled":
            status = "not logged in"
        if initiator and status != "-":
            initiator_status_by_name[initiator] = status

    def init_details(row: dict[str, Any]) -> str:
        details = []
        initiators = (
            row.get("initiator_name")
            or row.get("initiator-name")
            or row.get("initiator")
            or row.get("initiators")
        )
        for initiator in as_list(initiators):
            status = initiator_status_by_name.get(initiator)
            if not status:
                status = first_present(row, [
                    "logged-in",
                    "logged_in",
                    "is-logged-in",
                    "is_logged_in",
                    "initiator-status",
                    "initiator_status",
                ], "")
                if status:
                    status = "logged in" if normalize_enabled(status) == "enabled" else "not logged in" if normalize_enabled(status) == "disabled" else status
            details.append(f"{initiator}: {status or '-'}")
        return ", ".join(details) if details else "-"

    igroup_report = []
    for igroup in igroups:
        uuid = first_present(igroup, ["uuid"], "")
        igroup_report.append(
            {
                "vserver": first_present(igroup, ["vserver", "vserver-name", "svm"]),
                "igroup": first_present(igroup, ["name", "igroup", "initiator-group"]),
                "protocol": protocol_label(igroup.get("protocol_type")),
                "ostype": first_present(igroup, ["os_type", "os-type"]),
                "initiators": join_unique([
                    igroup.get("initiator_name"),
                    igroup.get("initiator-name"),
                    igroup.get("initiator"),
                    igroup.get("initiators"),
                ]),
                "boundPortset": first_present(igroup, ["bound_portset", "bound-portset"]),
                "childIgroups": join_unique([igroup.get("child_igroups"), igroup.get("child-igroups")]),
                "mappedLuns": map_count_by_igroup_uuid.get(uuid, 0),
                "initDetails": init_details(igroup),
                "uuid": uuid or "-",
            }
        )

    lun_report = []
    for lun in luns:
        maps = maps_by_lun_uuid.get(lun_key(lun), [])
        mapped_igroups = [igroup_by_uuid.get(first_present(lun_map, ["igroup_uuid", "igroup-uuid"], ""), {}) for lun_map in maps]
        mapped_igroups = [igroup for igroup in mapped_igroups if igroup]
        protocols_for_lun = [protocol_label(igroup.get("protocol_type")) for igroup in mapped_igroups]
        vserver = first_present(lun, ["vserver", "vserver-name", "svm"])
        volume_name = first_present(lun, ["volume"])
        volume_item = volume_by_key.get((vserver, volume_name), {})
        lun_size_bytes = bytes_value(first_present(lun, ["size", "dev_size", "dev-size"], ""))
        lun_report.append(
            {
                "aggregate": clean(volume_item.get("aggregate")),
                "vserver": vserver,
                "volume": volume_name,
                "lun": first_present(lun, ["name"]),
                "path": first_present(lun, ["path"]),
                "size": bytes_human(first_present(lun, ["size", "dev_size", "dev-size"], "")),
                "sizeBytes": lun_size_bytes,
                "ostype": first_present(lun, ["os_type", "os-type"]),
                "type": lun_space_type(lun),
                "mapped": first_present(lun, ["mapped"], "true" if maps else "false"),
                "igroup": join_unique([igroup.get("name") for igroup in mapped_igroups]),
                "lunId": join_unique([lun_map.get("lun_id") for lun_map in maps]),
                "reportingNodes": join_unique([lun_map.get("reporting_nodes") for lun_map in maps]),
                "initiators": join_unique([igroup.get("initiator_name") for igroup in mapped_igroups]),
                "state": first_present(lun, ["state", "online"]),
                "protocol": join_unique(protocols_for_lun),
            }
        )

    volume_allocated_by_aggr: dict[str, int] = defaultdict(int)
    volume_allocated_seen: dict[str, bool] = defaultdict(bool)
    for volume in volume_report:
        aggregate = clean(volume.get("aggregate"), "")
        size_bytes = volume.get("sizeBytes")
        if aggregate and isinstance(size_bytes, int):
            volume_allocated_by_aggr[aggregate] += size_bytes
            volume_allocated_seen[aggregate] = True

    lun_allocated_by_aggr: dict[str, int] = defaultdict(int)
    lun_allocated_seen: dict[str, bool] = defaultdict(bool)
    for lun in lun_report:
        aggregate = clean(lun.get("aggregate"), "")
        size_bytes = lun.get("sizeBytes")
        if aggregate and isinstance(size_bytes, int):
            lun_allocated_by_aggr[aggregate] += size_bytes
            lun_allocated_seen[aggregate] = True

    for aggregate in aggr_report:
        name = clean(aggregate.get("name"), "")
        aggregate["allocatedVolume"] = bytes_human_total(volume_allocated_by_aggr[name]) if volume_allocated_seen[name] else "-"
        aggregate["allocatedLun"] = bytes_human_total(lun_allocated_by_aggr[name]) if lun_allocated_seen[name] else "-"

    switch_by_adapter = {
        (first_present(row, ["node"], ""), first_present(row, ["adapter"], "")): row
        for row in fcp_switches
    }
    zoned_by_port = {
        (first_present(row, ["node"], ""), first_present(row, ["adapter"], ""), first_present(row, ["port_id", "port-id"], "")): row
        for row in fcp_zoned
    }
    zoned_by_adapter: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in fcp_zoned:
        zoned_by_adapter[(first_present(row, ["node"], ""), first_present(row, ["adapter"], ""))].append(row)
    fcp_lif_wwpn_by_lif: dict[tuple[str, str], str] = {}
    for row in fcp_lifs:
        wwpn = first_present(row, [
            "wwpn",
            "port-name",
            "port_name",
            "port-wwpn",
            "port_wwpn",
            "fc-wwpn",
            "fc_wwpn",
            "lif-wwpn",
            "lif_wwpn",
        ], "")
        if not wwpn:
            continue
        vserver = first_present(row, ["vserver", "vserver-name", "svm"], "")
        lif_name = first_present(row, [
            "lif",
            "lif-name",
            "lif_name",
            "interface-name",
            "interface_name",
            "vif",
            "logical-interface-name",
            "logical_interface_name",
            "name",
        ], "")
        if lif_name:
            fcp_lif_wwpn_by_lif[(vserver, lif_name)] = wwpn
            fcp_lif_wwpn_by_lif.setdefault(("", lif_name), wwpn)

    def lif_address(lif: dict[str, Any]) -> str:
        protocols = [str(value).lower() for value in as_list(lif.get("data_protocol"))]
        if "fcp" not in protocols and clean(lif.get("data_protocol"), "").lower() != "fcp":
            return clean(lif.get("address"))
        vserver = clean(lif.get("vserver"), "")
        lif_name = clean(lif.get("vif"), "")
        return (
            fcp_lif_wwpn_by_lif.get((vserver, lif_name))
            or fcp_lif_wwpn_by_lif.get(("", lif_name))
            or first_present(lif, [
                "wwpn",
                "port-name",
                "port_name",
                "port-wwpn",
                "port_wwpn",
                "fc-wwpn",
                "fc_wwpn",
                "lif-wwpn",
                "lif_wwpn",
            ], "")
            or clean(lif.get("address"))
        )

    fcp_adapter_report = []
    if fcp_adapters:
        for adapter in fcp_adapters:
            node = first_present(adapter, ["node"], "")
            adapter_name = first_present(adapter, ["adapter"], "")
            switch = switch_by_adapter.get((node, adapter_name), {})
            zoned = fcp_adapter_zoned_row(adapter, zoned_by_port, zoned_by_adapter)
            fcp_adapter_report.append(
                {
                    "node": node or "-",
                    "adapter": adapter_name or "-",
                    "status": first_present(adapter, ["adapter_status", "adapter-status"]),
                    "adminStatus": first_present(adapter, ["adapter_admin_status", "adapter-admin-status"]),
                    "subStatus": first_present(adapter, ["adapter_sub_status", "adapter-sub-status"]),
                    "rate": fcp_rate_label(first_present(adapter, ["adapter_data_link_rate", "adapter-data-link-rate"], "")),
                    "connection": first_present(adapter, ["adapter_connection_established", "adapter-connection-established"]),
                    "fabricEstablished": first_present(adapter, ["adapter_fabric_established", "adapter-fabric-established"]),
                    "fabricName": first_present(adapter, ["adapter_fabric_name", "adapter-fabric-name"]),
                    "switchName": first_present(switch, ["logical_name", "logical-name"]),
                    "switchPort": first_present(zoned, ["switch_port", "switch-port"]),
                    "switchWwn": first_present(switch, ["wwn"]),
                    "switchVendor": first_present(switch, ["vendor"]),
                    "switchRelease": first_present(switch, ["release"]),
                    "fabricPortName": first_present(zoned, ["fabric_port_name", "fabric-port-name"]),
                    "portId": first_present(adapter, ["adapter_host_port_addr", "adapter-host-port-addr"]),
                    "firmware": first_present(adapter, ["adapter_firmware_rev", "adapter-firmware-rev"]),
                    "sfpVendor": first_present(adapter, ["sfp_vendor_name", "sfp-vendor-name"]),
                    "sfpPart": first_present(adapter, ["sfp_part_number", "sfp-part-number"]),
                    "sfpSerial": first_present(adapter, ["sfp_serial_number", "sfp-serial-number"]),
                    "source": "xml",
                }
            )
    else:
        fcp_adapter_report = unique(sysconfig_fcp_adapter_rows, "node", "adapter")

    port_report = []
    if ports:
        for port in ports:
            node_name = clean(port.get("node"), "")
            port_name = clean(port.get("port"), "")
            ident = node_name + "/" + port_name
            lif_count = lif_ports.get(ident, 0)
            link = clean(port.get("link"))
            usage = "사용" if lif_count > 0 else ("연결됨" if link == "up" else "미사용")
            port_report.append(
                {
                    "node": node_name or "-",
                    "port": port_name or "-",
                    "portDisplay": display_port(node_name, port_name, ifgrp_members),
                    "ifgrpMembers": ifgrp_members.get((node_name, port_name), []),
                    "role": clean(port.get("role")),
                    "link": link,
                    "speed": clean(port.get("speed-oper") or port.get("speed-actual")),
                    "broadcastDomain": clean(port.get("broadcast-domain")),
                    "ipspace": clean(port.get("ipspace")),
                    "health": clean(port.get("health-status")),
                    "lifCount": lif_count,
                    "usage": usage,
                    "source": "xml",
                }
            )
    else:
        port_report = unique(sysconfig_network_port_rows, "node", "port")

    failover_group_report = [
        {
            "vserver": first_present(row, ["vserver"]),
            "group": first_present(row, ["failover-group", "failover_group"]),
            "broadcastDomain": first_present(row, ["broadcast-domain", "broadcast_domain"]),
            "targets": join_unique([row.get("targets")]),
            "targetCount": len(as_list(row.get("targets"))),
            "source": "xml",
        }
        for row in failover_groups
    ]

    peer_by_vserver = {clean(p.get("local_vserver_name"), ""): p for p in vserver_peers}
    peer_by_vserver.update({clean(p.get("peer_vserver_name"), ""): p for p in vserver_peers})
    peer_by_uuid = {clean(p.get("cluster_UUID"), ""): p for p in cluster_peers}
    cluster_peer_health_by_uuid = {clean(p.get("cluster_uuid"), ""): p for p in cluster_peer_health_rows}

    show_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    show_by_paths: dict[tuple[str, str], dict[str, Any]] = {}
    for sm in snapmirror_shows:
        show_by_key[snapmirror_key(sm)] = sm
        show_by_paths[(clean(sm.get("source_path"), ""), clean(sm.get("destination_path"), ""))] = sm

    snapmirror_report_map: dict[tuple[str, str, str], dict[str, Any]] = {}

    def append_snapmirror(row: dict[str, Any], view: str) -> None:
        source_path = clean(row.get("source_path"), "")
        destination_path = clean(row.get("destination_path"), "")
        key = snapmirror_key(row)
        if not any(key):
            return
        source_vserver = endpoint_vserver(source_path)
        destination_vserver = endpoint_vserver(destination_path)
        local_vserver = first_present(row, ["vserver"], destination_vserver or source_vserver or "-")
        if local_vserver == source_vserver and destination_vserver:
            opposite_vserver = destination_vserver
        elif local_vserver == destination_vserver and source_vserver:
            opposite_vserver = source_vserver
        else:
            opposite_vserver = destination_vserver or source_vserver or "-"
        peer = peer_by_vserver.get(local_vserver) or peer_by_vserver.get(source_vserver) or peer_by_vserver.get(destination_vserver) or {}
        cluster_peer = peer_by_uuid.get(clean(peer.get("peer_cluster_UUID"), ""), {})
        policy = find_snapmirror_policy(row, sm_policy_by_owner, sm_policy_by_name, cluster_name)

        item = snapmirror_report_map.get(key)
        if item is None:
            item = {
                "view": view,
                "sourcePath": source_path or "-",
                "destinationPath": destination_path or "-",
                "type": first_present(row, ["type"], "-"),
                "state": first_present(row, ["state"], "-"),
                "status": first_present(row, ["status", "catalog_status"], "-"),
                "healthy": first_present(row, ["healthy"], "-"),
                "policy": snapmirror_policy_name(row) or "-",
                "policyType": first_present(row, ["policy_type"], first_present(policy or {}, ["smpolicy_type"], "-")),
                "schedule": first_present(row, ["schedule"], "-"),
                "policySchedule": snapmirror_policy_schedule(policy),
                "policyRules": snapmirror_policy_rules(policy),
                "clusterPeer": clean(cluster_peer.get("cluster")),
                "vserver": local_vserver,
                "peerVserver": opposite_vserver,
                "lagTime": first_present(row, ["lag_time"], "-"),
                "lastTransfer": bytes_human(first_present(row, ["last_transfer_size"], "")),
                "relationshipId": snapmirror_relationship_id(row) or "-",
            }
            snapmirror_report_map[key] = item
            return

        views = item["view"].split(", ")
        if view not in views:
            item["view"] = item["view"] + ", " + view
        for field, value in {
            "state": first_present(row, ["state"], ""),
            "status": first_present(row, ["status", "catalog_status"], ""),
            "healthy": first_present(row, ["healthy"], ""),
            "policy": snapmirror_policy_name(row),
            "policyType": first_present(row, ["policy_type"], ""),
            "schedule": first_present(row, ["schedule"], ""),
            "lagTime": first_present(row, ["lag_time"], ""),
        }.items():
            if value and item.get(field, "-") == "-":
                item[field] = value
        if item.get("policySchedule") == "-" and policy:
            item["policySchedule"] = snapmirror_policy_schedule(policy)
            item["policyRules"] = snapmirror_policy_rules(policy)

    for sm in snapmirror_shows:
        append_snapmirror(sm, "snapmirror show")
    for dest in snapmirror_destinations:
        show = show_by_key.get(snapmirror_key(dest)) or show_by_paths.get((clean(dest.get("source_path"), ""), clean(dest.get("destination_path"), "")))
        if show:
            append_snapmirror(show, "snapmirror list-destination")
        else:
            append_snapmirror(dest, "snapmirror list-destination")

    snapmirror_report = sorted(snapmirror_report_map.values(), key=lambda item: (item["sourcePath"], item["destinationPath"]))

    snapmirror_destination_report = [
        {
            "sourcePath": clean(row.get("source_path")),
            "destinationPath": clean(row.get("destination_path")),
            "type": clean(row.get("type")),
            "status": clean(row.get("status")),
            "transferProgress": clean(row.get("transfer_progress")),
            "progressLastUpdated": clean(row.get("progress_last_updated")),
            "relationshipId": snapmirror_relationship_id(row) or "-",
            "sourceVolumeNode": clean(row.get("source_volume_node")),
        }
        for row in snapmirror_destinations
    ]

    snapmirror_policy_report = [
        {
            "vserver": first_present(row, ["vserver", "v", "svm"]),
            "policy": first_present(row, ["smpolicy_name", "policy", "name"]),
            "type": first_present(row, ["smpolicy_type", "type"]),
            "transferSchedule": first_present(row, ["smpolicy_transfer_schedule_name", "transfer-schedule"]),
            "snapshotSchedule": first_present(row, ["smpolicy_common_snapshot_schedule", "common-snapshot-schedule"]),
            "rules": snapmirror_policy_rules(row),
            "totalKeep": first_present(row, ["smpolicy_total_keep", "total-keep"]),
            "totalRules": first_present(row, ["smpolicy_total_rules", "total-rules"]),
            "throttle": first_present(row, ["smpolicy_throttle", "throttle"]),
            "tries": first_present(row, ["smpolicy_tries", "tries"]),
            "comment": first_present(row, ["smpolicy_comment", "comment"]),
        }
        for row in snapmirror_policies
    ]

    cluster_peer_report = []
    for peer in cluster_peers:
        uuid = clean(peer.get("cluster_UUID"), "")
        health = cluster_peer_health_by_uuid.get(uuid, {})
        cluster_peer_report.append(
            {
                "cluster": clean(peer.get("cluster")),
                "peerAddresses": clean(peer.get("peer_addrs")),
                "availability": first_present(health, ["remote_cluster_availability"], "-"),
                "pairsHealthy": first_present(health, ["pairs_healthy"], "-"),
                "pairsUnhealthy": first_present(health, ["pairs_unhealthy"], "-"),
                "authentication": clean(peer.get("authentication_state")),
                "encryption": clean(peer.get("encryption_protocol")),
                "addressFamily": clean(peer.get("address_family")),
                "version": clean(peer.get("cluster_peer_version_cache_full")),
                "uuid": uuid or "-",
            }
        )

    vserver_peer_report = []
    for peer in vserver_peers:
        cluster_peer = peer_by_uuid.get(clean(peer.get("peer_cluster_UUID"), ""), {})
        vserver_peer_report.append(
            {
                "localVserver": clean(peer.get("local_vserver_name")),
                "peerVserver": clean(peer.get("peer_vserver_name")),
                "realPeerVserver": clean(peer.get("real_peer_vserver_name")),
                "clusterPeer": clean(cluster_peer.get("cluster")),
                "state": clean(peer.get("peer_state")),
                "applications": clean(peer.get("peer_applications")),
                "peerClusterUuid": clean(peer.get("peer_cluster_UUID")),
            }
        )

    cifs_server_report = []
    for server in cifs_servers:
        cifs_server_report.append(
            {
                "vserver": first_present(server, ["vserver", "vserver-name", "svm"]),
                "server": first_present(server, ["name", "cifs-server", "server-name", "netbios-name"]),
                "mode": cifs_auth_type(server),
                "authStyle": first_present(server, ["auth_style", "auth-style", "authentication-style"]),
                "domain": first_present(server, ["domain", "domain-name", "windows-domain", "realm"]),
                "domainWorkgroup": first_present(server, ["domain_workgroup", "domain-workgroup"]),
                "workgroup": first_present(server, ["workgroup", "workgroup-name"]),
                "status": first_present(server, ["admin_status", "admin-status", "status", "state"]),
                "defaultSite": first_present(server, ["default_site", "default-site"]),
            }
        )

    cifs_share_report = []
    for share in cifs_shares:
        cifs_share_report.append(
            {
                "vserver": first_present(share, ["vserver", "vserver-name", "svm"]),
                "server": first_present(share, ["cifs_server", "cifs-server", "server-name"]),
                "share": first_present(share, ["share_name", "share-name", "share", "name"]),
                "path": first_present(share, ["path", "share-path", "junction-path"]),
                "properties": first_present(share, ["share_properties", "share-properties", "properties"]),
                "symlink": first_present(share, ["symlink_properties", "symlink-properties"]),
                "offlineCaching": first_present(share, ["offline_caching", "offline-caching"]),
                "vscanProfile": first_present(share, ["VscanFileopProfile", "vscan-fileop-profile"]),
            }
        )

    nfs_server_report = []
    for server in nfs_servers:
        nfs_server_report.append(
            {
                "vserver": first_present(server, ["vserver", "vserver-name", "svm", "vs"]),
                "status": first_present(server, ["admin_status", "admin-status", "status", "state", "nfs-access"]),
                "v3": first_present(server, ["enable_nfsv3", "enable-nfsv3", "nfsv3", "v3"]),
                "v4": first_present(server, ["enable_nfsv4", "enable-nfsv4", "nfsv4", "v4"]),
                "v41": first_present(server, ["enable_nfsv41", "enable-nfsv41", "nfsv41", "v41"]),
                "tcp": first_present(server, ["enable_tcp", "enable-tcp", "tcp"]),
                "udp": first_present(server, ["enable_udp", "enable-udp", "udp"]),
                "defaultWindowsUser": first_present(server, ["default_win_user", "default-win-user", "default-windows-user"]),
            }
        )

    nfs_export_rule_report = []
    nfs_export_rule_seen: set[tuple[str, str, str]] = set()
    for rule in nfs_export_rule_rows:
        vserver = first_present(rule, ["vserver", "vserver-name", "svm", "vs"])
        policy = first_present(rule, ["policy", "policy-name", "policyname", "export-policy", "name"])
        rule_index = first_present(rule, ["rule-index", "rule_index", "ruleindex", "index"])
        protocols = join_unique([rule.get("protocol"), rule.get("protocols"), rule.get("access-protocol")])
        if policy == "-" or rule_index == "-":
            continue
        identity = (vserver, policy, rule_index)
        if identity in nfs_export_rule_seen:
            continue
        nfs_export_rule_seen.add(identity)
        nfs_export_rule_report.append(
            {
                "vserver": vserver,
                "policy": policy,
                "ruleIndex": rule_index,
                "protocols": protocols,
                "clientMatch": first_present(rule, ["client-match", "client_match", "clientmatch", "clients"]),
                "roRule": first_present(rule, ["ro-rule", "ro_rule", "rorule"]),
                "rwRule": first_present(rule, ["rw-rule", "rw_rule", "rwrule"]),
                "superuser": first_present(rule, ["superuser", "super-user-security", "superuser-security"]),
                "anonymousUser": first_present(rule, ["anonymous-user-id", "anonymous_user_id", "anon", "anonymous-user"]),
            }
        )

    node_order = {node["hostname"]: idx for idx, node in enumerate(node_reports)}
    serial_to_node = {node["serial"]: node["hostname"] for node in node_reports if node["serial"] != "-"}
    license_report = []
    for license_row in licenses:
        owner = clean(license_row.get("owner"), "")
        serial = clean(license_row.get("serialno"))
        node = owner if owner in node_order else serial_to_node.get(serial, "Cluster")
        license_report.append(
            {
                "node": node,
                "nodeSerial": serial if node != "Cluster" else "-",
                "serial": serial,
                "package": clean(license_row.get("package")),
                "type": clean(license_row.get("type")),
                "installed": clean(license_row.get("installed_license")),
                "state": clean(license_row.get("state-info")),
                "entitlement": clean(license_row.get("entitlement-info")),
                "group": f"{node} / {serial}" if node != "Cluster" else f"Cluster / {serial}",
                "_order": node_order.get(node, len(node_reports)),
            }
        )
    license_report = sorted(license_report, key=lambda item: (item["_order"], item["node"], item["serial"], item["package"].lower()))
    for item in license_report:
        item.pop("_order", None)

    report = {
        "generatedAt": generated_at.strftime("%Y-%m-%d %H:%M:%S"),
        "sourceFolders": [str(f) for f in folders],
        "cluster": {
            "name": cluster_name,
            "ontap": next((n["ontap"] for n in node_reports if n["ontap"] != "-"), "-"),
            "protocols": sorted(protocols) or ["없음"],
            "management": management,
            "autosupport": autosupport.get("status", "-"),
            "ntp": ntp,
        },
        "autosupport": autosupport,
        "ntp": ntp,
        "nodes": node_reports,
        "shelves": shelf_report,
        "disks": {"total": disk_total, "summary": disk_summary},
        "networkInterfaces": [
            {
                "vserver": clean(l.get("vserver")),
                "lif": clean(l.get("vif")),
                "role": clean(l.get("role")),
                "protocol": clean(l.get("data_protocol")),
                "home": f"{clean(l.get('home_node'))}/{clean(l.get('home_port'))}",
                "current": f"{clean(l.get('curr_node'))}/{clean(l.get('curr_port'))}",
                "homeDisplay": f"{clean(l.get('home_node'))}/{display_port(clean(l.get('home_node'), ''), clean(l.get('home_port'), ''), ifgrp_members)}",
                "currentDisplay": f"{clean(l.get('curr_node'))}/{display_port(clean(l.get('curr_node'), ''), clean(l.get('curr_port'), ''), ifgrp_members)}",
                "failoverGroup": first_present(l, ["failover_group", "failover-group"]),
                "failoverPolicy": first_present(l, ["failover_policy", "failover-policy"]),
                "failoverTargets": join_unique([l.get("failover_targets"), l.get("failover-targets")]),
                "netmask": lif_netmask(l),
                "gateway": lif_gateway(l, lif_gateways),
                "address": lif_address(l),
                "status": clean(l.get("status_oper")),
            }
            for l in lifs
        ],
        "networkPorts": port_report,
        "failoverGroups": failover_group_report,
        "fcpAdapters": fcp_adapter_report,
        "nfsServers": nfs_server_report,
        "nfsExportRules": nfs_export_rule_report,
        "cifsServers": cifs_server_report,
        "cifsShares": cifs_share_report,
        "aggregates": aggr_report,
        "spareDisks": parse_spare_disks(folders),
        "volumes": volume_report,
        "luns": lun_report,
        "igroups": igroup_report,
        "snapshots": snapshot_report,
        "snapmirrors": snapmirror_report,
        "snapmirrorDestinations": snapmirror_destination_report,
        "snapmirrorPolicies": snapmirror_policy_report,
        "clusterPeers": cluster_peer_report,
        "vserverPeers": vserver_peer_report,
        "licenses": license_report,
        "eventLogs": parse_event_logs(folders, generated_at),
        "sysconfigA": [{"node": n["hostname"], "output": n["sysconfigA"]} for n in node_reports],
        "sysconfigCa": [{"node": n["hostname"], "output": n["sysconfigCa"]} for n in node_reports],
        "sysconfigSlots": sysconfig_slot_rows,
    }
    return report


def main() -> None:
    folders = [Path(arg) for arg in sys.argv[1:]] if len(sys.argv) > 1 else DEFAULT_NODE_DIRS
    missing = [str(folder) for folder in folders if not folder.exists()]
    if missing:
        raise SystemExit("Missing AutoSupport folders:\n" + "\n".join(missing))

    report = build_report(folders)
    payload = "window.REPORT_DATA = " + json.dumps(report, ensure_ascii=False, indent=2) + ";\n"
    Path("report-data.js").write_text(payload, encoding="utf-8")
    print(f"Generated report-data.js from {len(folders)} AutoSupport folders")
    print(f"Nodes: {len(report['nodes'])}, volumes: {len(report['volumes'])}, disks: {report['disks']['total']}")


if __name__ == "__main__":
    main()
