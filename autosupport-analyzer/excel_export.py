from __future__ import annotations

import io
import json
import re
import zipfile
from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape

MAX_CELL_TEXT = 32700
ROW_OFFSET = 1
COL_OFFSET = 1
BORDER_TOP = 1
BORDER_RIGHT = 2
BORDER_BOTTOM = 4
BORDER_LEFT = 8
BORDER_ALL = BORDER_TOP | BORDER_RIGHT | BORDER_BOTTOM | BORDER_LEFT
STYLE_KINDS = ["data", "title", "header", "empty", "good", "bad", "strong"]

GOOD_STATUS = {"up", "online", "healthy", "normal", "ok"}
BAD_STATUS = {"down", "offline", "degraded", "unhealthy", "failed", "failure", "error", "emergency", "alert", "link not connected", "no link"}


def safe_text(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        parts = [safe_text(item) for item in value]
        value = ", ".join(item for item in parts if item != "-")
    elif isinstance(value, dict):
        value = json.dumps(value, ensure_ascii=False)
    text = str(value).strip()
    if not text:
        text = "-"
    text = re.sub(r"[ \t]*[\r\n]+[ \t]*", " ", text).replace("\t", " ")
    text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", text)
    return text[:MAX_CELL_TEXT]


DISK_FIRMWARE_RE = re.compile(
    r"^\s*\d+(?:\.\d+)?\s*:\s+NETAPP\s+(\S+)\s+(\S+)\s+"
    r"[0-9.]+[KMGTPE]?B\s+\S+/sect\s+\([^)]+\)",
    re.MULTILINE,
)


def fill_disk_firmware(report: dict[str, Any]) -> None:
    """Fill firmware missing from legacy disk summaries using sysconfig -a."""
    disk_rows = report.get("disks", {}).get("summary", [])
    if not any(not row.get("firmware") or row.get("firmware") == "-" for row in disk_rows):
        return

    outputs = [node.get("sysconfigA", "") for node in report.get("nodes", [])]
    outputs.extend(item.get("output", "") for item in report.get("sysconfigA", []))
    firmware_by_model: dict[str, set[str]] = {}
    for output in outputs:
        for model, firmware in DISK_FIRMWARE_RE.findall(str(output or "")):
            firmware_by_model.setdefault(model, set()).add(firmware)

    for row in disk_rows:
        if row.get("firmware") and row.get("firmware") != "-":
            continue
        versions = firmware_by_model.get(str(row.get("model", "")), set())
        row["firmware"] = ", ".join(sorted(versions)) or "-"


def sheet_name(name: str, used: set[str]) -> str:
    cleaned = re.sub(r"[\\/*?:\[\]]", " ", name).strip()[:31] or "Sheet"
    candidate = cleaned
    index = 2
    while candidate in used:
        suffix = f" {index}"
        candidate = cleaned[: 31 - len(suffix)] + suffix
        index += 1
    used.add(candidate)
    return candidate


def col_name(index: int) -> str:
    result = ""
    while index:
        index, rem = divmod(index - 1, 26)
        result = chr(65 + rem) + result
    return result


def join_schedule(rows: list[dict[str, Any]] | None) -> str:
    if not rows:
        return "-"
    parts = []
    for row in rows:
        schedule = safe_text(row.get("schedule"))
        count = safe_text(row.get("count"))
        if schedule == "-" and count == "-":
            continue
        parts.append(f"{schedule}:{count}")
    return ", ".join(parts) if parts else "-"


def fc_rate(value: Any) -> str:
    text = safe_text(value)
    if text == "-":
        return text
    return f"{text}G" if re.fullmatch(r"\d+(?:\.\d+)?", text) else text


def port_speed(value: Any) -> str:
    text = safe_text(value)
    if text == "-":
        return text
    match = re.fullmatch(r"(\d+(?:\.\d+)?)", text)
    if not match:
        return text
    speed = float(match.group(1))
    if speed >= 1000 and speed.is_integer():
        return f"{int(speed / 1000) if speed % 1000 == 0 else speed / 1000:g}G"
    return text


def natural_key(value: Any) -> list[tuple[int, Any]]:
    return [(0, int(part)) if part.isdigit() else (1, part.lower()) for part in re.split(r"(\d+)", safe_text(value))]


def failover_target_rows(data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in data:
        targets = [target.strip() for target in safe_text(item.get("targets")).split(",") if target.strip() and target.strip() != "-"]
        if not targets:
            rows.append(item)
            continue
        rows.extend({**item, "targets": target} for target in targets)
    return rows


def lun_type_details(row: dict[str, Any]) -> str:
    lun_type = safe_text(row.get("type"))
    reserve = safe_text(row.get("spaceReserve"))
    if reserve == "-":
        reserve = "enabled" if lun_type == "thick" else "disabled" if lun_type == "thin" else "-"
    allocation = safe_text(row.get("spaceAllocation"))
    return f"{lun_type} ({reserve} / {allocation})"


def ontap_short(value: Any) -> str:
    text = safe_text(value)
    match = re.search(r"Release\s+([^:]+)", text)
    return match.group(1).strip() if match else text


def add_title(rows: list[list[Any]], title: str) -> None:
    if rows:
        rows.append([])
    rows.append([title])


def add_kv(rows: list[list[Any]], title: str, items: list[tuple[str, Any]]) -> None:
    add_title(rows, title)
    rows.append(["항목", "값"])
    rows.extend([[label, value] for label, value in items])


def add_table(rows: list[list[Any]], title: str, headers: list[str], data: list[dict[str, Any]], columns: list[tuple[str, str | Any]]) -> None:
    add_title(rows, title)
    rows.append(headers)
    if not data:
        rows.append(["없음"])
        return
    for item in data:
        output = []
        for _, getter in columns:
            output.append(getter(item) if callable(getter) else item.get(getter, "-"))
        rows.append(output)


def build_overview(report: dict[str, Any]) -> list[list[Any]]:
    cluster = report.get("cluster", {})
    nodes = report.get("nodes", [])
    sp_fw = sorted({safe_text(node.get("spFirmware")) for node in nodes if safe_text(node.get("spFirmware")) != "-"})
    rows: list[list[Any]] = []
    add_kv(rows, "개요", [
        ("Cluster", cluster.get("name", "-")),
        ("ONTAP", cluster.get("ontap", "-")),
        ("Protocols", ", ".join(cluster.get("protocols", [])) or "-"),
        ("AutoSupport", report.get("autosupport", {}).get("status") or cluster.get("autosupport", "-")),
        ("NTP IP", report.get("ntp", {}).get("servers") or cluster.get("ntp", {}).get("servers", "-")),
        ("NTP Timezone", report.get("ntp", {}).get("timezone") or cluster.get("ntp", {}).get("timezone", "-")),
        ("Generated At", report.get("generatedAt", "-")),
        ("Nodes", len(nodes)),
        ("Shelves", len(report.get("shelves", []))),
        ("Disks", report.get("disks", {}).get("total", 0)),
        ("Aggregates", len(report.get("aggregates", []))),
        ("Volumes", len(report.get("volumes", []))),
        ("SP Firmware", ", ".join(sp_fw) if sp_fw else "-"),
    ])
    add_table(rows, "컨트롤러 및 관리 IP", ["Hostname", "Serial", "Model", "ONTAP", "SP Type", "SP Firmware", "SP IP", "SP Status", "SP Gateway"], nodes, [
        ("Hostname", "hostname"), ("Serial", "serial"), ("Model", "model"), ("ONTAP", lambda row: ontap_short(row.get("ontap"))),
        ("SP Type", "spType"), ("SP Firmware", "spFirmware"), ("SP IP", "spIp"), ("SP Status", "spStatus"), ("SP Gateway", "spGateway"),
    ])
    mgmt = cluster.get("management", {})
    add_table(rows, "Cluster Mgmt IP", ["LIF", "IP", "Port"], mgmt.get("cluster", []), [("LIF", "lif"), ("IP", "ip"), ("Port", "port")])
    add_table(rows, "Node Mgmt IP", ["Node", "LIF", "IP", "Port"], mgmt.get("nodes", []), [("Node", "node"), ("LIF", "lif"), ("IP", "ip"), ("Port", "port")])
    return rows


def build_upload(report: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    add_kv(rows, "업로드 및 저장", [
        ("Storage Mode", report.get("storageMode", "-")),
        ("Saved At", report.get("savedAt", "-")),
        ("Generated At", report.get("generatedAt", "-")),
        ("Report ID", report.get("id", "-")),
    ])
    add_title(rows, "Source")
    rows.append(["No", "File or Folder"])
    for idx, name in enumerate(report.get("sourceNames", []) or report.get("sourceFolders", []), start=1):
        rows.append([idx, name])
    return rows


def build_hardware(report: dict[str, Any]) -> list[list[Any]]:
    fill_disk_firmware(report)
    rows: list[list[Any]] = []
    add_table(rows, "Shelves", ["Name", "Product", "Serial", "State", "Status", "Disk Count", "Modules"], report.get("shelves", []), [
        ("Name", "name"), ("Product", "product"), ("Serial", "serial"), ("State", "state"), ("Status", "status"), ("Disk Count", "diskCount"),
        ("Modules", lambda row: ", ".join(f"{m.get('id', '-')}: FW {m.get('version', '-')} / {m.get('status', '-')}" for m in row.get("modules", [])) or "-"),
    ])
    add_table(rows, "Disks", ["Disk Type", "Model", "Capacity", "Firmware", "Count"], report.get("disks", {}).get("summary", []), [("Disk Type", "type"), ("Model", "model"), ("Capacity", "size"), ("Firmware", "firmware"), ("Count", "count")])
    add_table(rows, "sysconfig -ca Slot", ["Node", "Slot", "Status", "Device", "Detail"], report.get("sysconfigSlots", []), [
        ("Node", "node"), ("Slot", "slot"), ("Status", "status"), ("Device", "device"), ("Detail", "detail"),
    ])
    return rows


def build_network(report: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    add_table(rows, "Network Interface", ["Vserver", "LIF", "Home Port", "Address", "Netmask", "Gateway", "Status", "Current Port", "Failover Group", "Failover Policy", "Role", "Protocol"], report.get("networkInterfaces", []), [
        ("Vserver", "vserver"), ("LIF", "lif"), ("Home Port", lambda r: r.get("homeDisplay") or r.get("home")), ("Address", "address"), ("Netmask", "netmask"), ("Gateway", "gateway"), ("Status", "status"),
        ("Current Port", lambda r: r.get("currentDisplay") or r.get("current")), ("Failover Group", "failoverGroup"), ("Failover Policy", "failoverPolicy"), ("Role", "role"), ("Protocol", "protocol"),
    ])
    port_headers = ["Node", "Port", "Link", "Speed", "Health", "Broadcast Domain", "Usage", "LIFs"]
    port_columns = [
        ("Node", "node"), ("Port", lambda r: r.get("portDisplay") or r.get("port")), ("Link", "link"), ("Speed", lambda r: port_speed(r.get("speed"))), ("Health", "health"), ("Broadcast Domain", "broadcastDomain"), ("Usage", "usage"), ("LIFs", "lifCount"),
    ]
    ports_by_node: dict[str, list[dict[str, Any]]] = {}
    for port in report.get("networkPorts", []):
        ports_by_node.setdefault(safe_text(port.get("node")), []).append(port)
    if ports_by_node:
        for node in sorted(ports_by_node, key=natural_key):
            node_ports = sorted(ports_by_node[node], key=lambda row: natural_key(row.get("portDisplay") or row.get("port")))
            add_table(rows, f"Network Port · {node}", port_headers, node_ports, port_columns)
    else:
        add_table(rows, "Network Port", port_headers, [], port_columns)
    add_table(rows, "Failover Group", ["Vserver", "Failover Group", "Broadcast Domain", "Targets"], failover_target_rows(report.get("failoverGroups", [])), [
        ("Vserver", "vserver"), ("Failover Group", "group"), ("Broadcast Domain", "broadcastDomain"), ("Targets", "targets"),
    ])
    return rows


def build_cifs(report: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    add_table(rows, "CIFS Server", ["Vserver", "CIFS Server", "Mode", "Auth Style", "Domain", "Domain/Workgroup", "Workgroup", "Status", "Site"], report.get("cifsServers", []), [
        ("Vserver", "vserver"), ("CIFS Server", "server"), ("Mode", "mode"), ("Auth Style", "authStyle"), ("Domain", "domain"), ("Domain/Workgroup", "domainWorkgroup"), ("Workgroup", "workgroup"), ("Status", "status"), ("Site", "defaultSite"),
    ])
    add_table(rows, "CIFS Share", ["Vserver", "CIFS Server", "Share", "Junction Path", "Properties", "Symlink", "Offline Caching"], report.get("cifsShares", []), [
        ("Vserver", "vserver"), ("CIFS Server", "server"), ("Share", "share"), ("Junction Path", "path"), ("Properties", "properties"), ("Symlink", "symlink"), ("Offline Caching", "offlineCaching"),
    ])
    return rows


def build_storage(report: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    add_table(rows, "Aggregate", ["Node", "Aggregate", "Usable Size", "Available", "Used %", "Allocated Volume", "Allocated LUN", "Disk Type", "RAID", "Max RAID", "Disk Count"], report.get("aggregates", []), [
        ("Node", "node"), ("Aggregate", "name"), ("Usable Size", "usableSize"), ("Available", "available"), ("Used %", "usedPercent"), ("Allocated Volume", "allocatedVolume"), ("Allocated LUN", "allocatedLun"), ("Disk Type", "diskType"), ("RAID", "raidType"), ("Max RAID", "maxRaid"), ("Disk Count", "diskCount"),
    ])
    add_table(rows, "Spare Disk", ["Node", "Disk", "Kind", "Size", "Model", "Serial", "State", "Partition"], report.get("spareDisks", []), [
        ("Node", "node"), ("Disk", "name"), ("Kind", "kind"), ("Size", "size"), ("Model", "model"), ("Serial", "serial"), ("State", "state"), ("Partition", "partition"),
    ])
    return rows


def build_volume(report: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    add_table(rows, "Volume", ["Aggregate", "Vserver", "Volume", "Size", "Used %", "State", "Junction Path", "Snapshot Policy", "Schedule / Count", "Snap Space %", "Volume Type", "space-guarantee", "Inode %", "Security Style", "Fractional Reserve"], report.get("volumes", []), [
        ("Aggregate", "aggregate"), ("Vserver", "vserver"), ("Volume", "volume"), ("Size", "size"), ("Used %", "usedPercent"), ("State", "state"), ("Junction Path", "junctionPath"), ("Snapshot Policy", "snapshotPolicy"), ("Schedule / Count", lambda r: join_schedule(r.get("schedules"))), ("Snap Space %", "snapshotSpace"), ("Volume Type", "volumeType"), ("space-guarantee", "type"), ("Inode %", "inodePercent"), ("Security Style", "securityStyle"), ("Fractional Reserve", "fractionalReserve"),
    ])
    return rows


def has_protocol(row: dict[str, Any], protocol: str) -> bool:
    values = re.split(r"[,/\s]+", safe_text(row.get("protocol")).lower())
    return protocol.lower() in values


def nfs_rule_allows_nfs(rule: dict[str, Any]) -> bool:
    values = re.split(r"[,/\s]+", safe_text(rule.get("protocols")).lower())
    return any(value in {"any", "all"} or value.startswith("nfs") for value in values)


def add_protocol_lifs(rows: list[list[Any]], title: str, interfaces: list[dict[str, Any]]) -> None:
    add_table(rows, title, ["Vserver", "LIF", "Home Port", "Address", "Netmask", "Gateway", "Status", "Current Port", "Role", "Protocol"], interfaces, [
        ("Vserver", "vserver"), ("LIF", "lif"), ("Home Port", lambda r: r.get("homeDisplay") or r.get("home")), ("Address", "address"),
        ("Netmask", "netmask"), ("Gateway", "gateway"), ("Status", "status"), ("Current Port", lambda r: r.get("currentDisplay") or r.get("current")),
        ("Role", "role"), ("Protocol", "protocol"),
    ])


def add_protocol_luns(rows: list[list[Any]], luns: list[dict[str, Any]]) -> None:
    add_table(rows, "LUN", ["Aggregate", "Vserver", "Volume", "LUN", "LUN Path", "Size", "OS Type", "Type (Space Reserve / Space Allocation)", "Mapped", "Igroup", "LUN ID", "State", "Protocol", "Reporting Nodes"], luns, [
        ("Aggregate", "aggregate"), ("Vserver", "vserver"), ("Volume", "volume"), ("LUN", "lun"), ("LUN Path", "path"), ("Size", "size"), ("OS Type", "ostype"), ("Type (Space Reserve / Space Allocation)", lun_type_details), ("Mapped", "mapped"), ("Igroup", "igroup"), ("LUN ID", "lunId"), ("State", "state"), ("Protocol", "protocol"), ("Reporting Nodes", "reportingNodes"),
    ])


def add_protocol_igroups(rows: list[list[Any]], igroups: list[dict[str, Any]]) -> None:
    add_table(rows, "Igroup", ["Vserver", "Igroup", "OS Type", "Initiators", "Init Details", "Mapped LUNs", "Protocol", "Portset"], igroups, [
        ("Vserver", "vserver"), ("Igroup", "igroup"), ("OS Type", "ostype"), ("Initiators", "initiators"), ("Init Details", "initDetails"), ("Mapped LUNs", "mappedLuns"), ("Protocol", "protocol"), ("Portset", "boundPortset"),
    ])


def build_nfs(report: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    interfaces = [row for row in report.get("networkInterfaces", []) if has_protocol(row, "nfs")]
    servers = report.get("nfsServers", [])
    export_rules = [row for row in report.get("nfsExportRules", []) if nfs_rule_allows_nfs(row)]
    export_policies = {(safe_text(row.get("vserver")), safe_text(row.get("policy"))) for row in export_rules}
    volumes = [
        row
        for row in report.get("volumes", [])
        if (safe_text(row.get("vserver")), safe_text(row.get("exportPolicy"))) in export_policies
        and safe_text(row.get("junctionPath")) != "-"
    ]
    add_table(rows, "NFS Server", ["Vserver", "Status", "NFSv3", "NFSv4", "NFSv4.1", "TCP", "UDP", "Default Windows User"], servers, [
        ("Vserver", "vserver"), ("Status", "status"), ("NFSv3", "v3"), ("NFSv4", "v4"), ("NFSv4.1", "v41"), ("TCP", "tcp"), ("UDP", "udp"), ("Default Windows User", "defaultWindowsUser"),
    ])
    add_protocol_lifs(rows, "NFS-enabled LIF", interfaces)
    add_table(rows, "NFS Export Rule", ["Vserver", "Policy", "Rule Index", "Protocols", "Client Match", "RO Rule", "RW Rule", "Superuser", "Anonymous User"], export_rules, [
        ("Vserver", "vserver"), ("Policy", "policy"), ("Rule Index", "ruleIndex"), ("Protocols", "protocols"), ("Client Match", "clientMatch"), ("RO Rule", "roRule"), ("RW Rule", "rwRule"), ("Superuser", "superuser"), ("Anonymous User", "anonymousUser"),
    ])
    add_table(rows, "NFS Export Volume", ["Aggregate", "Vserver", "Volume", "Junction Path", "Export Policy", "Volume Type", "Size", "Security Style", "State"], volumes, [
        ("Aggregate", "aggregate"), ("Vserver", "vserver"), ("Volume", "volume"), ("Junction Path", "junctionPath"), ("Export Policy", "exportPolicy"), ("Volume Type", "volumeType"), ("Size", "size"), ("Security Style", "securityStyle"), ("State", "state"),
    ])
    return rows


def build_iscsi(report: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    add_protocol_lifs(rows, "iSCSI LIF", [row for row in report.get("networkInterfaces", []) if has_protocol(row, "iscsi")])
    add_protocol_luns(rows, [row for row in report.get("luns", []) if has_protocol(row, "iscsi")])
    add_protocol_igroups(rows, [row for row in report.get("igroups", []) if has_protocol(row, "iscsi")])
    return rows


def build_fcp(report: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    add_protocol_lifs(rows, "FCP LIF", [row for row in report.get("networkInterfaces", []) if has_protocol(row, "fcp")])
    add_table(rows, "FCP Adapter", ["Node", "Adapter", "Status", "Admin", "Rate", "Switch", "Switch Port", "Switch WWN", "Fabric Port", "Firmware", "SFP"], report.get("fcpAdapters", []), [
        ("Node", "node"), ("Adapter", "adapter"), ("Status", "status"), ("Admin", "adminStatus"), ("Rate", lambda r: fc_rate(r.get("rate"))), ("Switch", "switchName"), ("Switch Port", "switchPort"), ("Switch WWN", "switchWwn"), ("Fabric Port", "fabricPortName"), ("Firmware", "firmware"), ("SFP", lambda r: " / ".join(safe_text(v) for v in [r.get("sfpVendor"), r.get("sfpPart"), r.get("sfpSerial")] if safe_text(v) != "-") or "-"),
    ])
    add_protocol_luns(rows, [row for row in report.get("luns", []) if has_protocol(row, "fcp")])
    add_protocol_igroups(rows, [row for row in report.get("igroups", []) if has_protocol(row, "fcp")])
    return rows


def build_lun_igroup(report: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    add_protocol_luns(rows, report.get("luns", []))
    add_protocol_igroups(rows, report.get("igroups", []))
    return rows


def build_snapshots(report: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    add_table(rows, "Snapshot List", ["Vserver", "Volume", "Snapshot", "Create Time", "Size"], report.get("snapshots", []), [
        ("Vserver", "vserver"), ("Volume", "volume"), ("Snapshot", "snapshot"), ("Create Time", "createTime"), ("Size", "size"),
    ])
    return rows


def build_replication(report: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    add_table(rows, "SnapMirror Relationship", ["Source Path", "Destination Path", "Type", "State", "Status", "Healthy", "Cluster Peer", "Vserver", "Peer Vserver", "Policy", "Schedule", "Policy Rules", "Policy Schedule", "Lag", "Last Transfer"], report.get("snapmirrors", []), [
        ("Source Path", "sourcePath"), ("Destination Path", "destinationPath"), ("Type", "type"), ("State", "state"), ("Status", "status"), ("Healthy", "healthy"), ("Cluster Peer", "clusterPeer"), ("Vserver", "vserver"), ("Peer Vserver", "peerVserver"), ("Policy", "policy"), ("Schedule", "schedule"), ("Policy Rules", "policyRules"), ("Policy Schedule", "policySchedule"), ("Lag", "lagTime"), ("Last Transfer", "lastTransfer"),
    ])
    add_table(rows, "SnapMirror List Destination", ["Source Path", "Destination Path", "Type", "Status", "Progress", "Updated", "Source Node", "Relationship ID"], report.get("snapmirrorDestinations", []), [("Source Path", "sourcePath"), ("Destination Path", "destinationPath"), ("Type", "type"), ("Status", "status"), ("Progress", "transferProgress"), ("Updated", "progressLastUpdated"), ("Source Node", "sourceVolumeNode"), ("Relationship ID", "relationshipId")])
    add_table(rows, "Cluster Peer", ["Peer Cluster", "Availability", "Address", "Address Family", "Healthy", "Unhealthy"], report.get("clusterPeers", []), [
        ("Peer Cluster", "cluster"), ("Availability", "availability"), ("Address", "peerAddresses"), ("Address Family", "addressFamily"), ("Healthy", "pairsHealthy"), ("Unhealthy", "pairsUnhealthy"),
    ])
    add_table(rows, "Vserver Peer", ["Vserver", "Peer Vserver", "Cluster Peer", "State", "Application"], report.get("vserverPeers", []), [
        ("Vserver", "localVserver"), ("Peer Vserver", "peerVserver"), ("Cluster Peer", "clusterPeer"), ("State", "state"), ("Application", "applications"),
    ])
    return rows


def build_events(report: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    add_table(rows, "Event Log", ["Node", "Severity", "Time", "Event", "Message"], report.get("eventLogs", []), [("Node", "node"), ("Severity", "severity"), ("Time", "time"), ("Event", "event"), ("Message", "message")])
    return rows


def build_licenses(report: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    add_table(rows, "License", ["Node", "Serial", "Package", "Type", "Installed"], report.get("licenses", []), [("Node", "node"), ("Serial", "serial"), ("Package", "package"), ("Type", "type"), ("Installed", "installed")])
    return rows


def build_raw(report: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = [["Section", "Node", "Line", "Output"]]
    found = False
    for section, key in [("sysconfig -a", "sysconfigA"), ("sysconfig -ca", "sysconfigCa")]:
        for item in report.get(key, []):
            node = item.get("node", "-")
            output = str(item.get("output", "") or "")
            lines = output.splitlines() or [output]
            for idx, line in enumerate(lines, start=1):
                rows.append([section, node, idx, line])
                found = True
    if not found:
        rows.append(["없음"])
    return rows


def workbook_sheets(report: dict[str, Any]) -> list[tuple[str, list[list[Any]]]]:
    return [
        ("개요", build_overview(report)),
        ("하드웨어", build_hardware(report)),
        ("네트워크", build_network(report)),
        ("CIFS", build_cifs(report)),
        ("NFS", build_nfs(report)),
        ("iSCSI", build_iscsi(report)),
        ("FCP", build_fcp(report)),
        ("스토리지", build_storage(report)),
        ("볼륨", build_volume(report)),
        ("LUN 및 Igroup", build_lun_igroup(report)),
        ("스냅샷", build_snapshots(report)),
        ("복제", build_replication(report)),
        ("라이센스", build_licenses(report)),
    ]


def row_kind(row: list[Any], previous_was_title: bool) -> str:
    if not row:
        return "blank"
    if len(row) == 1 and row[0] == "없음":
        return "empty"
    if len(row) == 1:
        return "title"
    if previous_was_title:
        return "header"
    return "data"


def row_kinds(rows: list[list[Any]]) -> list[str]:
    kinds: list[str] = []
    previous_was_title = False
    for row in rows:
        kind = row_kind(row, previous_was_title)
        kinds.append(kind)
        previous_was_title = kind == "title"
    return kinds


def status_kind(value: Any) -> str:
    text = re.sub(r"[\s_/:-]+", " ", safe_text(value).lower()).strip()
    if text in GOOD_STATUS:
        return "good"
    if text in BAD_STATUS or any(token in text for token in ["degraded", "offline", "unhealthy", "link not connected"]):
        return "bad"
    return "data"


def emphasis_columns(table_title: str | None, headers: list[Any]) -> set[int]:
    if table_title == "Network Interface":
        return {idx for idx, header in enumerate(headers) if safe_text(header) in {"Home Port", "Current Port"}}
    if table_title and table_title.startswith("Network Port"):
        return {idx for idx, header in enumerate(headers) if safe_text(header) == "Port"}
    return set()


def style_id(kind: str, border_mask: int) -> int:
    return STYLE_KINDS.index(kind) * 16 + border_mask


def block_end_index(kinds: list[str], header_idx: int) -> int:
    idx = header_idx + 1
    while idx < len(kinds) and kinds[idx] not in {"blank", "title"}:
        idx += 1
    return idx


def column_spans(block_rows: list[list[Any]]) -> list[int]:
    max_cols = max((len(row) for row in block_rows if row), default=1)
    lengths = [0] * max_cols
    for row in block_rows:
        for idx, value in enumerate(row):
            lengths[idx] = max(lengths[idx], len(safe_text(value)))

    spans = []
    for length in lengths:
        if length > 58:
            span = 4
        elif length > 36:
            span = 3
        elif length > 18:
            span = 2
        else:
            span = 1
        spans.append(span)

    max_physical_cols = 48
    while sum(spans) > max_physical_cols and any(span > 1 for span in spans):
        widest = max((span, idx, lengths[idx]) for idx, span in enumerate(spans) if span > 1)
        spans[widest[1]] -= 1
    return spans or [1]


def next_non_blank_kind(kinds: list[str], idx: int) -> str | None:
    for kind in kinds[idx + 1 :]:
        if kind != "blank":
            return kind
    return None


def cell_xml(col_idx: int, row_idx: int, value: Any, kind: str, mask: int, blank: bool = False) -> str:
    ref = f"{col_name(col_idx)}{row_idx}"
    text = " " if blank else safe_text(value)
    escaped = escape(text, {'"': '&quot;'})
    return f'<c r="{ref}" s="{style_id(kind, mask)}" t="inlineStr"><is><t xml:space="preserve">{escaped}</t></is></c>'


def desired_width(value: Any, kind: str) -> float:
    length = len(safe_text(value))
    if kind == "title":
        return min(max(length + 2, 14), 28)
    if kind == "header":
        return min(max(length + 2, 8), 18)
    return min(max(length + 2, 8), 22)


def worksheet_column_widths(rows: list[list[Any]], kinds: list[str]) -> list[float]:
    max_cols = max((len(row) for row in rows if row), default=1)
    widths = [1.55] + [8.0] * max(1 + COL_OFFSET + max_cols - 1, 1)
    if len(widths) > 1:
        widths[1] = 18.0

    current_spans: list[int] = []
    for idx, (row, kind) in enumerate(zip(rows, kinds)):
        if kind == "blank":
            current_spans = []
            continue
        if kind == "title":
            col_idx = 1 + COL_OFFSET
            widths[col_idx - 1] = max(widths[col_idx - 1], desired_width(row[0], kind))
            current_spans = []
            continue
        if kind == "header":
            end = block_end_index(kinds, idx)
            current_spans = column_spans(rows[idx:end])
        elif not current_spans:
            current_spans = [1] * len(row)
        logical_col = 1 + COL_OFFSET
        for idx, value in enumerate(row):
            span = current_spans[idx] if idx < len(current_spans) else 1
            col_idx = logical_col
            while len(widths) < col_idx:
                widths.append(8.0)
            widths[col_idx - 1] = max(widths[col_idx - 1], desired_width(value, kind))
            logical_col += span
    return widths


def estimated_row_height(row: list[Any], kind: str, spans: list[int], col_widths: list[float]) -> int:
    if kind == "title":
        return 22
    return 18


def append_table_cells(
    cells: list[str],
    merges: list[str],
    row_idx: int,
    row: list[Any],
    kind: str,
    spans: list[int],
    is_last: bool,
    emphasis_cols: set[int],
) -> int:
    start_col = 1 + COL_OFFSET
    table_width = sum(spans)
    end_col = start_col + table_width - 1

    if kind == "empty":
        for physical_col in range(start_col, end_col + 1):
            mask = 0
            if physical_col == start_col:
                mask |= BORDER_LEFT
            if physical_col == end_col:
                mask |= BORDER_RIGHT
            if is_last:
                mask |= BORDER_BOTTOM
            cells.append(cell_xml(physical_col, row_idx, "없음", "empty", mask, blank=physical_col != start_col))
        return end_col

    logical_col = start_col
    for idx, span in enumerate(spans):
        value = row[idx] if idx < len(row) else ""
        if kind == "header":
            cell_kind = "header"
        else:
            cell_kind = status_kind(value)
            if idx in emphasis_cols and cell_kind == "data":
                cell_kind = "strong"
        for offset in range(span):
            physical_col = logical_col + offset
            mask = 0
            if kind == "header":
                mask |= BORDER_TOP
            if is_last:
                mask |= BORDER_BOTTOM
            if physical_col == start_col:
                mask |= BORDER_LEFT
            if physical_col == end_col:
                mask |= BORDER_RIGHT
            cells.append(cell_xml(physical_col, row_idx, value, cell_kind, mask, blank=offset > 0))
        if span > 1:
            merges.append(f'<mergeCell ref="{col_name(logical_col)}{row_idx}:{col_name(logical_col + span - 1)}{row_idx}"/>')
        logical_col += span
    return end_col


def worksheet_xml(rows: list[list[Any]]) -> str:
    kinds = row_kinds(rows)
    col_widths = worksheet_column_widths(rows, kinds)
    xml_rows = []
    merges: list[str] = []
    current_spans: list[int] = []
    current_title: str | None = None
    current_emphasis_cols: set[int] = set()
    max_col = 1

    for idx, row in enumerate(rows):
        row_idx = idx + 1 + ROW_OFFSET
        kind = kinds[idx]
        if kind == "blank":
            xml_rows.append(f'<row r="{row_idx}"/>')
            current_spans = []
            current_emphasis_cols = set()
            continue

        cells = []
        row_height = 18
        if kind == "title":
            col_idx = 1 + COL_OFFSET
            cells.append(cell_xml(col_idx, row_idx, row[0], "title", BORDER_ALL))
            max_col = max(max_col, col_idx)
            current_spans = []
            current_title = safe_text(row[0])
            current_emphasis_cols = set()
            row_height = estimated_row_height(row, kind, [1], col_widths)
        else:
            if kind == "header":
                end = block_end_index(kinds, idx)
                current_spans = column_spans(rows[idx:end])
                current_emphasis_cols = emphasis_columns(current_title, row)
            elif not current_spans:
                current_spans = [1] * max(len(row), 1)
            is_last = kind in {"data", "empty"} and next_non_blank_kind(kinds, idx) in {None, "title"}
            row_height = estimated_row_height(row, kind, current_spans, col_widths)
            max_col = max(max_col, append_table_cells(cells, merges, row_idx, row, kind, current_spans, is_last, current_emphasis_cols))

        xml_rows.append(f'<row r="{row_idx}" ht="{row_height}" customHeight="1">{"".join(cells)}</row>')

    if max_col > len(col_widths):
        col_widths.extend([8.0] * (max_col - len(col_widths)))
    cols = "".join(f'<col min="{idx}" max="{idx}" width="{width:.2f}" customWidth="1"/>' for idx, width in enumerate(col_widths, start=1))
    dimension = f"A1:{col_name(max_col)}{max(len(rows) + ROW_OFFSET, 1)}"
    merge_xml = f'<mergeCells count="{len(merges)}">{"".join(merges)}</mergeCells>' if merges else ""
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <dimension ref="{dimension}"/>
  <sheetViews><sheetView workbookViewId="0"/></sheetViews>
  <sheetFormatPr defaultRowHeight="18"/>
  <cols>{cols}</cols>
  <sheetData>{''.join(xml_rows)}</sheetData>
  {merge_xml}
</worksheet>'''


def workbook_xml(names: list[str]) -> str:
    sheets = "".join(f'<sheet name="{escape(name, {chr(34): "&quot;"})}" sheetId="{idx}" r:id="rId{idx}"/>' for idx, name in enumerate(names, start=1))
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>{sheets}</sheets></workbook>'''


def workbook_rels(count: int) -> str:
    rels = "".join(f'<Relationship Id="rId{idx}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{idx}.xml"/>' for idx in range(1, count + 1))
    rels += f'<Relationship Id="rId{count + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{rels}</Relationships>'''


def content_types(count: int) -> str:
    sheets = "".join(f'<Override PartName="/xl/worksheets/sheet{idx}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for idx in range(1, count + 1))
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
  {sheets}
</Types>'''


def styles_xml() -> str:
    inner = "FF000000"
    outer = "FF000000"

    def side(name: str, mask: int, bit: int) -> str:
        style = "medium" if mask & bit else "thin"
        color = outer if mask & bit else inner
        return f'<{name} style="{style}"><color rgb="{color}"/></{name}>'

    borders = []
    for mask in range(16):
        borders.append(
            "<border>"
            + side("left", mask, BORDER_LEFT)
            + side("right", mask, BORDER_RIGHT)
            + side("top", mask, BORDER_TOP)
            + side("bottom", mask, BORDER_BOTTOM)
            + "</border>"
        )

    kind_formats = {
        "data": (0, 0),
        "title": (1, 2),
        "header": (2, 3),
        "empty": (3, 4),
        "good": (4, 5),
        "bad": (3, 4),
        "strong": (2, 0),
    }
    xfs = []
    for kind in STYLE_KINDS:
        font_id, fill_id = kind_formats[kind]
        xfs.extend(
            f'<xf numFmtId="0" fontId="{font_id}" fillId="{fill_id}" borderId="{mask}" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="center" wrapText="0"/></xf>'
            for mask in range(16)
        )

    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="5"><font><sz val="10"/><color theme="1"/><name val="Aptos"/></font><font><b/><sz val="12"/><color rgb="FFFFFFFF"/><name val="Aptos"/></font><font><b/><sz val="10"/><color rgb="FF0F2F2C"/><name val="Aptos"/></font><font><sz val="10"/><color rgb="FF8A2D2D"/><name val="Aptos"/></font><font><sz val="10"/><color rgb="FF1F6B3D"/><name val="Aptos"/></font></fonts>
  <fills count="6"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF0F2F2C"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFE4F2EE"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFBE4E4"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFE5F4EA"/><bgColor indexed="64"/></patternFill></fill></fills>
  <borders count="{len(borders)}">{"".join(borders)}</borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="{len(xfs)}">{"".join(xfs)}</cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>'''


def root_rels() -> str:
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>'''


def doc_props(report: dict[str, Any]) -> tuple[str, str]:
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    title = escape(f"NetApp AutoSupport Report - {safe_text(report.get('cluster', {}).get('name', '-'))}")
    core = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>{title}</dc:title><dc:creator>NetApp AutoSupport Analyzer</dc:creator><cp:lastModifiedBy>NetApp AutoSupport Analyzer</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">{now}</dcterms:modified></cp:coreProperties>'''
    app = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>NetApp AutoSupport Analyzer</Application></Properties>'''
    return core, app


def export_report_xlsx(report: dict[str, Any]) -> bytes:
    used_names: set[str] = set()
    sheets = [(sheet_name(name, used_names), rows) for name, rows in workbook_sheets(report)]
    core, app = doc_props(report)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types(len(sheets)))
        archive.writestr("_rels/.rels", root_rels())
        archive.writestr("docProps/core.xml", core)
        archive.writestr("docProps/app.xml", app)
        archive.writestr("xl/workbook.xml", workbook_xml([name for name, _ in sheets]))
        archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels(len(sheets)))
        archive.writestr("xl/styles.xml", styles_xml())
        for idx, (_, rows) in enumerate(sheets, start=1):
            archive.writestr(f"xl/worksheets/sheet{idx}.xml", worksheet_xml(rows))
    return buffer.getvalue()
