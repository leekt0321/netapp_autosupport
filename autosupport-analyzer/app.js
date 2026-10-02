let report = normalizeReport(window.REPORT_DATA || {});
let serverAvailable = false;
const tableState = {};

const $ = (selector) => document.querySelector(selector);

function fillLegacyDiskFirmware(data) {
  if (!data.disks.summary.some((disk) => !disk.firmware)) return;

  const firmwareByModel = new Map();
  const outputs = data.nodes.map((node) => node.sysconfigA).filter(Boolean);
  for (const output of outputs) {
    const diskLines = /^\s*\d+(?:\.\d+)?\s*:\s+NETAPP\s+(\S+)\s+(\S+)\s+[0-9.]+[KMGTPE]?B\s+\S+\/sect\s+\([^)]+\)/gm;
    for (const match of output.matchAll(diskLines)) {
      if (!firmwareByModel.has(match[1])) firmwareByModel.set(match[1], new Set());
      firmwareByModel.get(match[1]).add(match[2]);
    }
  }

  for (const disk of data.disks.summary) {
    if (disk.firmware) continue;
    disk.firmware = [...(firmwareByModel.get(disk.model) || [])].sort().join(", ") || "-";
  }
}

function normalizeReport(data) {
  data.cluster ||= { name: "-", ontap: "-", protocols: [], management: { cluster: [], nodes: [] } };
  data.cluster.protocols ||= [];
  data.cluster.autosupport ||= data.autosupport?.status || "-";
  data.cluster.ntp ||= data.ntp || { servers: "-", timezone: "-" };
  data.cluster.management ||= { cluster: [], nodes: [] };
  data.cluster.management.cluster ||= [];
  data.cluster.management.nodes ||= [];
  data.nodes ||= [];
  data.shelves ||= [];
  data.disks ||= { total: 0, summary: [] };
  data.disks.summary ||= [];
  fillLegacyDiskFirmware(data);
  data.networkInterfaces ||= [];
  data.networkPorts ||= [];
  data.failoverGroups ||= [];
  data.fcpAdapters ||= [];
  data.nfsServers ||= [];
  data.nfsExportRules ||= [];
  data.cifsServers ||= [];
  data.cifsShares ||= [];
  data.aggregates ||= [];
  data.spareDisks ||= [];
  data.volumes ||= [];
  data.luns ||= [];
  data.igroups ||= [];
  data.snapshots ||= [];
  data.snapmirrors ||= [];
  data.snapmirrorDestinations ||= [];
  data.snapmirrorPolicies ||= [];
  data.clusterPeers ||= [];
  data.vserverPeers ||= [];
  data.licenses ||= [];
  data.eventLogs ||= [];
  data.sysconfigA ||= [];
  data.sysconfigCa ||= [];
  data.sysconfigSlots ||= [];
  data.autosupport ||= { status: data.cluster.autosupport || "-", nodes: [] };
  data.ntp ||= data.cluster.ntp || { servers: "-", timezone: "-" };
  data.sourceFolders ||= [];
  data.generatedAt ||= "-";
  return data;
}

function escapeHtml(value) {
  return String(value ?? "-")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function stripHtml(value) {
  const text = String(value ?? "-").replace(/<[^>]*>/g, " ");
  return text.replace(/\s+/g, " ").trim();
}

function valueText(value) {
  if (Array.isArray(value)) return value.join(", ");
  return value ?? "-";
}

function badge(value, tone = "neutral") {
  return `<span class="badge badge--${tone}">${escapeHtml(valueText(value))}</span>`;
}

function severityTone(value) {
  const severity = String(value || "").toLowerCase();
  if (severity === "emergency") return "danger";
  if (severity === "alert") return "warn";
  if (severity === "error") return "bad";
  return "neutral";
}

function fcRate(value) {
  const text = String(value ?? "").trim();
  if (!text || text === "-") return "-";
  return /^\d+(?:\.\d+)?$/.test(text) ? `${text}G` : text;
}

function hasProtocol(row, protocol) {
  const values = String(row?.protocol || "")
    .toLowerCase()
    .split(/[,/\s]+/)
    .filter(Boolean);
  return values.includes(protocol.toLowerCase());
}

function nfsRuleAllowsNfs(rule) {
  return String(rule?.protocols || "")
    .toLowerCase()
    .split(/[,/\s]+/)
    .some((value) => value === "any" || value === "all" || value.startsWith("nfs"));
}

function nfsVolumes(data, exportRules) {
  const policies = new Set(exportRules.map((row) => `${row.vserver || ""}\u0000${row.policy || ""}`));
  return data.volumes.filter((row) => {
    const junction = String(row.junctionPath || "").trim();
    return policies.has(`${row.vserver || ""}\u0000${row.exportPolicy || ""}`) && junction && junction !== "-";
  });
}

function cellRaw(column, row) {
  if (typeof column.value === "function") return column.value(row);
  return row[column.value];
}

function cellText(column, row) {
  if (typeof column.sortValue === "function") return valueText(column.sortValue(row));
  if (column.sortValue) return valueText(row[column.sortValue]);
  return stripHtml(cellRaw(column, row));
}

function sortToken(value) {
  const text = stripHtml(value);
  const numberMatch = text.replace(/,/g, "").match(/^-?\d+(?:\.\d+)?/);
  if (numberMatch) return Number(numberMatch[0]);
  return text.toLowerCase();
}

function ensureTableTools(target, columns, rows, visibleRows, searchable) {
  const parent = target.closest(".table-wrap");
  if (!parent || !searchable) return;
  const id = target.id;
  const state = tableState[id];
  const signature = columns.map((column) => column.label).join("|");
  let tools = parent.querySelector(`.table-tools[data-for="${id}"]`);

  if (!tools || tools.dataset.columns !== signature) {
    if (!tools) {
      tools = document.createElement("div");
      tools.className = "table-tools";
      tools.dataset.for = id;
      parent.insertBefore(tools, target);
    }
    const options = [
      `<option value="all">전체 컬럼</option>`,
      ...columns.map((column, index) => `<option value="${index}">${escapeHtml(column.label)}</option>`),
    ].join("");
    tools.dataset.columns = signature;
    tools.innerHTML = `
      <label class="table-tool table-tool--basis">
        <span>검색 기준</span>
        <select>${options}</select>
      </label>
      <label class="table-tool table-tool--query">
        <span>검색어</span>
        <input type="search" autocomplete="off" />
      </label>
      <small></small>
    `;
    tools.querySelector("select").addEventListener("change", (event) => {
      tableState[id].searchIndex = event.target.value;
      renderTables();
    });
    tools.querySelector("input").addEventListener("input", (event) => {
      tableState[id].query = event.target.value;
      renderTables();
    });
  }

  const select = tools.querySelector("select");
  const input = tools.querySelector("input");
  const summary = tools.querySelector("small");
  const searchLabel = state.searchIndex === "all" ? "전체 컬럼" : columns[Number(state.searchIndex)]?.label || "전체 컬럼";
  const sortLabel = state.sortIndex === null
    ? "정렬 기준 없음"
    : `${columns[state.sortIndex]?.label || "-"} / ${state.direction === "asc" ? "오름차순" : "내림차순"}`;

  if (select.value !== state.searchIndex) select.value = state.searchIndex;
  input.placeholder = `${searchLabel}에서 검색`;
  if (document.activeElement !== input && input.value !== state.query) {
    input.value = state.query;
  }
  summary.textContent = `${visibleRows.length} / ${rows.length} · 정렬: ${sortLabel}`;
}

function table(selector, columns, rows, empty = "없음", options = {}) {
  const target = $(selector);
  if (!target) return;
  const id = target.id;
  const sourceRows = rows || [];
  tableState[id] ||= { query: "", searchIndex: "all", sortIndex: null, direction: "asc" };
  const state = tableState[id];

  if (state.searchIndex !== "all" && !columns[Number(state.searchIndex)]) {
    state.searchIndex = "all";
  }
  if (state.sortIndex !== null && !columns[state.sortIndex]) {
    state.sortIndex = null;
  }

  let visibleRows = sourceRows.filter((row) => {
    const query = state.query.trim().toLowerCase();
    if (!query) return true;
    if (state.searchIndex === "all") {
      return columns.some((column) => cellText(column, row).toLowerCase().includes(query));
    }
    const column = columns[Number(state.searchIndex)];
    return cellText(column, row).toLowerCase().includes(query);
  });

  if (state.sortIndex !== null) {
    const column = columns[state.sortIndex];
    visibleRows = [...visibleRows].sort((a, b) => {
      const left = sortToken(cellText(column, a));
      const right = sortToken(cellText(column, b));
      if (left < right) return state.direction === "asc" ? -1 : 1;
      if (left > right) return state.direction === "asc" ? 1 : -1;
      return 0;
    });
  }

  ensureTableTools(target, columns, sourceRows, visibleRows, options.searchable);

  if (!sourceRows.length) {
    target.innerHTML = `<tbody><tr><td colspan="${columns.length}" class="table-empty">${escapeHtml(empty)}</td></tr></tbody>`;
    return;
  }

  if (!visibleRows.length) {
    target.innerHTML = `<tbody><tr><td colspan="${columns.length}" class="table-empty">검색 결과 없음</td></tr></tbody>`;
    return;
  }

  const head = columns
    .map((column, index) => {
      const active = state.sortIndex === index;
      const sortText = active ? (state.direction === "asc" ? "오름차순" : "내림차순") : "정렬";
      const pressed = active ? "true" : "false";
      return `<th><button class="sort-button ${active ? "is-active" : ""}" type="button" data-table="${id}" data-index="${index}" aria-pressed="${pressed}" title="${escapeHtml(column.label)} ${sortText}"><span class="sort-name">${escapeHtml(column.label)}</span><span class="sort-label">${sortText}</span></button></th>`;
    })
    .join("");
  const body = visibleRows
    .map((row) => {
      const cells = columns
        .map((column) => {
          const raw = cellRaw(column, row);
          const html = column.html ? raw : escapeHtml(valueText(raw));
          return `<td>${html ?? "-"}</td>`;
        })
        .join("");
      return `<tr>${cells}</tr>`;
    })
    .join("");
  target.innerHTML = `<thead><tr>${head}</tr></thead><tbody>${body}</tbody>`;
  target.querySelectorAll(".sort-button").forEach((button) => {
    button.addEventListener("click", () => {
      const nextIndex = Number(button.dataset.index);
      if (state.sortIndex === nextIndex) {
        state.direction = state.direction === "asc" ? "desc" : "asc";
      } else {
        state.sortIndex = nextIndex;
        state.direction = "asc";
      }
      renderTables();
    });
  });
}

function renderMetrics() {
  const ontapShort = report.cluster.ontap.match(/Release\s+([^:]+)/)?.[1] || report.cluster.ontap;
  const spFirmware = [...new Set(report.nodes.map((node) => node.spFirmware).filter((value) => value && value !== "-"))].join(", ") || "-";
  const metrics = [
    ["Cluster", report.cluster.name],
    ["ONTAP", ontapShort],
    ["SP Firmware", spFirmware],
    ["AutoSupport", report.autosupport?.status || report.cluster.autosupport || "-"],
    ["NTP", `${report.ntp?.servers || report.cluster.ntp?.servers || "-"} / ${report.ntp?.timezone || report.cluster.ntp?.timezone || "-"}`],
    ["Nodes", report.nodes.length],
    ["Protocols", report.cluster.protocols.join(", ")],
    ["Shelves", report.shelves.length],
    ["Disks", report.disks.total],
    ["Aggregates", report.aggregates.length],
    ["Volumes", report.volumes.length],
    ["CIFS Shares", report.cifsShares.length],
  ];

  $("#metricGrid").innerHTML = metrics
    .map(([label, value]) => `<article class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></article>`)
    .join("");
}

function renderNodes() {
  const clusterIp = report.cluster.management.cluster.map((item) => `${item.ip} (${item.lif})`).join(", ") || "-";
  $("#nodeCards").innerHTML = report.nodes
    .map((node) => {
      const nodeMgmt = report.cluster.management.nodes.find((item) => item.node === node.hostname);
      return `
        <article class="node-card">
          <div class="node-card__top">
            <h3>${escapeHtml(node.hostname)}</h3>
            ${badge(node.spStatus, node.spStatus === "online" ? "good" : "warn")}
          </div>
          <dl class="facts">
            <div><dt>Serial</dt><dd>${escapeHtml(node.serial)}</dd></div>
            <div><dt>Model</dt><dd>${escapeHtml(node.model)}</dd></div>
            <div><dt>System ID</dt><dd>${escapeHtml(node.systemId)}</dd></div>
            <div><dt>Cluster IP</dt><dd>${escapeHtml(clusterIp)}</dd></div>
            <div><dt>Node Mgmt IP</dt><dd>${escapeHtml(nodeMgmt ? `${nodeMgmt.ip} (${nodeMgmt.lif})` : "-")}</dd></div>
            <div><dt>SP IP</dt><dd>${escapeHtml(node.spIp)}</dd></div>
            <div><dt>SP Type</dt><dd>${escapeHtml(node.spType || "-")}</dd></div>
            <div><dt>SP Firmware</dt><dd>${escapeHtml(node.spFirmware || "-")}</dd></div>
          </dl>
        </article>
      `;
    })
    .join("");
}

function renderShelves() {
  $("#shelfList").innerHTML = report.shelves
    .map((shelf) => {
      const modules = (shelf.modules || [])
        .map((module) => `<span>${escapeHtml(module.id)}: FW ${escapeHtml(module.version)} / ${escapeHtml(module.status)}</span>`)
        .join("");
      return `
        <article class="shelf">
          <div>
            <strong>${escapeHtml(shelf.name)}</strong>
            <span>${escapeHtml(`${shelf.product} / ${shelf.serial}`)}</span>
          </div>
          <div>${badge(`${shelf.diskCount} disks`, "ink")} ${badge(shelf.status, shelf.status === "Normal" ? "good" : "warn")}</div>
          <div class="module-line">${modules}</div>
        </article>
      `;
    })
    .join("");
}

function renderTables() {
  table("#diskTable", [
    { label: "Disk Type", value: "type" },
    { label: "Model", value: "model" },
    { label: "Capacity", value: "size" },
    { label: "Firmware", value: "firmware" },
    { label: "Count", value: "count" },
  ], report.disks.summary);

  table("#lifTable", [
    { label: "Vserver", value: "vserver" },
    { label: "LIF", value: "lif" },
    { label: "Role", value: "role" },
    { label: "Protocol", value: "protocol" },
    { label: "Home", value: (row) => row.homeDisplay || row.home },
    { label: "Current", value: (row) => row.currentDisplay || row.current },
    { label: "Failover Group", value: "failoverGroup" },
    { label: "Failover Policy", value: "failoverPolicy" },
    { label: "Netmask", value: "netmask" },
    { label: "Gateway", value: "gateway" },
    { label: "Address", value: "address" },
    { label: "Status", value: (row) => badge(row.status, row.status === "up" ? "good" : "warn"), sortValue: "status", html: true },
  ], report.networkInterfaces, "없음", { searchable: true });

  table("#portTable", [
    { label: "Node", value: "node" },
    { label: "Port", value: (row) => row.portDisplay || row.port },
    { label: "Usage", value: (row) => badge(row.usage, row.usage === "사용" ? "good" : row.usage === "미사용" ? "muted" : "warn"), sortValue: "usage", html: true },
    { label: "LIFs", value: "lifCount" },
    { label: "Link", value: "link" },
    { label: "Speed", value: "speed" },
    { label: "Broadcast Domain", value: "broadcastDomain" },
    { label: "Health", value: "health" },
  ], report.networkPorts, "없음", { searchable: true });

  table("#failoverGroupTable", [
    { label: "Vserver", value: "vserver" },
    { label: "Failover Group", value: "group" },
    { label: "Broadcast Domain", value: "broadcastDomain" },
    { label: "Target Count", value: "targetCount" },
    { label: "Targets", value: "targets" },
  ], report.failoverGroups, "Failover group 정보: 없음", { searchable: true });

  table("#fcpAdapterTable", [
    { label: "Node", value: "node" },
    { label: "Adapter", value: "adapter" },
    { label: "Status", value: (row) => badge(row.status, row.status === "online" ? "good" : "warn"), sortValue: "status", html: true },
    { label: "Admin", value: "adminStatus" },
    { label: "Rate", value: (row) => fcRate(row.rate) },
    { label: "Switch", value: "switchName" },
    { label: "Switch Port", value: "switchPort" },
    { label: "Switch WWN", value: "switchWwn" },
    { label: "Fabric Port", value: "fabricPortName" },
    { label: "Port ID", value: "portId" },
    { label: "Fabric", value: "fabricName" },
    { label: "Firmware", value: "firmware" },
    { label: "SFP", value: (row) => [row.sfpVendor, row.sfpPart, row.sfpSerial].filter((value) => value && value !== "-").join(" / ") || "-" },
  ], report.fcpAdapters, "FCP adapter / switch-port 정보: 없음", { searchable: true });

  table("#cifsServerTable", [
    { label: "Vserver", value: "vserver" },
    { label: "CIFS Server", value: "server" },
    { label: "Mode", value: (row) => badge(row.mode, row.mode === "AD" ? "good" : row.mode === "Workgroup" ? "warn" : "neutral"), sortValue: "mode", html: true },
    { label: "Auth Style", value: "authStyle" },
    { label: "Domain", value: "domain" },
    { label: "Domain/Workgroup", value: "domainWorkgroup" },
    { label: "Workgroup", value: "workgroup" },
    { label: "Status", value: (row) => badge(row.status, String(row.status).toLowerCase() === "up" ? "good" : "warn"), sortValue: "status", html: true },
    { label: "Site", value: "defaultSite" },
  ], report.cifsServers, "CIFS server 구성 정보: 없음", { searchable: true });

  table("#cifsShareTable", [
    { label: "Vserver", value: "vserver" },
    { label: "CIFS Server", value: "server" },
    { label: "Share", value: "share" },
    { label: "Junction Path", value: "path" },
    { label: "Properties", value: "properties" },
    { label: "Symlink", value: "symlink" },
    { label: "Offline Caching", value: "offlineCaching" },
  ], report.cifsShares, "CIFS share 구성 정보: 없음", { searchable: true });

  const protocolLifColumns = [
    { label: "Vserver", value: "vserver" },
    { label: "LIF", value: "lif" },
    { label: "Role", value: "role" },
    { label: "Protocol", value: "protocol" },
    { label: "Home", value: (row) => row.homeDisplay || row.home },
    { label: "Current", value: (row) => row.currentDisplay || row.current },
    { label: "Netmask", value: "netmask" },
    { label: "Gateway", value: "gateway" },
    { label: "Address", value: "address" },
    { label: "Status", value: (row) => badge(row.status, row.status === "up" ? "good" : "warn"), sortValue: "status", html: true },
  ];
  const protocolLunColumns = [
    { label: "Aggregate", value: "aggregate" },
    { label: "Vserver", value: "vserver" },
    { label: "Volume", value: "volume" },
    { label: "LUN", value: "lun" },
    { label: "LUN Path", value: "path" },
    { label: "Size", value: "size" },
    { label: "OS Type", value: "ostype" },
    { label: "Type", value: "type" },
    { label: "Mapped", value: "mapped" },
    { label: "Igroup", value: "igroup" },
    { label: "LUN ID", value: "lunId" },
    { label: "Reporting Nodes", value: "reportingNodes" },
    { label: "State", value: "state" },
    { label: "Protocol", value: "protocol" },
  ];
  const protocolIgroupColumns = [
    { label: "Vserver", value: "vserver" },
    { label: "Igroup", value: "igroup" },
    { label: "Protocol", value: "protocol" },
    { label: "OS Type", value: "ostype" },
    { label: "Mapped LUNs", value: "mappedLuns" },
    { label: "Initiators", value: "initiators" },
    { label: "Init Details", value: "initDetails" },
    { label: "Portset", value: "boundPortset" },
    { label: "Child Igroups", value: "childIgroups" },
  ];

  const nfsLifs = report.networkInterfaces.filter((row) => hasProtocol(row, "nfs"));
  const nfsExportRules = report.nfsExportRules.filter(nfsRuleAllowsNfs);
  table("#nfsServerTable", [
    { label: "Vserver", value: "vserver" },
    { label: "Status", value: "status" },
    { label: "NFSv3", value: "v3" },
    { label: "NFSv4", value: "v4" },
    { label: "NFSv4.1", value: "v41" },
    { label: "TCP", value: "tcp" },
    { label: "UDP", value: "udp" },
    { label: "Default Windows User", value: "defaultWindowsUser" },
  ], report.nfsServers, "NFS server 구성 정보: 없음", { searchable: true });
  table("#nfsLifTable", protocolLifColumns, nfsLifs, "NFS 활성 LIF 없음", { searchable: true });
  table("#nfsExportRuleTable", [
    { label: "Vserver", value: "vserver" },
    { label: "Policy", value: "policy" },
    { label: "Rule Index", value: "ruleIndex" },
    { label: "Protocols", value: "protocols" },
    { label: "Client Match", value: "clientMatch" },
    { label: "RO Rule", value: "roRule" },
    { label: "RW Rule", value: "rwRule" },
    { label: "Superuser", value: "superuser" },
    { label: "Anonymous User", value: "anonymousUser" },
  ], nfsExportRules, "NFS export rule 없음", { searchable: true });
  table("#nfsVolumeTable", [
    { label: "Aggregate", value: "aggregate" },
    { label: "Vserver", value: "vserver" },
    { label: "Volume", value: "volume" },
    { label: "Junction Path", value: "junctionPath" },
    { label: "Export Policy", value: "exportPolicy" },
    { label: "Volume Type", value: "volumeType" },
    { label: "Size", value: "size" },
    { label: "Security Style", value: "securityStyle" },
    { label: "State", value: "state" },
  ], nfsVolumes(report, nfsExportRules), "NFS export volume 없음", { searchable: true });

  table("#iscsiLifTable", protocolLifColumns, report.networkInterfaces.filter((row) => hasProtocol(row, "iscsi")), "iSCSI LIF 없음", { searchable: true });
  table("#iscsiLunTable", protocolLunColumns, report.luns.filter((row) => hasProtocol(row, "iscsi")), "iSCSI LUN 없음", { searchable: true });
  table("#iscsiIgroupTable", protocolIgroupColumns, report.igroups.filter((row) => hasProtocol(row, "iscsi")), "iSCSI igroup 없음", { searchable: true });

  table("#fcpLifTable", protocolLifColumns, report.networkInterfaces.filter((row) => hasProtocol(row, "fcp")), "FCP LIF 없음", { searchable: true });
  table("#fcpLunTable", protocolLunColumns, report.luns.filter((row) => hasProtocol(row, "fcp")), "FCP LUN 없음", { searchable: true });
  table("#fcpIgroupTable", protocolIgroupColumns, report.igroups.filter((row) => hasProtocol(row, "fcp")), "FCP igroup 없음", { searchable: true });

  table("#aggrTable", [
    { label: "Node", value: "node" },
    { label: "Aggregate", value: "name" },
    { label: "Root", value: "root" },
    { label: "Disk Type", value: "diskType" },
    { label: "Disk Count", value: "diskCount" },
    { label: "Max RAID", value: "maxRaid" },
    { label: "Usable Size", value: "usableSize" },
    { label: "Available", value: "available" },
    { label: "Used %", value: "usedPercent" },
    { label: "RAID", value: "raidType" },
  ], report.aggregates, "없음", { searchable: true });

  table("#spareTable", [
    { label: "Node", value: "node" },
    { label: "Disk", value: "name" },
    { label: "Kind", value: "kind" },
    { label: "Model", value: "model" },
    { label: "Size", value: "size" },
    { label: "Partition", value: "partition" },
    { label: "State", value: "state" },
    { label: "Serial", value: "serial" },
  ], report.spareDisks, "Spare disk 없음", { searchable: true });

  table("#volumeTable", [
    { label: "Aggregate", value: "aggregate" },
    { label: "Vserver", value: "vserver" },
    { label: "Volume", value: "volume" },
    { label: "Junction Path", value: "junctionPath" },
    { label: "Volume Type", value: "volumeType" },
    { label: "Size", value: "size" },
    { label: "space-guarantee", value: "type" },
    { label: "Security Style", value: "securityStyle" },
    { label: "Inode %", value: "inodePercent" },
    { label: "Used %", value: "usedPercent" },
    { label: "Snapshot Policy", value: "snapshotPolicy" },
    { label: "Snap Space %", value: "snapshotSpace" },
    { label: "Schedule / Count", value: (row) => (row.schedules || []).length ? row.schedules.map((s) => `${s.schedule}:${s.count}`).join(", ") : "-" },
    { label: "State", value: "state" },
  ], report.volumes, "없음", { searchable: true });

  table("#lunTable", [
    { label: "Aggregate", value: "aggregate" },
    { label: "Vserver", value: "vserver" },
    { label: "Volume", value: "volume" },
    { label: "LUN", value: "lun" },
    { label: "LUN Path", value: "path" },
    { label: "Size", value: "size" },
    { label: "OS Type", value: "ostype" },
    { label: "Type", value: "type" },
    { label: "Mapped", value: "mapped" },
    { label: "Igroup", value: "igroup" },
    { label: "LUN ID", value: "lunId" },
    { label: "Reporting Nodes", value: "reportingNodes" },
    { label: "State", value: "state" },
    { label: "Protocol", value: "protocol" },
  ], report.luns, "LUN 구성 정보: 없음", { searchable: true });

  table("#igroupTable", [
    { label: "Vserver", value: "vserver" },
    { label: "Igroup", value: "igroup" },
    { label: "Protocol", value: "protocol" },
    { label: "OS Type", value: "ostype" },
    { label: "Mapped LUNs", value: "mappedLuns" },
    { label: "Initiators", value: "initiators" },
    { label: "Init Details", value: "initDetails" },
    { label: "Portset", value: "boundPortset" },
    { label: "Child Igroups", value: "childIgroups" },
  ], report.igroups, "Igroup 구성 정보: 없음", { searchable: true });

  table("#snapshotTable", [
    { label: "Vserver", value: "vserver" },
    { label: "Volume", value: "volume" },
    { label: "Snapshot", value: "snapshot" },
    { label: "Create Time", value: "createTime" },
    { label: "State", value: "state" },
    { label: "Size", value: "size" },
    { label: "Total %", value: "totalPercent" },
    { label: "Used %", value: "usedPercent" },
    { label: "Busy", value: "busy" },
    { label: "Owners", value: "owners" },
    { label: "SnapMirror Label", value: "snapmirrorLabel" },
    { label: "Comment", value: "comment" },
    { label: "Expiry Time", value: "expiryTime" },
  ], report.snapshots, "Snapshot 목록 없음", { searchable: true });

  table("#snapmirrorTable", [
    { label: "Source Path", value: "sourcePath" },
    { label: "Destination Path", value: "destinationPath" },
    { label: "Type", value: "type" },
    { label: "State", value: "state" },
    { label: "Status", value: "status" },
    { label: "Healthy", value: "healthy" },
    { label: "Policy", value: "policy" },
    { label: "Schedule", value: "schedule" },
    { label: "Policy Schedule", value: "policySchedule" },
    { label: "Policy Rules", value: "policyRules" },
    { label: "Cluster Peer", value: "clusterPeer" },
    { label: "Vserver", value: "vserver" },
    { label: "Peer Vserver", value: "peerVserver" },
    { label: "Lag", value: "lagTime" },
    { label: "Last Transfer", value: "lastTransfer" },
  ], report.snapmirrors, "SnapMirror 구성 정보: 없음", { searchable: true });

  table("#snapmirrorDestinationTable", [
    { label: "Source Path", value: "sourcePath" },
    { label: "Destination Path", value: "destinationPath" },
    { label: "Type", value: "type" },
    { label: "Status", value: "status" },
    { label: "Progress", value: "transferProgress" },
    { label: "Updated", value: "progressLastUpdated" },
    { label: "Source Node", value: "sourceVolumeNode" },
    { label: "Relationship ID", value: "relationshipId" },
  ], report.snapmirrorDestinations, "snapmirror list-destination 정보: 없음", { searchable: true });

  table("#snapmirrorPolicyTable", [
    { label: "Owner", value: "vserver" },
    { label: "Policy", value: "policy" },
    { label: "Type", value: "type" },
    { label: "Transfer Schedule", value: "transferSchedule" },
    { label: "Snapshot Schedule", value: "snapshotSchedule" },
    { label: "Rules", value: "rules" },
    { label: "Total Keep", value: "totalKeep" },
    { label: "Total Rules", value: "totalRules" },
    { label: "Throttle", value: "throttle" },
    { label: "Tries", value: "tries" },
    { label: "Comment", value: "comment" },
  ], report.snapmirrorPolicies, "SnapMirror policy 정보: 없음", { searchable: true });

  table("#clusterPeerTable", [
    { label: "Peer Cluster", value: "cluster" },
    { label: "Addresses", value: "peerAddresses" },
    { label: "Availability", value: "availability" },
    { label: "Healthy", value: "pairsHealthy" },
    { label: "Unhealthy", value: "pairsUnhealthy" },
    { label: "Auth", value: "authentication" },
    { label: "Encryption", value: "encryption" },
    { label: "Address Family", value: "addressFamily" },
    { label: "Version", value: "version" },
  ], report.clusterPeers, "cluster peer show 정보: 없음", { searchable: true });

  table("#vserverPeerTable", [
    { label: "Local Vserver", value: "localVserver" },
    { label: "Peer Vserver", value: "peerVserver" },
    { label: "Real Peer", value: "realPeerVserver" },
    { label: "Cluster Peer", value: "clusterPeer" },
    { label: "State", value: "state" },
    { label: "Applications", value: "applications" },
    { label: "Peer Cluster UUID", value: "peerClusterUuid" },
  ], report.vserverPeers, "vserver peer show 정보: 없음", { searchable: true });

  table("#eventLogTable", [
    { label: "Node", value: "node" },
    { label: "Severity", value: (row) => badge(row.severity, severityTone(row.severity)), sortValue: "severity", html: true },
    { label: "Time", value: "time" },
    { label: "Event", value: "event" },
    { label: "Message", value: "message" },
  ], report.eventLogs, "alert/error/emergency event 없음", { searchable: true });

  table("#licenseTable", [
    { label: "Node / Serial", value: "group" },
    { label: "Node", value: "node" },
    { label: "Serial", value: "serial" },
    { label: "Package", value: "package" },
    { label: "Type", value: "type" },
    { label: "Installed", value: "installed" },
    { label: "State", value: "state" },
    { label: "Entitlement", value: "entitlement" },
  ], report.licenses, "License 정보: 없음", { searchable: true });
}

function rawDetails(items, empty) {
  if (!items || !items.length) return `<div class="empty-state compact">${escapeHtml(empty)}</div>`;
  return items
    .map((item) => `<details open><summary>${escapeHtml(item.node)}</summary><pre>${escapeHtml(item.output)}</pre></details>`)
    .join("");
}

function renderRaw() {
  $("#sysconfigARaw").innerHTML = rawDetails(report.sysconfigA, "sysconfig -a 없음");
  $("#sysconfigRaw").innerHTML = rawDetails(report.sysconfigCa, "sysconfig -ca 없음");
}

function renderReport() {
  report = normalizeReport(report);
  $("#clusterTitle").textContent = `${report.cluster.name} 구성 리포트`;
  $("#sourceLine").textContent = `${report.generatedAt} 기준 / ${report.sourceFolders.length}개 AutoSupport 폴더 분석`;
  renderMetrics();
  renderNodes();
  renderShelves();
  renderTables();
  renderRaw();
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || response.statusText);
  return payload;
}

async function loadReports() {
  const library = $("#reportLibrary");
  const storageLine = $("#storagePathLine");
  try {
    const [reports, storage] = await Promise.all([fetchJson("api/reports"), fetchJson("api/storage")]);
    serverAvailable = true;
    storageLine.textContent = `저장 위치: ${storage.reportsDir}`;
    $("#uploadStatus").textContent = "서버 연결됨. .7z/.zip 또는 압축 해제 폴더를 업로드할 수 있습니다.";
    if (!reports.length) {
      library.innerHTML = `<div class="empty-state compact">저장된 JSON 리포트 없음</div>`;
      return;
    }
    library.innerHTML = reports
      .map((item) => `
        <div class="report-row" data-file="${escapeHtml(item.file)}">
          <button class="report-item" type="button" data-file="${escapeHtml(item.file)}">
            <strong>${escapeHtml(item.cluster)}</strong>
            <span>${escapeHtml(item.savedAt)}</span>
            <small>${escapeHtml(item.nodes)} nodes / ${escapeHtml(item.volumes)} volumes / ${escapeHtml(item.disks)} disks</small>
            <small class="file-path">${escapeHtml(item.path)}</small>
          </button>
          <button class="icon-button icon-button--danger report-delete" type="button" title="리포트 삭제" aria-label="${escapeHtml(item.cluster)} 리포트 삭제" data-file="${escapeHtml(item.file)}" data-cluster="${escapeHtml(item.cluster)}">삭제</button>
        </div>
      `)
      .join("");
    library.querySelectorAll(".report-item").forEach((item) => {
      item.addEventListener("click", async () => {
        report = normalizeReport(await fetchJson(`api/reports/${encodeURIComponent(item.dataset.file)}`));
        renderReport();
      });
    });
    library.querySelectorAll(".report-delete").forEach((item) => {
      item.addEventListener("click", async () => deleteSavedReport(item.dataset.file, item.dataset.cluster));
    });
  } catch {
    serverAvailable = false;
    storageLine.textContent = "저장 위치: 로컬 서버 실행 후 확인 가능";
    library.innerHTML = `<div class="empty-state compact">정적 보기 모드입니다. 업로드를 쓰려면 server.py를 실행하세요.</div>`;
  }
}

async function deleteSavedReport(filename, cluster) {
  if (!serverAvailable || !filename) return;
  const confirmed = window.confirm(`${cluster || filename} 리포트를 삭제할까요? JSON 파일이 reports 폴더에서 제거됩니다.`);
  if (!confirmed) return;
  try {
    await fetchJson(`api/reports/${encodeURIComponent(filename)}`, { method: "DELETE" });
    $("#uploadStatus").textContent = `삭제 완료: ${cluster || filename}`;
    await loadReports();
  } catch (error) {
    $("#uploadStatus").textContent = `분석 실패: ${error.message}`;
  }
}

async function uploadFiles(event) {
  event.preventDefault();
  if (!serverAvailable) {
    $("#uploadStatus").textContent = "먼저 로컬 서버로 접속하세요: python server.py";
    return;
  }

  const archives = Array.from($("#archiveInput").files || []);
  const folderFiles = Array.from($("#folderInput").files || []);
  if (!archives.length && !folderFiles.length) {
    $("#uploadStatus").textContent = "업로드할 .7z/.zip 파일 또는 압축 해제 폴더를 선택하세요.";
    return;
  }

  const formData = new FormData();
  archives.forEach((file) => formData.append("files", file, file.name));
  folderFiles.forEach((file) => formData.append("files", file, file.webkitRelativePath || file.name));

  $("#uploadButton").disabled = true;
  $("#uploadStatus").textContent = "업로드 및 분석 중입니다. 원본은 분석 후 자동 정리됩니다.";
  try {
    const payload = await fetchJson("api/upload", { method: "POST", body: formData });
    report = normalizeReport(payload.report);
    renderReport();
    await loadReports();
    $("#uploadStatus").textContent = `저장 완료: ${payload.summary.cluster} / ${payload.storage.savedFile}`;
    $("#storagePathLine").textContent = `저장 위치: ${payload.storage.reportsDir}`;
    $("#uploadForm").reset();
  } catch (error) {
    $("#uploadStatus").textContent = `분석 실패: ${error.message}`;
  } finally {
    $("#uploadButton").disabled = false;
  }
}

function wireInteractions() {
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((item) => item.classList.remove("is-active"));
      document.querySelectorAll(".tab-panel").forEach((item) => item.classList.remove("is-active"));
      tab.classList.add("is-active");
      $(`#${tab.dataset.tab}Panel`).classList.add("is-active");
    });
  });

  $("#exportButton").addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${report.cluster.name || "autosupport"}-report.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  });

  $("#excelExportButton").addEventListener("click", async () => {
    if (!serverAvailable) {
      $("#uploadStatus").textContent = "Excel 추출은 로컬 서버 실행 후 사용할 수 있습니다: python server.py";
      return;
    }
    try {
      const response = await fetch("api/export/excel", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(report),
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.error || response.statusText);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${report.cluster.name || "autosupport"}-autosupport-report.xlsx`;
      anchor.click();
      URL.revokeObjectURL(url);
      $("#uploadStatus").textContent = "Excel 파일 생성 완료";
    } catch (error) {
      $("#uploadStatus").textContent = `Excel 추출 실패: ${error.message}`;
    }
  });
  $("#uploadForm").addEventListener("submit", uploadFiles);
  $("#refreshReportsButton").addEventListener("click", loadReports);
}

async function init() {
  renderReport();
  wireInteractions();
  await loadReports();
}

init();
