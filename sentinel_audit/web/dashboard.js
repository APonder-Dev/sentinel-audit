"use strict";

const $ = (id) => document.getElementById(id);
const collectors = [
  ["system", "System", "monitor", "system_info"],
  ["network", "Network", "network", "network_info"],
  ["firewall", "Firewall", "shield", "firewall_status"],
  ["processes", "Processes", "cpu", "process_info"],
  ["disk", "Encryption", "hard-drive", "disk_encryption"],
];
const severityOrder = ["high", "medium", "low", "informational"];
const terminal = new Set(["finished", "error", "unsupported", "partial", "unknown"]);
const state = {
  token: null, connected: false, launching: false, active: null, scan: null, deepSupported: false,
  version: 0, offset: 0, total: 0, tab: "findings", signature: "", syncing: false,
  again: false, timer: null, historyQuery: "", historyStatus: "", actionError: "", historySignature: "",
  baselineOffset: 0, baselinesLoaded: false, baselineBusy: false, comparison: null,
};

function node(tag, className, text) {
  const result = document.createElement(tag);
  if (className) result.className = className;
  if (text !== undefined) result.textContent = String(text);
  return result;
}
function icon(name, className = "") {
  const item = node("i", className);
  item.dataset.lucide = name;
  item.setAttribute("aria-hidden", "true");
  return item;
}
function icons() {
  lucide.createIcons({ attrs: { "aria-hidden": "true" } });
}
function badge(value) {
  const allowed = [...severityOrder, "failed", "error", "completed", "finished", "running", "queued", "unsupported", "partial", "denied", "awaiting_approval", "new", "resolved", "changed", "unchanged", "newly_observed", "no_longer_observed", "unverified"];
  const label = value === "denied" ? "Approval denied" : value === "awaiting_approval" ? "Awaiting approval" : (value || "Unknown").replaceAll("_", " ");
  return node("span", "badge " + (allowed.includes(value) ? value : "unknown"), label);
}
function date(value) {
  return value ? new Date(value).toLocaleString(undefined, {
    month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit",
  }) : "Not started";
}
function duration(value) {
  return typeof value === "number" ? value.toFixed(1) + "s" : "--";
}
function route() {
  const hash = location.hash.slice(1);
  if (hash === "history") return { page: "history" };
  if (hash.startsWith("scan/")) return { page: "detail", id: hash.slice(5) };
  return { page: "overview" };
}
function announce(message) { $("announcement").textContent = message; }
function error(message) {
  $("error-text").textContent = message;
  $("error-banner").hidden = !message;
}
function connection(online) {
  state.connected = online;
  $("connection").classList.toggle("offline", !online);
  $("connection").replaceChildren(node("span", "status-dot"), document.createTextNode(online ? "Local connection" : "Disconnected"));
  buttons();
}
function buttons() {
  const busy = Boolean(state.active) || state.launching;
  $("run-scan").disabled = busy || !state.connected;
  $("first-scan").disabled = busy || !state.connected;
  $("scan-mode").disabled = busy || !state.connected;
  $("scan-mode").querySelector('option[value="deep"]').disabled = !state.deepSupported;
  $("run-scan").querySelector("span").textContent = state.launching ? "Starting scan..." : busy ? "Scan in progress" : $("scan-mode").value === "deep" ? "Run deep scan" : "Run scan";
}
async function api(path, options = {}, retryToken = true) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  let response;
  try {
    response = await fetch(path, { ...options, signal: controller.signal, cache: "no-store",
      headers: { ...(options.method ? { "Content-Type": "application/json", "X-Sentinel-Token": state.token } : {}), ...options.headers },
    });
  } catch {
    throw new Error("Cannot reach the local server. Check that SentinelAudit is running.");
  } finally {
    clearTimeout(timeout);
  }
  if (response.status === 403 && options.method && retryToken) {
    state.token = (await api("/api/session")).token;
    return api(path, options, false);
  }
  const body = await response.json();
  if (!response.ok) {
    const failure = new Error(typeof body.detail === "string" ? body.detail : "The request could not be completed.");
    failure.status = response.status;
    throw failure;
  }
  return body;
}
async function launch() {
  if (state.launching || state.active || !state.connected) return;
  state.launching = true;
  state.actionError = "";
  buttons();
  error("");
  try {
    const scan = await api("/api/scans", { method: "POST", body: JSON.stringify({ mode: $("scan-mode").value }) });
    state.active = { ...scan, progress: {} };
    location.hash = "scan/" + scan.id;
    announce("Scan started.");
  } catch (failure) {
    state.actionError = failure.message;
    error(failure.message);
  } finally {
    state.launching = false;
    buttons();
    sync();
  }
}

function renderProgress(scan) {
  $("active-panel").hidden = !scan;
  if (!scan) return;
  const progress = scan.progress || {};
  $("active-title").textContent = scan.status === "awaiting_approval" ? "Waiting for administrator approval" : scan.mode === "deep" ? "Deep scan in progress" : "Scan in progress";
  const finished = collectors.filter(([key]) => terminal.has(progress[key])).length;
  $("scan-progress").value = finished;
  $("active-count").textContent = finished + " / 5 finished";
  $("active-caption").textContent = scan.status === "awaiting_approval" ? "Approve or cancel the Windows UAC prompt. The scan has not started." : scan.status === "queued" ? "Waiting to start" : finished === 5 ? "Analyzing findings" : "Collecting host telemetry";
  $("active-link").href = "#scan/" + scan.id;
  const list = $("collector-progress");
  list.replaceChildren();
  collectors.forEach(([key, label]) => {
    const status = progress[key] || "pending";
    const item = node("div", "collector-step " + status);
    const symbol = status === "running" ? "loader-circle" : status === "finished" ? "circle-check" : status === "error" ? "circle-alert" : status === "unsupported" ? "circle-minus" : "circle";
    item.append(icon(symbol, status === "running" ? "spin" : ""));
    const text = node("span", "", label);
    text.append(node("small", "", status.charAt(0).toUpperCase() + status.slice(1)));
    item.append(text);
    list.append(item);
  });
}
function showRoute() {
  const view = route();
  $("page-title").textContent = view.page === "history" ? "Scan history" : view.page === "detail" ? "Scan details" : "Endpoint overview";
  $("breadcrumb").textContent = view.page === "history" ? "Scan history" : view.page === "detail" ? "Scan details" : "Overview";
  $("page-subtitle").textContent = view.page === "history" ? "Local audit records" : "Local audit workspace";
  for (const key of ["overview", "history"]) {
    const current = key === (view.page === "detail" ? "history" : view.page);
    if (current) $("nav-" + key).setAttribute("aria-current", "page");
    else $("nav-" + key).removeAttribute("aria-current");
  }
}
function renderHistory(history) {
  const signature = JSON.stringify([history, state.offset]);
  if (signature === state.historySignature) return;
  state.historySignature = signature;
  state.total = history.total;
  $("history-count").textContent = history.total;
  $("history-empty").hidden = history.items.length > 0;
  $("history-range").textContent = history.total ? (state.offset + 1) + "-" + Math.min(state.offset + 10, history.total) + " of " + history.total + " scans" : "0 scans";
  $("previous-page").disabled = state.offset === 0;
  $("next-page").disabled = state.offset + 10 >= history.total;
  const rows = $("history-rows");
  rows.replaceChildren();
  history.items.forEach((scan) => {
    const row = node("tr");
    const name = node("td");
    const link = node("a", "", scan.hostname || "Local host");
    link.href = "#scan/" + scan.id;
    name.append(link, node("small", "mono", scan.id.slice(0, 8)), node("small", "", scan.mode === "deep" ? "Deep scan" : "Standard scan"));
    const started = node("td", "", date(scan.created_at));
    const status = node("td"); status.append(badge(scan.status));
    const score = node("td", "", scan.score == null ? "--" : scan.score + " / 100");
    if (scan.score != null) score.append(node("small", "", scan.coverage_collected == null ? "Coverage unknown" : scan.coverage_collected < 5 ? "Provisional / " + scan.coverage_collected + " of 5 checks" : "5 of 5 checks collected"));
    const findings = node("td", "", scan.findings_count ?? "--");
    const elapsed = node("td", "", duration(scan.duration_seconds));
    const open = node("td");
    const arrow = node("a", "text-link");
    arrow.href = link.href;
    arrow.setAttribute("aria-label", "Open scan " + scan.id.slice(0, 8));
    arrow.title = "Open scan";
    arrow.append(icon("arrow-up-right"));
    open.append(arrow);
    row.append(name, started, status, score, findings, elapsed, open);
    rows.append(row);
  });
}
function renderScan(scan) {
  if (state.scan?.id !== scan?.id) resetComparison();
  state.scan = scan;
  $("empty").hidden = Boolean(scan);
  $("detail-view").hidden = !scan;
  if (!scan) return;
  $("page-subtitle").textContent = date(scan.created_at) + (scan.duration_seconds != null ? "  /  " + duration(scan.duration_seconds) : "");
  $("host-name").textContent = scan.report?.system_info?.hostname || "Local host";
  $("scan-status").replaceChildren(badge(scan.status));
  $("scan-id").textContent = scan.id;
  $("scan-error").hidden = !["failed", "denied"].includes(scan.status);
  $("scan-error").textContent = scan.error || "This scan did not finish.";
  $("pending-result").hidden = !["queued", "awaiting_approval", "running"].includes(scan.status);
  $("pending-result").textContent = scan.status === "awaiting_approval" ? "No scan runs until administrator approval is granted." : "Results will appear when the scan finishes.";
  $("report-view").hidden = !scan.report;
  $("export-toolbar").hidden = !scan.report || scan.status !== "completed";
  const signature = JSON.stringify(scan);
  if (!scan.report || signature === state.signature) return;
  state.signature = signature;
  const report = scan.report;
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const counts = Object.fromEntries(severityOrder.map((severity) => [severity, findings.filter((finding) => finding.severity === severity).length]));
  $("score-value").textContent = report.risk_score?.score ?? "--";
  $("score-label").textContent = report.risk_score?.label || "Not available";
  $("high-value").textContent = counts.high;
  $("medium-caption").textContent = counts.medium + " medium severity";
  $("total-value").textContent = findings.length;
  $("findings-tab-count").textContent = findings.length;
  $("severity-caption").textContent = counts.low + " low / " + counts.informational + " informational";
  $("severity-bar").replaceChildren();
  severityOrder.forEach((severity) => {
    if (!counts[severity]) return;
    const bar = node("span", severity);
    bar.style.flexGrow = counts[severity];
    bar.title = severity + ": " + counts[severity];
    $("severity-bar").append(bar);
  });
  renderCoverage(scan);
  renderFindings();
  renderHost(report);
  renderCollection(scan);
  renderPorts();
}
function gapMessage(check, report) {
  if (check.key === "processes" && check.status === "partial") {
    const data = report?.process_info || {};
    const counts = Number.isInteger(data.unknown_owner_count) && Number.isInteger(data.process_count);
    return {
      title: "Process ownership partially available",
      summary: counts ? "Ownership could not be read for " + data.unknown_owner_count + " of " + data.process_count + " processes. Privileged counts are a lower bound." : "Some process owners could not be verified. Privileged counts are a lower bound.",
      action: "Review processes with appropriate OS permissions. Protected or exited processes may remain unavailable even as administrator.",
    };
  }
  const details = String(check.details || "");
  const bitlocker = /bitlocker/i.test(details) || report?.system_info?.os?.toLowerCase() === "windows";
  if (check.key === "disk" && check.status === "error" && bitlocker && /access.*denied|accessdenied|administrative rights|0x80070005/i.test(details)) {
    return {
      title: "BitLocker status requires elevated access",
      summary: "Windows denied access to the encryption check. Encryption status is unknown; this does not mean encryption is disabled.",
      action: "Verify BitLocker in Windows settings or run an audit from an authorized administrator session. No automatic elevation is performed.",
    };
  }
  return {
    title: check.label + " collection " + (check.status === "error" ? "failed" : check.status),
    summary: "This check did not produce a fully verified result.",
    action: check.remediation || "Review this check with native OS tools.",
  };
}
function technicalDetails(text) {
  const details = node("details", "technical-details");
  details.append(node("summary", "", "Technical details"), node("pre", "", text || "No technical output recorded."));
  return details;
}
function renderCoverage(scan) {
  const coverage = scan.coverage || scan.report?.coverage;
  const checks = coverage?.checks || collectors.map(([key, label]) => ({
    key, label, status: "unknown", details: "Coverage was not recorded.", remediation: "Run a new scan.",
  }));
  const gaps = checks.filter((check) => check.status !== "collected");
  $("coverage-warning").hidden = gaps.length === 0;
  $("coverage-value").textContent = checks.length - gaps.length;
  $("gap-summary").textContent = gaps.length + " of 5 checks incomplete";
  $("gap-toggle").textContent = "Review " + gaps.length + " collection gaps";
  $("coverage-caption").textContent = gaps.length ? gaps.length + " partial, failed or unknown" : "Collection complete; not a security guarantee";
  $("score-confidence").textContent = gaps.length ? "Provisional / incomplete coverage" : "Higher is better / heuristic score";
  $("gap-list").replaceChildren();
  gaps.forEach((check) => {
    const item = node("div", "coverage-gap");
    const message = gapMessage(check, scan.report);
    const heading = node("div", "inline");
    heading.append(node("strong", "", message.title), badge(check.status));
    item.append(heading, node("p", "", message.summary), node("p", "", message.action), technicalDetails(check.details));
    $("gap-list").append(item);
  });
}
function renderPorts() {
  const network = state.scan?.report?.network_info || {};
  const inventory = Array.isArray(network.inventory) ? network.inventory : [];
  const query = $("port-query").value.trim().toLowerCase();
  const rows = inventory.filter((row) =>
    (!$("port-protocol").value || row.protocol === $("port-protocol").value) &&
    (!$("port-binding").value || row.binding === $("port-binding").value) &&
    [row.port, row.address, row.process, row.pid, row.service_hint].join(" ").toLowerCase().includes(query)
  );
  $("port-count").textContent = rows.length + " / " + inventory.length + " sockets";
  $("port-rows").replaceChildren();
  rows.forEach((row) => {
    const tr = node("tr");
    const address = node("td", "mono", row.address);
    address.append(node("small", "", row.family));
    const process = node("td", "", row.process || "Unknown process");
    process.append(node("small", "", row.pid == null ? "PID unavailable" : "PID " + row.pid));
    tr.append(node("td", "", row.port), node("td", "", String(row.protocol).toUpperCase()), address,
      node("td", "", row.binding), node("td", "", row.state), process, node("td", "", row.service_hint || "Unknown"));
    $("port-rows").append(tr);
  });
  $("ports-empty").hidden = rows.length > 0;
  $("ports-empty").textContent = !Array.isArray(network.inventory) ? "Structured inventory was not recorded for this scan. Run a new scan." :
    network.status !== "collected" ? "Socket inventory is unavailable or incomplete. Review collection gaps." :
    inventory.length ? "No sockets match your filters." : "No local sockets were observed in this snapshot.";
}
function renderFindings() {
  const original = state.scan?.report?.findings || [];
  const query = $("finding-query").value.trim().toLowerCase();
  const severity = $("finding-severity").value;
  const findings = original.filter((finding) => (!severity || finding.severity === severity) && [finding.title, finding.description, finding.recommendation].join(" ").toLowerCase().includes(query));
  findings.sort((a, b) => {
    const rank = (value) => { const index = severityOrder.indexOf(value); return index < 0 ? 4 : index; };
    return ($("finding-sort").value === "severity" ? rank(a.severity) - rank(b.severity) : 0) || String(a.title || "").localeCompare(String(b.title || ""));
  });
  $("findings-caption").textContent = findings.length + " of " + original.length + " findings";
  $("findings-empty").hidden = findings.length > 0;
  $("findings-empty").textContent = original.length ? "No findings match your filters." : "No findings generated. Review collection coverage before drawing conclusions.";
  const list = $("findings-list");
  list.replaceChildren();
  findings.forEach((finding) => {
    const item = node("details", "finding");
    const summary = node("summary");
    const title = node("span", "finding-title", finding.title || "Untitled finding");
    if (finding.category) title.append(node("small", "", finding.category));
    summary.append(badge(finding.severity), title, icon("chevron-down"));
    const body = node("div", "finding-body");
    body.append(node("h3", "", "FINDING ID"), node("p", "mono", finding.id || "Not recorded"),
      node("h3", "", "EVIDENCE"), node("p", "", finding.description || "No additional evidence recorded."),
      node("h3", "", "RECOMMENDATION"), node("p", "", finding.recommendation || "No recommendation recorded."));
    item.append(summary, body);
    list.append(item);
  });
  icons();
}
function renderHost(report) {
  const system = report.system_info || {};
  const fields = [
    ["Hostname", system.hostname], ["Operating system", [system.os, system.os_release].filter(Boolean).join(" ")],
    ["Current user", system.current_user], ["Local IP address", report.network_info?.ip_address],
    ["Architecture", system.architecture], ["Processor", system.processor],
    ["OS version", system.os_version], ["Audit version", report.version],
  ];
  $("host-fields").replaceChildren();
  fields.forEach(([label, value]) => {
    const row = node("div", "host-field");
    row.append(node("dt", "", label), node("dd", "", value || "Not recorded"));
    $("host-fields").append(row);
  });
}
function renderCollection(scan) {
  const disk = scan.report?.disk_encryption || {};
  const stateLabel = (value, yes, no) => value === true ? yes : value === false ? no : "Unknown / not recorded";
  $("protection-summary").replaceChildren(
    node("span", "", "Data encrypted: " + stateLabel(disk.encrypted, "Yes", "No")),
    node("strong", "", "Active protection: " + stateLabel(disk.protection_active, "On", "Off / suspended")),
  );
  $("collection-list").replaceChildren();
  collectors.forEach(([key, label, symbol, field]) => {
    const report = scan.report || {};
    const result = report[field];
    const check = scan.coverage?.checks?.find((entry) => entry.key === key);
    const status = check?.status || result?.status || "unknown";
    const item = node("details", "collection-item");
    const summary = node("summary");
    summary.append(icon(symbol), node("strong", "", label), badge(status === "collected" ? "finished" : status));
    item.append(summary);
    if (check && check.status !== "collected") {
      const message = gapMessage(check, report);
      const explanation = node("div", "collection-explanation");
      explanation.append(node("strong", "", message.title), node("p", "", message.summary), node("p", "", message.action));
      item.append(explanation);
    }
    item.append(technicalDetails(result ? JSON.stringify(result, null, 2) : "No collector output recorded."));
    $("collection-list").append(item);
  });
}
function tab(name, focus = false) {
  state.tab = name;
  document.querySelectorAll("[data-tab]").forEach((button) => {
    const selected = button.dataset.tab === name;
    button.setAttribute("aria-selected", String(selected));
    button.tabIndex = selected ? 0 : -1;
    $("panel-" + button.dataset.tab).hidden = !selected;
    if (selected && focus) button.focus();
  });
  if (name === "comparison" && !state.baselinesLoaded) loadBaselines();
}

async function downloadReport() {
  const scan = state.scan;
  if (!scan?.report || scan.status !== "completed") return;
  const format = $("export-format").value;
  const sanitized = $("export-sanitize").checked;
  $("export-report").disabled = true;
  try {
    const response = await fetch("/api/scans/" + scan.id + "/export?format=" + format + "&sanitize=" + sanitized, { cache: "no-store" });
    if (!response.ok) {
      const body = await response.json();
      throw new Error(typeof body.detail === "string" ? body.detail : "Report export failed.");
    }
    const url = URL.createObjectURL(await response.blob());
    const link = node("a");
    link.href = url;
    link.download = "sentinel-audit-" + scan.id + (sanitized ? "-sanitized" : "") + "." + (format === "markdown" ? "md" : format);
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    announce("Report downloaded.");
  } catch (failure) {
    state.actionError = failure.message || "Report export failed.";
    error(state.actionError);
  } finally {
    $("export-report").disabled = false;
  }
}
function resetComparison() {
  state.baselineOffset = 0;
  state.baselinesLoaded = false;
  state.baselineBusy = false;
  state.comparison = null;
  $("comparison-baseline").replaceChildren(node("option", "", "Select an earlier scan"));
  $("comparison-baseline").firstChild.value = "";
  $("older-baselines").disabled = false;
  $("compare-scans").disabled = true;
  $("comparison-output").hidden = true;
  $("comparison-error").hidden = true;
}
function comparisonError(message) {
  $("comparison-error").textContent = message;
  $("comparison-error").hidden = !message;
}
async function loadBaselines() {
  if (!state.scan?.report || state.baselineBusy) return;
  const current = state.scan;
  state.baselineBusy = true;
  $("older-baselines").disabled = true;
  try {
    const result = await api("/api/scans?status=completed&limit=200&offset=" + state.baselineOffset);
    if (state.scan?.id !== current.id) return;
    for (const item of result.items) {
      if (item.id === current.id || item.created_at > current.created_at) continue;
      const option = node("option", "", date(item.created_at) + " / " + (item.hostname || "Local host") + " / " + item.mode + " / " + item.id.slice(0, 8));
      option.value = item.id;
      $("comparison-baseline").append(option);
    }
    state.baselineOffset += result.items.length;
    state.baselinesLoaded = true;
    $("older-baselines").disabled = state.baselineOffset >= result.total;
    comparisonError($("comparison-baseline").options.length === 1 && state.baselineOffset >= result.total ? "No earlier completed scans are available." : "");
  } catch (failure) {
    if (state.scan?.id === current.id) {
      comparisonError(failure.message);
      $("older-baselines").disabled = false;
    }
  } finally {
    if (state.scan?.id === current.id) state.baselineBusy = false;
  }
}
async function compareScans() {
  const current = state.scan?.id;
  const baseline = $("comparison-baseline").value;
  if (!current || !baseline) return;
  $("compare-scans").disabled = true;
  $("comparison-output").hidden = true;
  comparisonError("");
  try {
    const result = await api("/api/scans/" + current + "/compare?baseline=" + encodeURIComponent(baseline));
    if (state.scan?.id !== current || $("comparison-baseline").value !== baseline) return;
    state.comparison = result;
    $("comparison-filter").value = "";
    renderComparison();
  } catch (failure) {
    if (state.scan?.id === current) comparisonError(failure.message);
  } finally {
    if (state.scan?.id === current) $("compare-scans").disabled = !$("comparison-baseline").value;
  }
}
function renderComparison() {
  const result = state.comparison;
  if (!result) return;
  $("comparison-output").hidden = false;
  $("comparison-warnings").replaceChildren(...result.warnings.map((warning) => node("li", "", warning)));
  $("comparison-warnings").hidden = !result.warnings.length;
  $("comparison-counts").textContent = Object.entries(result.counts).map(([key, value]) => value + " " + key.replaceAll("_", " ")).join(" / ");
  const filter = $("comparison-filter").value;
  $("comparison-list").replaceChildren();
  for (const [group, entries] of Object.entries(result.groups)) {
    if (filter && group !== filter) continue;
    for (const entry of entries) {
      const item = node("details", "comparison-item");
      const summary = node("summary");
      summary.append(badge(group), node("strong", "", (entry.after || entry.before).title), node("span", "mono", entry.id));
      const pair = node("div", "comparison-pair");
      for (const [label, finding] of [["Baseline", entry.before], ["Current", entry.after]]) {
        const side = node("section");
        side.append(node("h3", "", label));
        if (finding) side.append(badge(finding.severity), node("p", "", finding.title), node("p", "", finding.description), node("p", "", finding.recommendation));
        else side.append(node("p", "", "Not observed in this scan."));
        pair.append(side);
      }
      item.append(summary, pair);
      $("comparison-list").append(item);
    }
  }
  if (!$("comparison-list").childElementCount) $("comparison-list").append(node("p", "inline-empty", "No findings in this group."));
}
async function sync() {
  if (state.syncing) { state.again = true; return; }
  clearTimeout(state.timer);
  state.syncing = true;
  const version = state.version;
  const view = route();
  try {
    if (!state.token) {
      const session = await api("/api/session");
      state.token = session.token;
      state.deepSupported = Boolean(session.capabilities?.deep_scan);
    }
    const { scan: active } = await api("/api/scans/active");
    if (state.active && !active) announce("Scan finished. Results are available in scan history.");
    state.active = active;
    renderProgress(active);
    connection(true);
    let history;
    let scan;
    if (view.page === "history") {
      const params = new URLSearchParams({ limit: "10", offset: String(state.offset), query: state.historyQuery });
      if (state.historyStatus) params.set("status", state.historyStatus);
      history = await api("/api/scans?" + params);
    } else if (view.id) {
      if (!/^[0-9a-f-]{36}$/i.test(view.id)) {
        const failure = new Error("This scan link is invalid."); failure.status = 404; throw failure;
      }
      scan = await api("/api/scans/" + view.id);
    } else {
      const recent = await api("/api/scans?limit=1");
      scan = recent.items.length ? await api("/api/scans/" + recent.items[0].id) : null;
    }
    if (version === state.version) {
      $("loading").hidden = true;
      $("history-view").hidden = view.page !== "history";
      if (view.page === "history") {
        $("empty").hidden = true;
        $("detail-view").hidden = true;
        renderHistory(history);
      } else renderScan(scan);
      error(state.actionError);
      $("updated-at").textContent = "Updated " + new Date().toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
    }
  } catch (failure) {
    if (version === state.version) {
      error(failure.message);
      $("loading").hidden = true;
      if (!failure.status) connection(false);
      if (failure.status === 404) {
        $("detail-view").hidden = true;
        $("empty").hidden = true;
      }
    }
  } finally {
    state.syncing = false;
    icons();
    if (state.again) { state.again = false; sync(); }
    else state.timer = setTimeout(sync, state.active ? 1200 : 6000);
  }
}
function navigate() {
  state.version++;
  state.signature = "";
  state.scan = null;
  resetComparison();
  $("history-view").hidden = true;
  $("detail-view").hidden = true;
  $("empty").hidden = true;
  $("loading").hidden = false;
  $("finding-query").value = "";
  $("finding-severity").value = "";
  $("port-query").value = "";
  $("port-protocol").value = "";
  $("port-binding").value = "";
  tab("findings");
  showRoute();
  error("");
  sync();
}

$("run-scan").addEventListener("click", launch);
$("export-report").addEventListener("click", downloadReport);
$("export-sanitize").addEventListener("change", () => {
  $("export-note").textContent = $("export-sanitize").checked ? "Raw diagnostics omitted. Review before sharing." : "Full export contains sensitive host data.";
});
$("older-baselines").addEventListener("click", loadBaselines);
$("comparison-baseline").addEventListener("change", () => {
  $("compare-scans").disabled = !$("comparison-baseline").value;
  $("comparison-output").hidden = true;
});
$("compare-scans").addEventListener("click", compareScans);
$("comparison-filter").addEventListener("change", renderComparison);
$("scan-mode").addEventListener("change", buttons);
$("first-scan").addEventListener("click", launch);
$("retry").addEventListener("click", () => { state.actionError = ""; sync(); });
$("refresh-history").addEventListener("click", sync);
$("previous-page").addEventListener("click", () => { state.offset = Math.max(0, state.offset - 10); state.version++; sync(); });
$("next-page").addEventListener("click", () => { state.offset += 10; state.version++; sync(); });
let searchTimer;
$("history-query").addEventListener("input", () => {
  clearTimeout(searchTimer);
  state.version++;
  searchTimer = setTimeout(() => { state.historyQuery = $("history-query").value.trim(); state.offset = 0; sync(); }, 200);
});
$("history-status").addEventListener("change", () => { state.historyStatus = $("history-status").value; state.offset = 0; state.version++; sync(); });
["finding-query", "finding-severity", "finding-sort"].forEach((id) => {
  $(id).addEventListener(id === "finding-query" ? "input" : "change", renderFindings);
});
["port-query", "port-protocol", "port-binding"].forEach((id) => {
  $(id).addEventListener(id === "port-query" ? "input" : "change", renderPorts);
});
document.querySelectorAll("[data-tab]").forEach((button) => {
  button.addEventListener("click", () => tab(button.dataset.tab));
  button.addEventListener("keydown", (event) => {
    const names = ["findings", "ports", "host", "collection", "comparison"];
    let index = names.indexOf(button.dataset.tab);
    if (event.key === "ArrowRight") index = (index + 1) % names.length;
    else if (event.key === "ArrowLeft") index = (index + names.length - 1) % names.length;
    else if (event.key === "Home") index = 0;
    else if (event.key === "End") index = names.length - 1;
    else return;
    event.preventDefault();
    tab(names[index], true);
  });
});
window.addEventListener("hashchange", navigate);
window.addEventListener("online", sync);
document.addEventListener("visibilitychange", () => { if (!document.hidden) sync(); });
icons();
navigate();
