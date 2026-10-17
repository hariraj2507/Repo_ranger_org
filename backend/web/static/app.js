"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const state = { token: null, session: null, scans: [], selectedId: null, report: null, pollTimer: null, refreshing: false, submitting: false, selection: 0, visibleLimit: 40 };
  const riskLevels = ["critical", "high", "medium", "low"];
  const ruleNames = {
    aws_access_key_id: "AWS access key", github_token: "GitHub token", gitlab_token: "GitLab token",
    private_key_block: "Private key", high_entropy_token: "Potential credential", jwt: "JSON web token",
    private_jwk: "Private JSON web key", hardcoded_password: "Hardcoded password",
  };
  const number = (value) => Number.isFinite(Number(value)) ? Math.max(0, Number(value)) : 0;
  const text = (value, fallback = "") => value == null ? fallback : String(value);
  const titleCase = (value) => text(value).replace(/_/g, " ").replace(/^./, (character) => character.toUpperCase());
  const isPending = (scan) => scan && ["queued", "running"].includes(scan.status);
  const dateLabel = (value) => {
    if (!value) return "";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "" : date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
  };
  const sourceName = (source) => {
    const pieces = text(source).replace(/\.git\/?$/, "").replace(/[\\/]+$/, "").split(/[\\/]/);
    return pieces[pieces.length - 1] || text(source, "Repository");
  };
  const icon = (name) => {
    const element = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    element.classList.add("icon");
    element.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#icon-${name}`);
    element.append(use);
    return element;
  };
  const element = (tag, className, content) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (content != null) node.textContent = text(content);
    return node;
  };

  function setNotice(id, message) {
    $(id).textContent = message || "";
    $(id).hidden = !message;
  }

  function setConnection(connected, label) {
    $("connection-status").classList.toggle("offline", !connected);
    $("connection-label").textContent = label || (connected ? "Connected locally" : "Connection unavailable");
  }

  async function api(path, options = {}) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 15000);
    let response;
    try {
      response = await fetch(path, { credentials: "same-origin", cache: "no-store", ...options, signal: controller.signal });
      const payload = await response.json();
      if (!response.ok) {
        const error = new Error(payload.error?.message || `The request could not be completed (${response.status}).`);
        error.status = response.status;
        error.code = payload.error?.code;
        throw error;
      }
      setConnection(true);
      return payload;
    } catch (error) {
      if (error.name === "AbortError") throw new Error("The dashboard did not respond in time. Check that the server is running and try again.");
      if (!response) {
        setConnection(false);
        throw new Error("Cannot reach the local dashboard. Check that the server is running and try again.");
      }
      throw error;
    } finally {
      window.clearTimeout(timeout);
    }
  }

  function applySession(session) {
    state.session = session;
    state.token = session.token;
    $("allowed-root").textContent = text(session.allowed_root, "Current server folder");
    for (const [id, key, fallback] of [["max-commits", "max_commits", 500], ["max-blobs", "max_blobs", 10000]]) {
      const maximum = number(session.limits?.[key]) || fallback;
      $(id).max = text(maximum);
      $(id).value = text(Math.min(number($(id).value) || maximum, maximum));
    }
    $("start-scan").disabled = state.submitting;
  }

  function renderRecent() {
    const container = $("recent-scans");
    container.replaceChildren();
    $("recent-count").textContent = text(state.scans.length);
    if (!state.scans.length) {
      container.append(element("p", "sidebar-empty", "Your scans will appear here."));
      return;
    }
    for (const scan of state.scans) {
      const button = element("button", `recent-item${scan.id === state.selectedId ? " selected" : ""}`);
      button.type = "button";
      button.title = text(scan.source);
      button.setAttribute("aria-pressed", text(scan.id === state.selectedId));
      const top = element("span", "recent-item-top");
      const level = riskLevels.includes(scan.summary?.risk_level) ? scan.summary.risk_level : "low";
      const dot = element("span", `scan-dot ${scan.status === "complete" ? level : text(scan.status)}`);
      dot.setAttribute("aria-hidden", "true");
      top.append(dot, element("span", "recent-name", sourceName(scan.source)));
      let description = titleCase(scan.status);
      if (scan.status === "complete" && scan.summary) description = `${number(scan.summary.finding_count).toLocaleString()} findings`;
      const timestamp = dateLabel(scan.completed_at || scan.created_at);
      button.append(top, element("small", "", `${description}${timestamp ? ` · ${timestamp}` : ""}`));
      button.addEventListener("click", () => selectScan(scan.id));
      container.append(button);
    }
  }

  function resetReport() {
    state.report = null;
    state.visibleLimit = 40;
    $("report-content").hidden = true;
    $("download-report").hidden = true;
    $("report-time").textContent = "";
    $("empty-report").hidden = false;
    $("findings-list").replaceChildren();
    $("finding-search").value = "";
    $("risk-filter").value = "all";
    $("scope-filter").value = "all";
    setNotice("coverage-warning", "");
  }

  function showEmpty(title, description, showAction = true) {
    $("empty-report").querySelector("h3").textContent = title;
    $("empty-report").querySelector("p").textContent = description;
    $("empty-start").hidden = !showAction;
  }

  function displayScan(scan) {
    $("report-source").textContent = text(scan.source);
    $("scan-status").hidden = !isPending(scan);
    setNotice("scan-error", "");
    if (isPending(scan)) {
      $("scan-status-title").textContent = scan.status === "queued" ? "Your scan is queued" : "Reviewing your repository";
      $("scan-status-description").textContent = scan.status === "queued" ? "The scan will start as soon as a scanning slot is available." : scan.history ? "Checking current files and Git history. Larger repositories can take a little longer." : "Checking repository files for potential credentials. Your report will appear here when ready.";
      showEmpty("Your report is on its way.", "You can leave this page open while RepoRanger reviews the repository.", false);
    } else if (scan.status === "failed") {
      showEmpty("The scan could not finish.", "Check the repository source and start a new scan to try again.");
      setNotice("scan-error", text(scan.error?.message || scan.error, "The repository could not be scanned. Please try again."));
    }
    if (scan.status === "complete" && scan.report) renderReport(scan);
  }

  async function loadSelected() {
    const id = state.selectedId;
    const selection = state.selection;
    if (!id) return;
    try {
      const scan = await api(`/api/scans/${encodeURIComponent(id)}`);
      if (selection !== state.selection || id !== state.selectedId) return;
      const index = state.scans.findIndex((item) => item.id === id);
      if (index >= 0) state.scans[index] = scan;
      displayScan(scan);
      renderRecent();
    } catch (error) {
      if (selection === state.selection) setNotice("scan-error", error.message);
    }
  }

  async function selectScan(id) {
    if (id === state.selectedId && state.report) return;
    state.selectedId = id;
    state.selection += 1;
    resetReport();
    const scan = state.scans.find((item) => item.id === id);
    if (scan) displayScan(scan);
    renderRecent();
    await loadSelected();
    scheduleRefresh();
  }

  function scheduleRefresh() {
    window.clearTimeout(state.pollTimer);
    state.pollTimer = null;
    if (state.scans.some(isPending)) state.pollTimer = window.setTimeout(refreshScans, 1800);
  }

  async function refreshScans() {
    if (state.refreshing) return;
    state.refreshing = true;
    try {
      const payload = await api("/api/scans");
      state.scans = Array.isArray(payload.scans) ? payload.scans : [];
      renderRecent();
      const selected = state.scans.find((scan) => scan.id === state.selectedId);
      if (selected && !state.report) await loadSelected();
      if (!selected && state.selectedId) {
        state.selectedId = null;
        state.selection += 1;
        resetReport();
        $("scan-status").hidden = true;
        $("report-source").textContent = "Choose a recent scan or start a new one.";
        showEmpty("This scan is no longer available.", "Results are kept for this server session, with a limited number of recent scans.");
        renderRecent();
      }
    } catch (error) {
      setConnection(false, "Reconnecting…");
      if (!state.report) setNotice("scan-error", error.message);
    } finally {
      state.refreshing = false;
      scheduleRefresh();
    }
  }

  function newScan() {
    state.selectedId = null;
    state.selection += 1;
    resetReport();
    $("scan-status").hidden = true;
    $("report-source").textContent = "Start a scan to see what needs your attention.";
    showEmpty("A good place to start.", "Choose a repository above. Your report will bring potential credentials, their locations, and review context together.");
    setNotice("form-error", "");
    setNotice("scan-error", "");
    renderRecent();
    $("source").focus();
    $("source").select();
    $("scan-heading").scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "center" });
  }

  async function submitScan(event) {
    event.preventDefault();
    if (state.submitting || !$("scan-form").reportValidity()) return;
    setNotice("form-error", "");
    const source = $("source").value.trim();
    if (!source) {
      setNotice("form-error", "Enter a local repository path or a public GitHub URL.");
      $("source").focus();
      return;
    }
    state.submitting = true;
    $("start-scan").disabled = true;
    $("start-label").textContent = "Starting…";
    const request = () => api("/api/scans", {
      method: "POST", headers: { "Content-Type": "application/json", "X-RepoRanger-Token": state.token },
      body: JSON.stringify({ source, history: $("include-history").checked, max_commits: Number($("max-commits").value), max_blobs: Number($("max-blobs").value) }),
    });
    try {
      if (!state.token) applySession(await api("/api/session"));
      let scan;
      try { scan = await request(); }
      catch (error) {
        if (error.status !== 403 || !["invalid_token", "csrf_failed", "invalid_session"].includes(error.code)) throw error;
        applySession(await api("/api/session"));
        scan = await request();
      }
      state.scans = [scan, ...state.scans.filter((item) => item.id !== scan.id)];
      await selectScan(scan.id);
    } catch (error) {
      setNotice("form-error", error.message);
    } finally {
      state.submitting = false;
      $("start-scan").disabled = false;
      $("start-label").textContent = "Start scan";
    }
  }

  function renderCoverage(report) {
    const scan = report.scan || {};
    const skipped = scan.skipped_files && typeof scan.skipped_files === "object" ? scan.skipped_files : {};
    const history = scan.history && typeof scan.history === "object" ? Object.values(scan.history) : [];
    const commits = history.reduce((total, stats) => total + number(stats.commits_scanned), 0);
    const blobs = history.reduce((total, stats) => total + number(stats.blobs_scanned), 0);
    const blobSkips = history.reduce((total, stats) => total + number(stats.blobs_skipped), 0);
    $("files-scanned").textContent = number(scan.files_scanned).toLocaleString();
    $("files-skipped").textContent = Object.values(skipped).reduce((total, count) => total + number(count), 0).toLocaleString();
    $("history-summary").textContent = history.length ? `${commits.toLocaleString()} commits · ${blobs.toLocaleString()} file revisions reviewed` : "Current files only · Git history not included";
    const details = $("coverage-detail-content");
    details.replaceChildren();
    for (const [reason, count] of Object.entries(skipped)) if (number(count)) details.append(element("p", "", `${titleCase(reason)}: ${number(count).toLocaleString()} files`));
    if (blobSkips) details.append(element("p", "", `Skipped historical file revisions: ${blobSkips.toLocaleString()}`));
    if (number(scan.suppressed_findings)) details.append(element("p", "", `Findings excluded by scan policy: ${number(scan.suppressed_findings).toLocaleString()}`));
    $("coverage-details").hidden = !details.childElementCount;
    const incomplete = scan.incomplete || history.some((stats) => stats.incomplete || stats.truncated || stats.shallow);
    const warnings = Array.isArray(scan.warnings) ? scan.warnings.filter((warning) => typeof warning === "string") : [];
    const message = incomplete ? "Git history coverage is incomplete. Scan limits, unavailable file revisions, or a shallow checkout may have prevented a full review." : "";
    setNotice("coverage-warning", [message, ...warnings].filter(Boolean).join(" "));
  }

  function renderReport(scan) {
    const report = scan.report;
    if (!report || !Array.isArray(report.findings) || !report.summary) {
      setNotice("scan-error", "This scan returned an unreadable report. Start a new scan to try again.");
      return;
    }
    state.report = report;
    $("empty-report").hidden = true;
    $("report-content").hidden = false;
    $("scan-status").hidden = true;
    const level = riskLevels.includes(report.summary.risk_level) ? report.summary.risk_level : "low";
    const score = Math.min(100, number(report.summary.score));
    $("risk-level").textContent = titleCase(level);
    $("risk-level").className = `badge ${level}`;
    $("risk-score").textContent = text(score);
    $("score-fill").style.width = `${score}%`;
    $("score-fill").className = level;
    $("score-explanation").textContent = report.findings.length ? "Based on the strongest finding." : "No findings detected in this scan.";
    $("finding-count").textContent = number(report.summary.finding_count ?? report.findings.length).toLocaleString();
    const affectedFiles = new Set(report.findings.map((finding) => finding.file_path)).size;
    $("finding-description").textContent = affectedFiles ? `Across ${affectedFiles.toLocaleString()} ${affectedFiles === 1 ? "file" : "files"}` : "Across the scanned repository";
    for (const risk of riskLevels) $(`${risk}-count`).textContent = number(report.summary.risk_counts?.[risk]).toLocaleString();
    $("report-time").textContent = `Completed ${dateLabel(scan.completed_at || report.generated_at)}`;
    $("report-source").textContent = text(report.repository_source || scan.source);
    $("download-report").href = `/api/scans/${encodeURIComponent(scan.id)}/report`;
    $("download-report").download = `reporanger-${scan.id}.json`;
    $("download-report").setAttribute("aria-label", `Download redacted JSON report for ${sourceName(scan.source)}`);
    $("download-report").hidden = false;
    $("announcer").textContent = `Scan complete for ${sourceName(scan.source)}. ${number(report.summary.finding_count ?? report.findings.length)} potential findings. ${titleCase(level)} review priority.`;
    renderCoverage(report);
    renderFindings();
  }

  function detailGroup(heading, values, className = "") {
    const group = element("div", `detail-group ${className}`);
    group.append(element("h4", "", heading));
    if (Array.isArray(values)) {
      const list = element("ul");
      for (const value of values) list.append(element("li", "", value));
      group.append(list);
    } else group.append(element("p", "", values));
    return group;
  }

  function recommendation(finding) {
    if (finding.recommendation) return text(finding.recommendation);
    if (finding.rule_id === "jwt") return "Check whether this is a real authentication token and whether it can still grant access. If exposed, revoke its session or token and remove it from tracked files.";
    return "Confirm whether this value is a real credential. If exposed, revoke or rotate it with the provider, remove it from tracked files, and use an environment variable or a secret manager. Historical copies may still need attention.";
  }

  function findingElement(finding) {
    const details = element("details", "finding-item");
    const summary = element("summary", "finding-row");
    const level = riskLevels.includes(finding.risk_level) ? finding.risk_level : "low";
    summary.append(element("span", `badge ${level}`, titleCase(level)));
    const identity = element("div", "finding-identity");
    const name = ruleNames[finding.rule_id] || titleCase(finding.rule_id) || titleCase(finding.category) || "Potential credential";
    const heading = element("div", "finding-title", name);
    if (finding.history) heading.append(element("span", "source-badge", "History"));
    const firstLine = number(finding.line_start);
    const lastLine = number(finding.line_end);
    const location = `${text(finding.file_path, "Unknown file")}${firstLine ? `:${firstLine}${lastLine > firstLine ? `–${lastLine}` : ""}` : ""}`;
    identity.append(heading, element("div", "finding-location", location));
    summary.append(identity, element("span", "confidence-label", `${titleCase(finding.confidence || "unknown")} confidence`), icon("chevron"));
    details.append(summary);
    const content = element("div", "finding-detail");
    const previewLabel = element("div", "preview-label");
    previewLabel.append(element("span", "", "REDACTED PREVIEW"), element("span", "", "Credential values are hidden"));
    content.append(previewLabel, element("pre", "redacted-preview", text(finding.preview, "Preview unavailable")));
    const grid = element("div", "finding-details-grid");
    const rationale = Array.isArray(finding.rationale) ? finding.rationale : [];
    grid.append(detailGroup("Why it was flagged", rationale.length ? rationale : "A credential pattern or suspicious literal matched this location."));
    const confidence = Array.isArray(finding.confidence_rationale) ? finding.confidence_rationale : [];
    grid.append(detailGroup("Confidence assessment", confidence.length ? confidence : `${titleCase(finding.confidence || "unknown")} confidence. Review the surrounding code to confirm the finding.`));
    if (finding.validation && typeof finding.validation === "object") {
      const validation = finding.validation;
      const description = `${text(validation.provider, "Credential")} · ${validation.format_valid === true ? "Format matches" : validation.format_valid === false ? "Format check did not pass" : "Format check unavailable"}. This is an offline check; live validity has not been verified.`;
      const group = detailGroup("Offline validation", description);
      if (Array.isArray(validation.reasons) && validation.reasons.length) {
        const list = element("ul");
        for (const reason of validation.reasons) list.append(element("li", "", reason));
        group.append(list);
      }
      grid.append(group);
    } else grid.append(detailGroup("Offline validation", "No provider-specific format check is available for this finding. Live validity has not been verified."));
    if (finding.context && typeof finding.context === "object") {
      const context = finding.context;
      const description = [titleCase(context.language), titleCase(context.symbol_kind)].filter(Boolean).join(" · ");
      const group = detailGroup("Code context", description || "Source context was available for scoring.");
      if (Array.isArray(context.evidence) && context.evidence.length) {
        const list = element("ul");
        for (const evidence of context.evidence) list.append(element("li", "", evidence));
        group.append(list);
      }
      grid.append(group);
    }
    if (finding.history && typeof finding.history === "object") grid.append(detailGroup("Historical location", `Commit ${text(finding.history.commit_id, "unknown")} · ${titleCase(finding.history.source_kind || "Git history")}`, "wide history-location"));
    const rule = detailGroup("Detection rule", text(finding.rule_id));
    rule.querySelector("p").classList.add("rule-id");
    if (finding.category) rule.append(element("p", "", `Category: ${titleCase(finding.category)}`));
    grid.append(rule, detailGroup("Recommended next step", recommendation(finding), "wide"));
    content.append(grid);
    details.append(content);
    return details;
  }

  function renderFindings() {
    if (!state.report) return;
    const query = $("finding-search").value.trim().toLowerCase();
    const risk = $("risk-filter").value;
    const scope = $("scope-filter").value;
    const filtered = state.report.findings.filter((finding) => {
      if (risk !== "all" && finding.risk_level !== risk) return false;
      if (scope === "current" && finding.history) return false;
      if (scope === "history" && !finding.history) return false;
      if (!query) return true;
      return [finding.file_path, finding.rule_id, finding.category, ruleNames[finding.rule_id], finding.preview].some((value) => text(value).toLowerCase().includes(query));
    }).sort((a, b) => number(b.risk_score) - number(a.risk_score));
    const visible = filtered.slice(0, state.visibleLimit);
    $("visible-count").textContent = filtered.length.toLocaleString();
    $("clear-filters").hidden = !query && risk === "all" && scope === "all";
    const fragment = document.createDocumentFragment();
    for (const finding of visible) fragment.append(findingElement(finding));
    $("findings-list").replaceChildren(fragment);
    $("findings-empty").hidden = filtered.length > 0;
    if (!state.report.findings.length) {
      $("findings-empty-title").textContent = "No findings detected";
      $("findings-empty-text").textContent = "A clean scan is a useful signal, but does not guarantee that every credential has been found.";
    } else {
      $("findings-empty-title").textContent = "No findings match these filters";
      $("findings-empty-text").textContent = "Try a different search or clear the filters to see all findings.";
    }
    $("finding-pagination").hidden = filtered.length <= state.visibleLimit;
    $("finding-page-label").textContent = `Showing ${visible.length.toLocaleString()} of ${filtered.length.toLocaleString()} findings`;
  }

  function updateFilters() { state.visibleLimit = 40; renderFindings(); }

  async function init() {
    $("start-scan").disabled = true;
    $("scan-form").addEventListener("submit", submitScan);
    $("new-scan").addEventListener("click", newScan);
    $("empty-start").addEventListener("click", newScan);
    $("finding-search").addEventListener("input", updateFilters);
    $("risk-filter").addEventListener("change", updateFilters);
    $("scope-filter").addEventListener("change", updateFilters);
    $("clear-filters").addEventListener("click", () => {
      $("finding-search").value = "";
      $("risk-filter").value = "all";
      $("scope-filter").value = "all";
      updateFilters();
      $("finding-search").focus();
    });
    $("load-more").addEventListener("click", () => { state.visibleLimit += 40; renderFindings(); });
    window.addEventListener("focus", () => { if (!state.submitting) refreshScans(); });
    try {
      const [session, scans] = await Promise.all([api("/api/session"), api("/api/scans")]);
      applySession(session);
      state.scans = Array.isArray(scans.scans) ? scans.scans : [];
      renderRecent();
      if (state.scans.length) await selectScan(state.scans[0].id);
      scheduleRefresh();
    } catch (error) {
      $("allowed-root").textContent = "Unavailable while the server is disconnected";
      $("start-scan").disabled = false;
      setNotice("form-error", error.message);
    }
  }

  init();
})();
