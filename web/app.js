// ============================================================
// FireGod-ESP — WebUI client
// Opens a WebSocket to /ws, sends command JSON, renders events.
// ============================================================
(function () {
  "use strict";

  var ws = null;
  var reconnectTimer = null;
  var rowCount = 0;
  var activeColumns = null; // current table schema (event type)
  var rowIndex = {};        // upsert lookup: key -> <tr> for keyed event types

  // --- DOM refs ---
  var el = function (id) { return document.getElementById(id); };
  var connDot = el("connDot"), connText = el("connText");
  var statHeap = el("statHeap"), statUptime = el("statUptime");
  var statModule = el("statModule"), statState = el("statState");
  var version = el("version");
  var head = el("resultsHead"), body = el("resultsBody");
  var emptyHint = el("emptyHint"), rowCountEl = el("rowCount");
  var logPane = el("logPane");

  // --- Column schemas per event type ---
  var SCHEMAS = {
    ap: [
      { key: "ssid", label: "SSID" },
      { key: "bssid", label: "BSSID" },
      { key: "rssi", label: "RSSI", render: rssiCell },
      { key: "ch", label: "CH" },
      { key: "enc", label: "Enc", render: encCell },
      { key: "vendor", label: "Vendor" }
    ],
    host: [
      { key: "ip", label: "IP" },
      { key: "mac", label: "MAC" },
      { key: "vendor", label: "Vendor" }
    ],
    client: [
      { key: "ip", label: "IP" },
      { key: "mac", label: "MAC" },
      { key: "vendor", label: "Vendor" }
    ],
    sniff_dev: [
      { key: "mac", label: "MAC" },
      { key: "ap", label: "Type", render: typeCell },
      { key: "ssid", label: "SSID" },
      { key: "rssi", label: "RSSI", render: rssiCell },
      { key: "ch", label: "CH" },
      { key: "frames", label: "Frames" },
      { key: "vendor", label: "Vendor" }
    ]
  };

  // Events that upsert rows keyed by a field (update-in-place), not append.
  var UPSERT_KEY = { sniff_dev: "mac" };

  function typeCell(v) {
    return v === true || v === "true"
      ? '<span class="rssi-strong">AP</span>'
      : '<span class="log-info">STA</span>';
  }

  function rssiCell(v) {
    var n = parseInt(v, 10);
    var cls = n >= -60 ? "rssi-strong" : (n >= -75 ? "rssi-mid" : "rssi-weak");
    return '<span class="' + cls + '">' + esc(v) + "</span>";
  }
  function encCell(v) {
    var cls = (v === "OPEN") ? "enc-open" : "";
    return cls ? '<span class="' + cls + '">' + esc(v) + "</span>" : esc(v);
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  // ---------------- WebSocket ----------------
  function connect() {
    var url = "ws://" + location.host + "/ws";
    log("Connecting to " + url, "info");
    ws = new WebSocket(url);

    ws.onopen = function () {
      setConn(true);
      send({ cmd: "status" });
    };
    ws.onclose = function () {
      setConn(false);
      scheduleReconnect();
    };
    ws.onerror = function () { try { ws.close(); } catch (e) {} };
    ws.onmessage = function (ev) { handleMessage(ev.data); };
  }

  function scheduleReconnect() {
    if (reconnectTimer) return;
    reconnectTimer = setTimeout(function () {
      reconnectTimer = null;
      connect();
    }, 1500);
  }

  function setConn(ok) {
    connDot.classList.toggle("on", ok);
    connText.textContent = ok ? "connected" : "disconnected";
  }

  function send(obj) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      log("Not connected — command dropped", "error");
      return;
    }
    ws.send(JSON.stringify(obj));
  }

  // ---------------- Event handling ----------------
  function handleMessage(raw) {
    var msg;
    try { msg = JSON.parse(raw); }
    catch (e) { log("Bad JSON from device: " + raw, "error"); return; }

    switch (msg.event) {
      case "status": return onStatus(msg);
      case "log":    return log(msg.msg, "info");
      case "error":  return log(msg.msg, "error");
      case "scan_complete":
        return log("Scan complete (" + (msg.type || "?") + "): " +
                   (msg.count != null ? msg.count : "?") + " result(s)", "ok");
      case "sniff_stats":
        return onSniffStats(msg);
      default:
        if (SCHEMAS[msg.event]) addRow(msg.event, msg);
        else log(raw, "info");
    }
  }

  function onSniffStats(m) {
    statModule.textContent = "sniffer ch" + m.ch;
    statState.textContent =
      m.pkts + " pkt / " + m.devices + " dev";
    log("ch" + m.ch + "  pkts=" + m.pkts + " mgmt=" + m.mgmt +
        " data=" + m.data + " beacons=" + m.beacons +
        " deauth=" + m.deauth + " eapol=" + m.eapol,
        m.deauth > 0 ? "warn" : "info");
  }

  function onStatus(msg) {
    if (msg.heap != null) statHeap.textContent = fmtBytes(msg.heap);
    if (msg.uptime != null) statUptime.textContent = fmtUptime(msg.uptime);
    if (msg.version) version.textContent = "v" + msg.version;
    if (msg.module != null) statModule.textContent = msg.module;
    if (msg.state != null) statState.textContent = msg.state;
  }

  function fmtBytes(b) {
    b = Number(b);
    return b >= 1024 ? (b / 1024).toFixed(1) + " KB" : b + " B";
  }
  function fmtUptime(s) {
    s = Number(s);
    var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return (h ? h + "h " : "") + (m ? m + "m " : "") + sec + "s";
  }

  // ---------------- Results table ----------------
  function ensureSchema(type) {
    if (activeColumns === type) return;
    activeColumns = type;
    rowCount = 0;
    rowIndex = {};
    body.innerHTML = "";
    var cols = SCHEMAS[type];
    head.innerHTML = "<tr>" + cols.map(function (c) {
      return "<th>" + esc(c.label) + "</th>";
    }).join("") + "</tr>";
  }

  function rowHtml(cols, msg) {
    return cols.map(function (c) {
      var v = msg[c.key];
      return "<td>" + (c.render ? c.render(v) : esc(v)) + "</td>";
    }).join("");
  }

  function addRow(type, msg) {
    ensureSchema(type);
    emptyHint.classList.add("hidden");
    var cols = SCHEMAS[type];
    var upsertKey = UPSERT_KEY[type];

    // Update-in-place for keyed event types (e.g. sniffer devices by MAC).
    if (upsertKey && msg[upsertKey] != null) {
      var id = String(msg[upsertKey]);
      var existing = rowIndex[id];
      if (existing) {
        existing.innerHTML = rowHtml(cols, msg);
        return;
      }
      var tr2 = document.createElement("tr");
      tr2.innerHTML = rowHtml(cols, msg);
      body.appendChild(tr2);
      rowIndex[id] = tr2;
      rowCount++;
      rowCountEl.textContent = rowCount;
      return; // don't auto-scroll: keeps the live table stable
    }

    var tr = document.createElement("tr");
    tr.innerHTML = rowHtml(cols, msg);
    body.appendChild(tr);
    rowCount++;
    rowCountEl.textContent = rowCount;
    autoScroll(body.parentElement.parentElement);
  }

  function clearResults() {
    body.innerHTML = "";
    head.innerHTML = "";
    activeColumns = null;
    rowIndex = {};
    rowCount = 0;
    rowCountEl.textContent = "0";
    emptyHint.classList.remove("hidden");
  }

  // ---------------- Log pane ----------------
  function log(text, kind) {
    var line = document.createElement("div");
    line.className = "log-" + (kind || "info");
    line.textContent = "[" + new Date().toLocaleTimeString() + "] " + text;
    logPane.appendChild(line);
    while (logPane.childNodes.length > 500) logPane.removeChild(logPane.firstChild);
    autoScroll(logPane);
  }

  function autoScroll(node) {
    // Only stick to bottom if user is already near the bottom.
    if (node.scrollHeight - node.scrollTop - node.clientHeight < 80) {
      node.scrollTop = node.scrollHeight;
    }
  }

  // ---------------- UI wiring ----------------
  document.querySelectorAll(".btn[data-cmd]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var cmd = btn.getAttribute("data-cmd");
      var payload = { cmd: cmd };
      if (btn.hasAttribute("data-needs-creds")) {
        var ssid = el("ssid").value.trim();
        var pass = el("pass").value;
        if (!ssid) { log("Enter a target SSID first", "warn"); return; }
        payload.ssid = ssid;
        payload.pass = pass;
      }
      send(payload);
    });
  });

  el("clearBtn").addEventListener("click", clearResults);

  document.querySelectorAll(".tab").forEach(function (tab) {
    tab.addEventListener("click", function () {
      document.querySelectorAll(".tab").forEach(function (t) { t.classList.remove("active"); });
      tab.classList.add("active");
      var name = tab.getAttribute("data-tab");
      el("view-table").classList.toggle("hidden", name !== "table");
      el("view-log").classList.toggle("hidden", name !== "log");
    });
  });

  connect();
})();
