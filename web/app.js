// ============================================================
// FireGod-ESP — WebUI client (modular card-launcher)
// One WebSocket; events routed to each tool's own results table.
// ============================================================
(function () {
  "use strict";

  var ws = null, reconnectTimer = null, statusTimer = null;

  var el = function (id) { return document.getElementById(id); };
  var connDot = el("connDot"), connText = el("connText");
  var statHeap = el("statHeap"), statUptime = el("statUptime"), statModule = el("statModule");
  var version = el("version"), globalStop = el("globalStop");
  var logPane = el("logPane");

  // ---------------- Column schemas ----------------
  var SCHEMAS = {
    ap: [
      { key: "ssid", label: "SSID" }, { key: "bssid", label: "BSSID" },
      { key: "rssi", label: "RSSI", render: rssiCell }, { key: "ch", label: "CH" },
      { key: "enc", label: "Enc", render: encCell }, { key: "vendor", label: "Vendor" }
    ],
    host:   [ { key: "ip", label: "IP" }, { key: "mac", label: "MAC" }, { key: "vendor", label: "Vendor" } ],
    client: [ { key: "ip", label: "IP" }, { key: "mac", label: "MAC" }, { key: "vendor", label: "Vendor" } ],
    sniff_dev: [
      { key: "mac", label: "MAC" }, { key: "ap", label: "Type", render: typeCell },
      { key: "ssid", label: "SSID" }, { key: "rssi", label: "RSSI", render: rssiCell },
      { key: "ch", label: "CH" }, { key: "frames", label: "Frames" }, { key: "vendor", label: "Vendor" }
    ],
    ble_dev: [
      { key: "addr", label: "Address" }, { key: "name", label: "Name" },
      { key: "rssi", label: "RSSI", render: rssiCell }, { key: "appear", label: "Appearance" }
    ],
    creds: [ { key: "portal", label: "Portal" }, { key: "user", label: "User" }, { key: "pass", label: "Password" } ],
    karma: [ { key: "ssid", label: "Probed SSID" }, { key: "mac", label: "Client MAC" } ],
    mitm: [
      { key: "ip", label: "Client" }, { key: "type", label: "Proto", render: protoCell },
      { key: "host", label: "Host" }, { key: "detail", label: "Detail" }
    ]
  };
  var UPSERT_KEY = { sniff_dev: "mac", ble_dev: "addr" };

  // ---------------- Cell renderers ----------------
  function protoCell(v) {
    if (v === "HTTP") return '<span class="rssi-weak">HTTP</span>';
    if (v === "TGT") return '<span class="tag">TGT</span>';
    return '<span class="log-info">DNS</span>';
  }
  function typeCell(v) {
    return (v === true || v === "true")
      ? '<span class="rssi-strong">AP</span>' : '<span class="log-info">STA</span>';
  }
  function rssiCell(v) {
    var n = parseInt(v, 10);
    var cls = n >= -60 ? "rssi-strong" : (n >= -75 ? "rssi-mid" : "rssi-weak");
    return '<span class="' + cls + '">' + esc(v) + "</span>";
  }
  function encCell(v) {
    return (v === "OPEN") ? '<span class="enc-open">' + esc(v) + "</span>" : esc(v);
  }
  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  // ---------------- Results table factory ----------------
  function Table(headId, bodyId, emptyId) {
    var head = el(headId), body = el(bodyId), empty = el(emptyId);
    var schema = null, rowIndex = {};
    function ensure(type) {
      if (schema === type) return;
      schema = type; rowIndex = {}; body.innerHTML = "";
      head.innerHTML = "<tr>" + SCHEMAS[type].map(function (c) {
        return "<th>" + esc(c.label) + "</th>";
      }).join("") + "</tr>";
    }
    function rowHtml(cols, msg) {
      return cols.map(function (c) {
        var v = msg[c.key];
        return "<td>" + (c.render ? c.render(v) : esc(v)) + "</td>";
      }).join("");
    }
    return {
      add: function (type, msg) {
        ensure(type);
        if (empty) empty.classList.add("hidden");
        var cols = SCHEMAS[type], key = UPSERT_KEY[type];
        if (key && msg[key] != null) {
          var id = String(msg[key]), ex = rowIndex[id];
          if (ex) { ex.innerHTML = rowHtml(cols, msg); return; }
          var trU = document.createElement("tr"); trU.innerHTML = rowHtml(cols, msg);
          body.appendChild(trU); rowIndex[id] = trU; return;
        }
        var tr = document.createElement("tr"); tr.innerHTML = rowHtml(cols, msg);
        body.appendChild(tr);
        stick(body.closest(".results"));
      },
      clear: function () {
        body.innerHTML = ""; head.innerHTML = ""; schema = null; rowIndex = {};
        if (empty) empty.classList.remove("hidden");
      }
    };
  }

  var tables = {
    recon:   Table("reconHead", "reconBody", "reconEmpty"),
    attacks: Table("attacksHead", "attacksBody", "attacksEmpty"),
    mitm:    Table("mitmHead", "mitmBody", "mitmEmpty"),
    ble:     Table("bleHead", "bleBody", "bleEmpty")
  };

  function setStrip(id, text) { var n = el(id); if (n) n.textContent = text; }
  function stick(node) {
    if (!node) return;
    if (node.scrollHeight - node.scrollTop - node.clientHeight < 90) node.scrollTop = node.scrollHeight;
  }

  // ---------------- WebSocket ----------------
  function connect() {
    var url = "ws://" + location.host + "/ws";
    log("Connecting to " + url, "info");
    ws = new WebSocket(url);
    ws.onopen = function () { setConn(true); send({ cmd: "status" }); };
    ws.onclose = function () { setConn(false); scheduleReconnect(); };
    ws.onerror = function () { try { ws.close(); } catch (e) {} };
    ws.onmessage = function (ev) { handleMessage(ev.data); };
  }
  function scheduleReconnect() {
    if (reconnectTimer) return;
    reconnectTimer = setTimeout(function () { reconnectTimer = null; connect(); }, 1500);
  }
  function setConn(ok) {
    connDot.classList.toggle("on", ok);
    connText.textContent = ok ? "online" : "offline";
    var bc = el("bigConn"); if (bc) bc.textContent = ok ? "online" : "offline";
  }
  function send(obj) {
    if (!ws || ws.readyState !== WebSocket.OPEN) { log("Not connected — command dropped", "error"); return; }
    ws.send(JSON.stringify(obj));
  }

  // ---------------- Event routing ----------------
  function handleMessage(raw) {
    var msg;
    try { msg = JSON.parse(raw); } catch (e) { log("Bad JSON: " + raw, "error"); return; }
    switch (msg.event) {
      case "status": return onStatus(msg);
      case "log":    return log(msg.msg, "info");
      case "error":  return log(msg.msg, "error");
      case "scan_complete":
        return log("Complete (" + (msg.type || "?") + "): " + (msg.count != null ? msg.count : "?") + " result(s)", "ok");
      case "ap": case "host": case "client": case "sniff_dev":
        return tables.recon.add(msg.event, msg);
      case "sniff_stats":
        setStrip("sniffStat", "ch" + msg.ch + "  " + msg.pkts + " pkt / " + msg.devices + " dev  (deauth " + msg.deauth + ")");
        statModule.textContent = "sniffer";
        log("ch" + msg.ch + " pkts=" + msg.pkts + " beacons=" + msg.beacons + " deauth=" + msg.deauth + " eapol=" + msg.eapol, msg.deauth > 0 ? "warn" : "info");
        return;
      case "creds":
        log("CREDS @" + msg.portal + " -> " + msg.user + " : " + msg.pass, "warn");
        return tables.attacks.add("creds", msg);
      case "spam_stats": {
        var t = msg.type || "spam";
        var s = t + ": " + (msg.sent != null ? msg.sent : 0) + " sent";
        if (msg.seen != null) s += " / " + msg.seen + " seen";
        if (msg.ch != null) s += " · ch" + msg.ch;
        if (msg.mode) s += " · " + msg.mode;
        statModule.textContent = t;
        setStrip(t === "ble" ? "bleStat" : "atkStat", s);
        return;
      }
      case "karma":
        log("KARMA probe '" + msg.ssid + "' from " + msg.mac, "info");
        return tables.attacks.add("karma", msg);
      case "ble_threat":
        setStrip("bleStat", "THREAT " + msg.proto + " · " + msg.distinct_macs +
          " rotating MACs · " + msg.severity);
        log("BLE SPAM THREAT: " + msg.proto + " — " + msg.distinct_macs +
          " rotating MACs in " + msg.window_ms + "ms (" + msg.severity + ")", "warn");
        return;
      case "ble_detect_stats":
        setStrip("bleStat", "detect " + msg.secs + "s · adverts " + msg.adverts +
          " · apple " + msg.apple + " swift " + msg.swiftpair + " fast " + msg.fastpair);
        statModule.textContent = "ble detect"; return;
      case "ble_dev": return tables.ble.add("ble_dev", msg);
      case "ble_stats":
        setStrip("bleStat", msg.seen + " seen / " + msg.secs + "s");
        statModule.textContent = "ble scan"; return;
      case "mitm_stats":
        setStrip("mitmStat", msg.victims + " target(s) / " + msg.fwd + " frames fwd");
        statModule.textContent = "mitm"; return;
      case "mitm_target":
        return tables.mitm.add("mitm", { ip: msg.ip, type: "TGT", host: msg.mac, detail: msg.vendor || "" });
      case "mitm_dns":
        log("DNS " + msg.ip + " -> " + msg.host, "info");
        return tables.mitm.add("mitm", { ip: msg.ip, type: "DNS", host: msg.host, detail: "" });
      case "mitm_http":
        var d = (msg.req || "") + (msg.data ? "  [" + msg.data + "]" : "");
        log((msg.data ? "HTTP POST " : "HTTP ") + msg.ip + "  " + (msg.host || "") + "  " + d, msg.data ? "warn" : "info");
        return tables.mitm.add("mitm", { ip: msg.ip, type: "HTTP", host: msg.host, detail: d });
      default:
        if (SCHEMAS[msg.event]) return; // unknown keyed event, ignore
        log(raw, "info");
    }
  }

  function onStatus(msg) {
    if (msg.heap != null) { var h = fmtBytes(msg.heap); statHeap.textContent = h; setBig("bigHeap", h); }
    if (msg.uptime != null) { var u = fmtUptime(msg.uptime); statUptime.textContent = u; setBig("bigUptime", u); }
    if (msg.version) { version.textContent = "v" + msg.version; setBig("bigVer", "v" + msg.version); }
    var st = String(msg.state);
    var busy = (st === "busy") || (/^\d+$/.test(st) && st !== "0");
    toggleStop(busy);
    setBig("bigState", busy ? "busy" : "idle");
    if (!busy) { statModule.textContent = "idle"; setBig("bigModule", "idle"); }
    else setBig("bigModule", statModule.textContent || "busy");
  }
  function setBig(id, v) { var n = el(id); if (n) n.textContent = v; }
  function toggleStop(show) { globalStop.classList.toggle("hidden", !show); }

  function fmtBytes(b) { b = Number(b); return b >= 1024 ? (b / 1024).toFixed(1) + " KB" : b + " B"; }
  function fmtUptime(s) {
    s = Number(s);
    var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return (h ? h + "h " : "") + (m ? m + "m " : "") + sec + "s";
  }

  // ---------------- Log ----------------
  function log(text, kind) {
    var line = document.createElement("div");
    line.className = "log-" + (kind || "info");
    line.textContent = "[" + new Date().toLocaleTimeString() + "] " + text;
    logPane.appendChild(line);
    while (logPane.childNodes.length > 600) logPane.removeChild(logPane.firstChild);
    stick(logPane);
  }

  // ---------------- Inputs / payloads ----------------
  function numVal(id) { var v = parseInt((el(id) && el(id).value) || "", 10); return isNaN(v) ? null : v; }
  function strVal(id) { return (el(id) && el(id).value || "").trim(); }

  function buildPayload(cmd) {
    var p = { cmd: cmd }, ch;
    switch (cmd) {
      case "client_scan":
      case "arp_scan":
        var ss = strVal("reconSsid");
        if (!ss) { log("Enter a target SSID first", "warn"); return null; }
        p.ssid = ss; p.pass = el("reconPass").value; break;
      case "sniff":
        ch = numVal("chSniff"); if (ch != null) p.channel = ch; break;
      case "beacon_spam":
        ch = numVal("atkCh"); if (ch != null) p.channel = ch;
        var csv = strVal("atkCsv"); if (csv) p.ssids = csv; break;
      case "ssid_clone":
        var cs = strVal("atkSsid");
        if (!cs) { log("Enter an SSID to clone", "warn"); return null; }
        p.ssid = cs; ch = numVal("atkCh"); if (ch != null) p.channel = ch;
        p.wpa2 = el("cloneWpa2").checked; break;
      case "karma":
        ch = numVal("atkCh"); if (ch != null) p.channel = ch; break;
      case "evil_portal":
        var ps = strVal("atkSsid"); if (ps) p.ssid = ps;
        ch = numVal("atkCh"); if (ch != null) p.channel = ch; break;
      case "deauth":
        var b = strVal("deauthBssid");
        if (!b) { log("Enter a BSSID to deauth", "warn"); return null; }
        p.bssid = b; var t = strVal("deauthTarget"); if (t) p.target = t;
        ch = numVal("atkCh"); if (ch != null) p.channel = ch; break;
      case "ble_scan":
      case "ble_detect":
        var secs = numVal("bleSecs"); if (secs != null) p.secs = secs; break;
      case "ble_spam":
        p.mode = parseInt(el("bleMode").value, 10) || 0; break;
      case "bad_ble":
        var txt = strVal("bleText"); if (txt) p.text = txt; break;
      case "mitm":
        var ms = strVal("mitmSsid");
        if (!ms) { log("Enter the network SSID to MITM", "warn"); return null; }
        p.ssid = ms; p.pass = el("mitmPass").value;
        p.target = strVal("mitmTarget") || "all"; break;
    }
    return p;
  }

  // ---------------- Navigation ----------------
  function showView(name) {
    document.querySelectorAll(".view").forEach(function (v) { v.classList.remove("active"); });
    var target = el("view-" + name) || el("view-home");
    target.classList.add("active");
    window.scrollTo(0, 0);
  }

  document.addEventListener("click", function (e) {
    var go = e.target.closest("[data-go]");
    if (go) { showView(go.getAttribute("data-go")); return; }
    var cmdEl = e.target.closest("[data-cmd]");
    if (cmdEl) {
      var payload = buildPayload(cmdEl.getAttribute("data-cmd"));
      if (payload) send(payload);
      return;
    }
    var clr = e.target.closest("[data-clear]");
    if (clr) { var tk = clr.getAttribute("data-clear"); if (tables[tk]) tables[tk].clear(); return; }
  });

  el("clearLog").addEventListener("click", function () { logPane.innerHTML = ""; });

  // ---------------- Boot ----------------
  connect();
  statusTimer = setInterval(function () {
    if (ws && ws.readyState === WebSocket.OPEN) send({ cmd: "status" });
  }, 5000);
})();
