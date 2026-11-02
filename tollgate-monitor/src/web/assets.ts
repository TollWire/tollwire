// Static files of the GUI, embedded as strings: nothing is read from disk at run time (no path handling), nothing is
// loaded from outside (CSP `default-src 'none'`). The script writes text only through `textContent`.
export interface Asset {
  type: string;
  body: string;
}

const HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>TollGate monitor</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header>
<h1>TollGate monitor</h1>
<span id="mode" class="badge"></span>
<span id="live" class="badge"></span>
</header>
<main>
<section id="login">
<label for="token">Access token</label>
<input id="token" type="password" autocomplete="off" spellcheck="false" maxlength="512">
<button id="connect" type="button">Connect</button>
<p id="login-error" class="error"></p>
</section>
<section id="view" hidden>
<div class="bar">
<label for="f-type">Type</label><input id="f-type" type="text" maxlength="40" placeholder="decision">
<label for="f-session">Session</label><input id="f-session" type="text" maxlength="128">
<label for="f-limit">Limit</label><input id="f-limit" type="number" min="1" max="1000" value="100">
<span id="f-user-wrap" hidden><label for="f-user">User id</label><input id="f-user" type="text" maxlength="10"></span>
<button id="reload" type="button">Reload</button>
<button id="verify" type="button">Verify chain</button>
</div>
<p id="notice" class="notice"></p>
<div id="verify-result" class="result"></div>
<section id="admin" hidden>
<h2>Locks (administrator)</h2>
<p class="notice">A lock blocks tool calls of Claude Code that run the TollGate hook. It does not stop running processes or other tools. Locks are removed on the host with <code>sudo tollgate-control unlock</code>, not here.</p>
<table id="locks"><thead></thead><tbody></tbody></table>
<div class="bar">
<label for="a-kind">Lock</label>
<select id="a-kind"><option value="user">user</option><option value="session">session</option><option value="tool">tool or MCP server</option><option value="global">everything on this host (emergency stop)</option></select>
<input id="a-target" type="text" maxlength="128" placeholder="user id / session id / tool name or mcp__server__*" spellcheck="false">
<label for="a-minutes">Minutes (empty: until removed)</label><input id="a-minutes" type="number" min="1" max="43200">
</div>
<div class="bar"><label for="a-reason">Reason (8 to 500 characters)</label><input id="a-reason" type="text" maxlength="500" size="60"><button id="a-review" type="button">Review</button></div>
<div id="a-confirm" hidden class="result">
<div id="a-summary"></div>
<div id="a-warn" class="notice"></div>
<div id="a-typed-wrap" hidden><label for="a-typed">Type <b id="a-expect"></b> to confirm</label> <input id="a-typed" type="text" maxlength="128" autocomplete="off"></div>
<button id="a-commit" type="button">Apply lock</button> <button id="a-cancel" type="button">Cancel</button>
</div>
<p id="a-result" class="notice"></p>
</section>
<h2>Sessions</h2>
<table id="sessions"><thead></thead><tbody></tbody></table>
<h2>Events</h2>
<table id="events"><thead></thead><tbody></tbody></table>
</section>
</main>
<script src="/app.js"></script>
</body>
</html>
`;

const CSS = `body{font:14px/1.4 system-ui,sans-serif;margin:0;color:#1b1f23;background:#f6f8fa}
header{display:flex;gap:12px;align-items:center;padding:8px 16px;background:#24292f;color:#fff}
h1{font-size:16px;margin:0}h2{font-size:14px;margin:16px 0 4px}
main{padding:12px 16px}
.badge{padding:2px 8px;border-radius:10px;background:#57606a;font-size:12px}
.badge.on{background:#1a7f37}.badge.off{background:#9a6700}
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
input{padding:3px 6px;border:1px solid #d0d7de;border-radius:4px}
button{padding:3px 10px}
table{border-collapse:collapse;width:100%;background:#fff}
th,td{border:1px solid #d0d7de;padding:2px 6px;text-align:left;vertical-align:top;word-break:break-word}
th{background:#eaeef2}
.error{color:#cf222e}.notice{color:#9a6700}
.deny{background:#ffebe9}.ok{color:#1a7f37}.bad{color:#cf222e;font-weight:600}
.result{margin:8px 0}
select{padding:3px 6px}
`;

const JS = String.raw`"use strict";
(function () {
  var state = { token: "", mode: "", live: null, ctrl: null };
  var UNSAFE = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]/g;
  function mask(text) {
    return String(text).replace(UNSAFE, function (c) {
      return "\\u{" + c.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0") + "}";
    });
  }
  function el(tag, text, cls) {
    var e = document.createElement(tag);
    if (text !== undefined && text !== null) e.textContent = mask(text);
    if (cls) e.className = cls;
    return e;
  }
  function $(id) { return document.getElementById(id); }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function get(obj, path) {
    var cur = obj;
    for (var i = 0; i < path.length; i++) {
      if (cur === null || typeof cur !== "object") return undefined;
      cur = cur[path[i]];
    }
    return cur;
  }
  function api(path) {
    return fetch(path, { headers: { Authorization: "Bearer " + state.token }, cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" });
  }
  function fail(message) { $("login-error").textContent = mask(message); }
  function head(table, names) {
    var thead = table.tHead || table.createTHead();
    clear(thead);
    var row = el("tr");
    names.forEach(function (n) { row.appendChild(el("th", n)); });
    thead.appendChild(row);
  }
  function eventRow(item, admin) {
    var e = item.event;
    var row = el("tr", null, get(e, ["decision", "outcome"]) === "deny" ? "deny" : "");
    var cells = [
      e.ts, e.type, get(e, ["claude", "session_id"]), get(e, ["tool", "name"]),
      get(e, ["decision", "outcome"]), get(e, ["decision", "rule_kind"]), get(e, ["decision", "reason"]),
      (get(e, ["tool", "paths"]) || []).join(" "), (get(e, ["tool", "command"]) || "")
    ];
    if (admin) {
      cells.push(get(e, ["user", "name"]), get(e, ["host", "name"]));
      cells.push(item.relay ? (item.relay.chain_ok === false ? "chain not ok" : "") + (item.relay.meta_ok === false ? " meta not ok" : "") : "");
    }
    cells.forEach(function (c) { row.appendChild(el("td", c === undefined || c === null ? "" : c)); });
    return row;
  }
  function render(listing, sessions) {
    var admin = state.mode === "admin";
    var cols = ["Time", "Type", "Session", "Tool", "Outcome", "Rule", "Reason", "Paths", "Command"];
    if (admin) cols = cols.concat(["User", "Host", "Relay"]);
    var table = $("events");
    head(table, cols);
    var body = table.tBodies[0];
    clear(body);
    listing.events.forEach(function (item) { body.appendChild(eventRow(item, admin)); });
    var st = $("sessions");
    head(st, ["Session", "First", "Last", "Events", "Denied"].concat(admin ? ["User", "Host"] : []));
    var sb = st.tBodies[0];
    clear(sb);
    sessions.sessions.forEach(function (s) {
      var row = el("tr");
      [s.session_id, s.first_ts, s.last_ts, s.events, s.denies].concat(admin ? [s.user ? s.user.name : "", s.host] : []).forEach(function (c) { row.appendChild(el("td", c)); });
      sb.appendChild(row);
    });
    var notes = [];
    if (listing.has_more) notes.push("More events match than shown.");
    if (listing.truncated || sessions.truncated) notes.push("Not all data could be read (limits).");
    (listing.findings || []).forEach(function (f) { notes.push(f.kind + ": " + f.file); });
    $("notice").textContent = mask(notes.join(" "));
  }
  function query(withLimit) {
    var p = [];
    var t = $("f-type").value.trim(), s = $("f-session").value.trim(), u = $("f-user").value.trim();
    var l = parseInt($("f-limit").value, 10);
    if (t) p.push("type=" + encodeURIComponent(t));
    if (s) p.push("session=" + encodeURIComponent(s));
    if (u && state.mode === "admin") p.push("user=" + encodeURIComponent(u));
    if (withLimit && l > 0) p.push("limit=" + l);
    return p.length ? "?" + p.join("&") : "";
  }
  function reload() {
    Promise.all([api("/api/v1/events" + query(true)), api("/api/v1/sessions" + query(false))]).then(function (rs) {
      if (rs[0].status === 401 || rs[1].status === 401) { showLogin("The token is invalid or expired."); return null; }
      if (!rs[0].ok || !rs[1].ok) { $("notice").textContent = "Request failed (" + rs[0].status + "/" + rs[1].status + ")."; return null; }
      return Promise.all([rs[0].json(), rs[1].json()]);
    }).then(function (data) { if (data) render(data[0], data[1]); }).catch(function () { $("notice").textContent = "Request failed."; });
  }
  function showLogin(message) {
    state.token = "";
    stopLive();
    $("view").hidden = true;
    $("login").hidden = false;
    $("token").value = "";
    fail(message || "");
  }
  function verify() {
    var box = $("verify-result");
    box.textContent = "Checking ...";
    api("/api/v1/verify").then(function (r) {
      if (r.status === 429) { box.textContent = "A check is already running or was requested too often."; return null; }
      if (!r.ok) { box.textContent = "Check failed (" + r.status + ")."; return null; }
      return r.json();
    }).then(function (v) {
      if (!v) return;
      clear(box);
      box.appendChild(el("span", v.ok ? "Chain valid" : "Chain NOT valid", v.ok ? "ok" : "bad"));
      var text = " files " + v.files + ", events " + v.events + ", chains " + v.chains + (v.complete ? "" : ", incomplete (limit)");
      if (v.embedded) text += ", embedded " + v.embedded.checked + ", flagged by relay " + v.embedded.relay_flagged;
      box.appendChild(el("span", text));
      v.findings.slice(0, 20).forEach(function (f) { box.appendChild(el("div", f.kind + " " + f.file + ":" + f.line + " " + f.detail, "bad")); });
      v.read_findings.slice(0, 20).forEach(function (f) { box.appendChild(el("div", f.kind + " " + f.file + " " + f.detail, "bad")); });
    }).catch(function () { box.textContent = "Check failed."; });
  }
  function stopLive() {
    if (state.ctrl) { state.ctrl.abort(); state.ctrl = null; }
    var b = $("live"); b.textContent = "live: off"; b.className = "badge off";
  }
  function startLive() {
    stopLive();
    var ctrl = new AbortController();
    state.ctrl = ctrl;
    fetch("/api/v1/stream", { headers: { Authorization: "Bearer " + state.token }, cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer", signal: ctrl.signal }).then(function (r) {
      if (!r.ok || !r.body) throw new Error("stream");
      var b = $("live"); b.textContent = "live: on"; b.className = "badge on";
      var reader = r.body.getReader(), dec = new TextDecoder("utf-8"), buf = "";
      function pump() {
        return reader.read().then(function (chunk) {
          if (chunk.done) { throw new Error("closed"); }
          buf += dec.decode(chunk.value, { stream: true });
          if (buf.length > 262144) throw new Error("too long");
          var parts = buf.split("\n\n");
          buf = parts.pop();
          parts.forEach(function (block) {
            block.split("\n").forEach(function (line) {
              if (line.indexOf("data: ") !== 0) return;
              var item;
              try { item = JSON.parse(line.slice(6)); } catch (e) { return; }
              if (item && item.event) {
                var body = $("events").tBodies[0];
                body.insertBefore(eventRow(item, state.mode === "admin"), body.firstChild);
                while (body.rows.length > 1000) body.deleteRow(body.rows.length - 1);
              }
            });
          });
          return pump();
        });
      }
      return pump();
    }).catch(function () {
      if (state.ctrl === ctrl) { stopLive(); }
    });
  }

  function post(path, body) {
    return fetch(path, { method: "POST", headers: { Authorization: "Bearer " + state.token, "Content-Type": "application/json" }, body: JSON.stringify(body), cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" });
  }
  var pending = null;
  function describeTarget(t) {
    var keys = Object.keys(t || {});
    return keys.length ? keys[0] + " " + t[keys[0]] : "all";
  }
  function loadLocks() {
    api("/api/v1/admin/locks").then(function (r) { return r.ok ? r.json() : null; }).then(function (v) {
      var table = $("locks");
      head(table, ["Id", "Kind", "Target", "Created", "Expires", "Via"]);
      var body = table.tBodies[0];
      clear(body);
      if (!v) { $("a-result").textContent = "The lock state could not be read."; return; }
      var all = (v.global ? [v.global] : []).concat(v.locks);
      all.forEach(function (e) {
        var row = el("tr");
        [e.id, e.kind, describeTarget(e.target), e.created, e.expires || "until removed", e.via].forEach(function (c) { row.appendChild(el("td", c)); });
        body.appendChild(row);
      });
      if (!all.length) { var empty = el("tr"); empty.appendChild(el("td", "no locks")); body.appendChild(empty); }
    }).catch(function () { $("a-result").textContent = "The lock state could not be read."; });
  }
  function buildAction() {
    var kind = $("a-kind").value, raw = $("a-target").value.trim(), target;
    if (kind === "user") { if (!/^[1-9][0-9]{0,9}$/.test(raw)) return "A user id is a plain number."; target = { uid: Number(raw) }; }
    else if (kind === "session") target = { session_id: raw };
    else if (kind === "tool") target = { tool: raw };
    else target = {};
    var m = $("a-minutes").value.trim();
    if (m && !/^[1-9][0-9]{0,4}$/.test(m)) return "Minutes must be a plain number.";
    return { kind: kind, target: target, expires_in_minutes: m ? Number(m) : null, reason: $("a-reason").value.trim() };
  }
  function cancelAction() { pending = null; $("a-confirm").hidden = true; $("a-typed").value = ""; }
  function review() {
    $("a-result").textContent = "";
    var action = buildAction();
    if (typeof action === "string") { $("a-result").textContent = action; return; }
    post("/api/v1/admin/actions/prepare", { action: action }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); }).then(function (x) {
      if (!x.ok) { $("a-result").textContent = mask(x.body.message || "The action was refused."); return; }
      pending = { id: x.body.confirm_id, action: x.body.summary, expect: x.body.confirm_text };
      var tool = x.body.summary.kind === "tool" ? x.body.summary.target.tool : "";
      $("a-warn").textContent = tool && tool.indexOf("mcp__") !== 0 && !/^[A-Z]/.test(tool) ? mask("Warning: " + tool + " is not a known tool name shape (Claude Code names start with a capital letter, MCP tools with mcp__).") : "";
      var s = x.body.summary;
      $("a-summary").textContent = mask("Lock " + s.kind + " " + describeTarget(s.target) + " on " + x.body.host + (s.expires_in_minutes ? " for " + s.expires_in_minutes + " minutes" : " until removed") + ". Reason: " + s.reason);
      $("a-typed-wrap").hidden = pending.expect === null;
      $("a-expect").textContent = pending.expect === null ? "" : mask(pending.expect);
      $("a-typed").value = "";
      $("a-confirm").hidden = false;
    }).catch(function () { $("a-result").textContent = "The request failed."; });
  }
  function commit() {
    if (!pending) return;
    if (pending.expect !== null && $("a-typed").value !== pending.expect) { $("a-result").textContent = "The typed text does not match."; return; }
    var p = pending;
    cancelAction();
    post("/api/v1/admin/actions/commit", { confirm_id: p.id, action: p.action }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); }).then(function (x) {
      var until = x.ok ? (x.body.expires ? " until " + x.body.expires : " until removed") : "";
      $("a-result").textContent = x.ok ? mask(x.body.result === "exists" ? "Already locked (" + x.body.lock_id + ")" + until + "; the existing lock lasts at least as long." : x.body.result === "extended" ? "Lock extended (" + x.body.lock_id + ")" + until + "." : "Locked (" + x.body.lock_id + ")" + until + ".") : mask(x.body.message || "The action failed.");
      loadLocks();
    }).catch(function () { $("a-result").textContent = "The request failed."; });
  }
  $("a-review").addEventListener("click", review);
  $("a-commit").addEventListener("click", commit);
  $("a-cancel").addEventListener("click", cancelAction);
  function connect() {
    var t = $("token").value.trim();
    if (!t) { fail("Enter the token."); return; }
    state.token = t;
    $("token").value = "";
    api("/api/v1/health").then(function (r) {
      if (!r.ok) { showLogin(r.status === 401 ? "The token is invalid or expired." : "Connection failed (" + r.status + ")."); return null; }
      return r.json();
    }).then(function (h) {
      if (!h) return;
      state.mode = h.mode;
      $("mode").textContent = mask(h.mode === "admin" ? "admin view" : "user view");
      $("f-user-wrap").hidden = h.mode !== "admin";
      $("admin").hidden = !(h.mode === "admin" && h.admin_actions === true);
      if (!$("admin").hidden) loadLocks();
      $("login").hidden = true;
      $("view").hidden = false;
      fail("");
      reload();
      startLive();
    }).catch(function () { showLogin("Connection failed."); });
  }
  $("connect").addEventListener("click", connect);
  $("token").addEventListener("keydown", function (e) { if (e.key === "Enter") connect(); });
  $("reload").addEventListener("click", reload);
  $("verify").addEventListener("click", verify);
  var m = /^#token=([A-Za-z0-9_-]{1,512})$/.exec(location.hash);
  if (m) {
    // The token from the address bar goes to memory only; the fragment is removed from the address and the history.
    $("token").value = m[1];
    history.replaceState(null, "", location.pathname + location.search);
    connect();
  }
  stopLive();
})();
`;

export const ASSETS: Readonly<Record<string, Asset>> = {
  "/": { type: "text/html; charset=utf-8", body: HTML },
  "/index.html": { type: "text/html; charset=utf-8", body: HTML },
  "/style.css": { type: "text/css; charset=utf-8", body: CSS },
  "/app.js": { type: "text/javascript; charset=utf-8", body: JS },
};
