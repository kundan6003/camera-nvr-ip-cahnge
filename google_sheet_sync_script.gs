/**
 * Bulk Device Config Tool -> Google Sheet sync + Dashboard
 * ----------------------------------------------------------
 * ONE-TIME SETUP (same as before):
 * 1. Extensions -> Apps Script, delete ALL old code, paste this whole file.
 * 2. Deploy -> Manage deployments -> pencil icon -> Version: New version
 *    -> Deploy (keeps the SAME Web App URL).
 * 3. Reload the Google Sheet tab. A "CCTV Tool" menu appears - click
 *    CCTV Tool -> Setup / Refresh Dashboard once.
 *
 * v4.5 - MODERN BRANCH SEARCH: clicking the magnifier icon on the
 * Dashboard (D1) - or CCTV Tool > "Search / Pick Branch..." - opens a
 * slim sidebar with a real combobox: type to filter, click to apply.
 * The B1 dropdown always lists every branch again (no C1 search cell).
 * v4.4b - BRANCH FILTER FIX: a hidden helper column on every Latest row
 * stores the owning NVR's branch, so the Dashboard camera table now shows
 * ONLY the selected branch's cameras (ALL still shows everything).
 * v4.4a - CAMERA WRITE FIX: camera rows are padded to the full column
 * width and written as their own block after the NVR row - the earlier
 * ragged write crashed and silently dropped every camera row. Sheets
 * found with an old column layout are moved aside as "(old N)" tabs.
 * Every sync step is still individually error-trapped and the response
 * reports exactly what succeeded/failed.
 *
 * LAYOUT (v4.3, unchanged): one NVR row with full detail, its camera rows
 * underneath carry ONLY camera details:
 *   NVR row    = Synced At, "NVR", NVR IP/Port/Username/Password,
 *                Branch, Common user, New HTTP/HTTPS/RTSP ports   (12 cols)
 *   Camera row = Synced At, "Camera", Channel, Name, IP, Port,
 *                Username, Password, Online                        (9 cols)
 */

// NVR row columns (12 visible + 1 hidden helper) - camera rows only fill
// the first 9:
// A Synced At | B Row Type | C NVR IP | D NVR Port | E NVR Username |
// F NVR Password | G Branch Name | H Common Username | I Common Password |
// J New HTTP Port | K New HTTPS Port | L New RTSP Port |
// M Branch (helper, hidden) - the owning NVR's branch on EVERY row, so the
//   Dashboard can filter cameras per branch without repeating NVR detail
var HEADERS = [
  "Synced At", "Row Type", "NVR IP", "NVR Port", "NVR Username", "NVR Password",
  "Branch Name", "Common Username", "Common Password",
  "New HTTP Port", "New HTTPS Port", "New RTSP Port", "Branch (helper)"
];

/** Magnifier icon shown in Dashboard!D1 (click = searchable picker). */
var ICON_PNG_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAABzklEQVR42u2bzXHDIBCFVQIlqATOOakESnAJKiAHOlAJKoUSXEmGEhI0I894PFH4MfvCwh7exZZs9gN2YVmmz4+vaWRNAkAACAABIADotASZIPsic37XHYA5aA1yQd+Jcuc7M2cAR+P3DKOvtKNBvPsDqpLhv4FQrQM45rAnMP4hj/ATpS/eCA1/1a01AEjjySFQG+9PL789hcDt/My3ACF3zuc4MZPwmybTiS7/BUAl9tjRs7qgITpx7eBrR4fUB1N6yVZokE0cXVAAM3h+pviZGQlgB/R87kjYUQDmhDlPFaMdYhTEHlgjjdCEAHTkv1cEAIdyRgXTzyEA/NUDBgDARNpACmCJxGPUltVTLoxK6TsgAEc5CktD0QYEsFGG4FIAFgjACoAGAQwxBYZ3gsOHweEXQrIUls2QbIclISIpMUmKtpUWP3SvmRrndjBSHQKnozESCFwOR8kgcDgeJ4XQcoEEBELLJTJ3BISWi6QUAkLrZXLkEDgUSpJC4FLSSgaBU10vCQRuxc3VIXCs8K4KgWuZewkE19t9gRIIurcLE7kQbI83RnIgdAkgB4LuFUAKhO6c4BUEd2G8GgHAc5L1se/Qcm1OAAgAAXClHxD+5rt9jMXDAAAAAElFTkSuQmCC";

/** Pad/truncate a row to exactly HEADERS.length columns - setValues()
 *  throws on ragged rows, which silently killed camera writes before. */
function normalizeRow(row) {
  var out = (row || []).slice();
  while (out.length < HEADERS.length) out.push("");
  return out.slice(0, HEADERS.length);
}

function onOpen() {
  SpreadsheetApp.getUi()
    .createMenu("CCTV Tool")
    .addItem("Setup / Refresh Dashboard", "setupDashboard")
    .addSeparator()
    .addItem("\uD83D\uDD0E Search / Pick Branch\u2026", "showBranchPicker")
    .addToUi();
}

function doPost(e) {
  var errors = [];
  var rowsWritten = 0;
  try {
    var data = JSON.parse(e.postData.contents);
    var ss = SpreadsheetApp.getActiveSpreadsheet();

    // 0) Make sure ALL three tabs exist FIRST - whatever fails later,
    //    the sheet structure is always complete.
    var log = getOrCreateSheet(ss, "Devices", HEADERS);
    getOrCreateSheet(ss, "Latest", HEADERS);
    try { setupDashboard(); } catch (err) { errors.push("Dashboard build: " + err); }

    var ts = data.timestamp || new Date().toISOString();

    // 1) One NVR row (full detail) + its camera rows underneath.
    var rowsToAdd = [];
    rowsToAdd.push([
      ts, "NVR", data.nvr_ip || "", data.nvr_port || "", data.nvr_username || "",
      data.nvr_password || "", data.branch_name || "",
      data.nvr_common_username || "", data.nvr_common_password || "",
      data.nvr_new_http_port || "", data.nvr_new_https_port || "",
      data.nvr_new_rtsp_port || "", data.branch_name || ""
    ]);
    var cams = data.cameras || [];
    for (var i = 0; i < cams.length; i++) {
      var c = cams[i];
      rowsToAdd.push([
        ts, "Camera",
        c.channel || "", c.name || "", c.ip || "", c.port || "",
        c.username || "", c.password || "", c.online ? "Online" : "Offline"
      ]);
    }

    // 2) Append the block to the permanent log (Synced At as plain text
    //    so it never shows up as a raw date-serial number). The NVR row
    //    and the camera rows are written SEPARATELY and every row is
    //    padded to the header width - a ragged write once killed the
    //    camera rows silently.
    try {
      var startRow = log.getLastRow() + 1;
      log.getRange(startRow, 1, 1, 1).setNumberFormat("@");
      log.getRange(startRow, 1, 1, HEADERS.length).setValues([normalizeRow(rowsToAdd[0])]);
      rowsWritten = 1;
    } catch (err) {
      errors.push("Devices NVR write: " + err);
    }
    if (rowsToAdd.length > 1) {
      try {
        var camRows = rowsToAdd.slice(1).map(normalizeRow);
        var camStart = log.getLastRow() + 1;
        log.getRange(camStart, 1, 1, 1).setNumberFormat("@");
        log.getRange(camStart, 1, camRows.length, HEADERS.length).setValues(camRows);
        rowsWritten += camRows.length;
      } catch (err) {
        errors.push("Devices camera write: " + err);
      }
    }

    // 3) Rebuild "Latest" from the log - each NVR keeps only its most
    //    recent block (NVR row + the cameras under it)
    try { rebuildLatest(ss); } catch (err) { errors.push("Latest rebuild: " + err); }

    // 4) Refresh the Dashboard formulas
    try { setupDashboard(); } catch (err) { errors.push("Dashboard refresh: " + err); }

    return ContentService.createTextOutput(JSON.stringify({
      ok: errors.length === 0,
      rows_added: rowsWritten,
      cameras: cams.length,
      warnings: errors
    })).setMimeType(ContentService.MimeType.JSON);

  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({
      ok: false,
      rows_added: rowsWritten,
      error: String(err && err.stack ? err.stack : err)
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

function getOrCreateSheet(ss, name, headers) {
  var sheet = ss.getSheetByName(name);
  if (!sheet) {
    sheet = ss.insertSheet(name);
    sheet.appendRow(headers);
    sheet.setFrozenRows(1);
    return sheet;
  }
  // If an old sync left a different column layout behind, move that tab
  // aside (keeps history) and start a fresh one with the current headers.
  var firstRow = [];
  try { firstRow = sheet.getRange(1, 1, 1, headers.length).getValues()[0]; } catch (e) {}
  var matches = headers.every(function (h, i) { return String(firstRow[i] || "") === String(h); });
  if (firstRow.length && !matches) {
    try {
      var suffix = 1;
      while (ss.getSheetByName(name + " (old " + suffix + ")")) suffix++;
      sheet.setName(name + " (old " + suffix + ")");
      sheet = ss.insertSheet(name);
      sheet.appendRow(headers);
      sheet.setFrozenRows(1);
    } catch (e) {
      // could not rename - just reset the header in place
      sheet.clearContents();
      sheet.appendRow(headers);
      sheet.setFrozenRows(1);
    }
  }
  return sheet;
}

/** Latest = every NVR's most recent block (NVR row + its camera rows),
 *  rebuilt from the append-only Devices log. */
function rebuildLatest(ss) {
  var latest = getOrCreateSheet(ss, "Latest", HEADERS);
  var log = ss.getSheetByName("Devices");
  latest.clearContents();
  if (!log || log.getLastRow() < 2) return;

  var data = log.getDataRange().getValues();
  var blocks = {};  // nvrIp -> rows of its most recent block
  var order = [];   // NVR IPs in first-seen order
  var cur = null;
  var curBranch = "";
  for (var i = 1; i < data.length; i++) {
    var rowType = String(data[i][1] || "");
    if (rowType === "NVR") {
      var ip = String(data[i][2] || "");
      curBranch = String(data[i][6] || "");   // G = Branch Name
      if (!(ip in blocks)) order.push(ip);
      blocks[ip] = [data[i]];
      cur = ip;
    } else if (rowType === "Camera" && cur) {
      var camRow = data[i].slice();
      while (camRow.length < HEADERS.length) camRow.push("");
      camRow[HEADERS.length - 1] = curBranch;  // M = owning NVR's branch
      blocks[cur].push(camRow);
    }
  }

  var all = [HEADERS];
  for (var k = 0; k < order.length; k++) {
    all = all.concat(blocks[order[k]]);
  }
  if (all.length) {
    latest.getRange(1, 1, all.length, HEADERS.length).setValues(
      all.map(normalizeRow)
    );
    latest.getRange(2, 1, all.length - 1, 1).setNumberFormat("@");
    try { latest.hideColumns(HEADERS.length); } catch (e) {}
  }
}

function setupDashboard() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  getOrCreateSheet(ss, "Devices", HEADERS);
  getOrCreateSheet(ss, "Latest", HEADERS);

  var dash = ss.getSheetByName("Dashboard");
  if (!dash) {
    dash = ss.insertSheet("Dashboard");
  }

  // Widen the grid FIRST so every later range is in bounds (a fresh
  // Dashboard sheet only has 26 columns - AD/AF live beyond that).
  try {
    if (dash.getMaxColumns() < 32) {
      dash.insertColumnsAfter(dash.getMaxColumns(), 32 - dash.getMaxColumns());
    }
    if (dash.getMaxRows() < 12) {
      dash.insertRowsAfter(dash.getMaxRows(), 12 - dash.getMaxRows());
    }
  } catch (e) { /* non-fatal - ranges below auto-expand on write */ }

  // Clear leftover cells from any earlier version of this script so old
  // layouts never leave stale text/formulas behind.
  dash.getRange("A1:AF10").clearContent();
  dash.getRange("A1:AF10").setBackground(null);
  dash.getRange("A1:AF10").clearFormat();
  try { dash.getCharts() && dash.getCharts().forEach(function (ch) { dash.removeChart(ch); }); } catch (e) {}

  // ---------------- Select Branch + inline Search (columns A/B/C) ----------------
  // How it works: type in C1 -> the AD2 helper formula filters itself ->
  // the B1 dropdown then only lists matching branches (plus ALL).
  // No dialog, no trigger, no authorization - just type and pick.
  dash.getRange("AD1").setValue("ALL");
  dash.getRange("AD2").setFormula(
    '=IFERROR(UNIQUE(FILTER(Latest!G2:G,Latest!B2:B="NVR",Latest!G2:G<>"")),"")');
  var branchRule = SpreadsheetApp.newDataValidation()
    .requireValueInRange(dash.getRange("AD1:AD200"), true)
    .setAllowInvalid(false)
    .build();
  dash.getRange("B1").setDataValidation(branchRule).setValue("ALL");
  var b1 = dash.getRange("B1");
  b1.setFontSize(13).setFontWeight("bold").setFontColor("#ffffff");
  b1.setBackground("#7c3aed").setHorizontalAlignment("center").setVerticalAlignment("middle");
  b1.setBorder(true, true, true, true, false, false, "#4c1d95",
               SpreadsheetApp.BorderStyle.SOLID_MEDIUM);
  dash.getRange("A1").setValue("Select Branch:").setFontWeight("bold")
    .setFontSize(12).setFontColor("#ffffff")
    .setBackground("#312e81").setHorizontalAlignment("center")
    .setVerticalAlignment("middle");
  // D1: clickable icon that opens the searchable branch picker (sidebar)
  dash.getRange("D1").clearContent()
    .setBackground("#7c3aed")
    .setHorizontalAlignment("center").setVerticalAlignment("middle")
    .setBorder(true, true, true, true, false, false, "#4c1d95",
               SpreadsheetApp.BorderStyle.SOLID_MEDIUM);
  try {
    var icon = SpreadsheetApp.newCellImage()
      .setSourceString(ICON_PNG_BASE64)
      .build();
    dash.getRange("D1").setValue(icon);
  } catch (eIcon) {
    dash.getRange("D1").setValue("\uD83D\uDD0D Click to search branch");
  }
  dash.setColumnWidth(1, 110);
  dash.setColumnWidth(2, 190);
  dash.setColumnWidth(3, 40);
  dash.setColumnWidth(4, 90);
  dash.setRowHeight(1, 34);

  // Full NVR detail (admin login + Common user + new ports) per branch
  var nvrHeaders = ["Branch Name", "NVR IP", "NVR Port", "NVR Username", "NVR Password",
                    "Common Username", "Common Password (read-only)",
                    "New HTTP Port", "New HTTPS Port", "New RTSP Port"];
  dash.getRange("A3:J3").setValues([nvrHeaders]).setFontWeight("bold")
    .setBackground("#0f766e").setFontColor("#ffffff");
  dash.getRange("A4").setFormula(
    '=IFERROR(IF(B1="ALL",' +
    'FILTER({Latest!G2:G,Latest!C2:C,Latest!D2:D,Latest!E2:E,Latest!F2:F,Latest!H2:H,Latest!I2:I,Latest!J2:J,Latest!K2:K,Latest!L2:L},Latest!B2:B="NVR"),' +
    'FILTER({Latest!G2:G,Latest!C2:C,Latest!D2:D,Latest!E2:E,Latest!F2:F,Latest!H2:H,Latest!I2:I,Latest!J2:J,Latest!K2:K,Latest!L2:L},Latest!G2:G=B1,Latest!B2:B="NVR")' +
    '),"No NVRs synced yet - sync a device from the tool first, with a Branch Name filled in")'
  );
  dash.setColumnWidths(1, 10, 120);

  // Cameras (in Latest they already sit under their own NVR's row)
  dash.getRange("L3").setValue("Cameras (in Latest, listed under their NVR)").setFontWeight("bold").setFontSize(11);
  var camHeaders = ["Channel", "Camera Name", "Camera IP", "Camera Port",
                     "Camera Username", "Camera Password", "Online"];
  dash.getRange("L4:R4").setValues([camHeaders]).setFontWeight("bold")
    .setBackground("#7c3aed").setFontColor("#ffffff");
  dash.getRange("L5").setFormula(
    '=IFERROR(IF(B1="ALL",' +
    'FILTER({Latest!C2:C,Latest!D2:D,Latest!E2:E,Latest!F2:F,Latest!G2:G,Latest!H2:H,Latest!I2:I},Latest!B2:B="Camera"),' +
    'FILTER({Latest!C2:C,Latest!D2:D,Latest!E2:E,Latest!F2:F,Latest!G2:G,Latest!H2:H,Latest!I2:I},Latest!B2:B="Camera",Latest!M2:M=B1)' +
    '),"No cameras synced yet for this branch")'
  );
  dash.setColumnWidths(12, 7, 120);

  // ---------------- Stylish summary + pie chart ----------------
  dash.getRange("T1").setValue("\uD83D\uDCCA Summary").setFontWeight("bold").setFontSize(13).setFontColor("#2dd4bf");
  dash.getRange("T2").setValue("NVRs").setFontWeight("bold").setFontColor("#ffffff")
    .setBackground("#0f766e").setHorizontalAlignment("center").setVerticalAlignment("middle");
  dash.getRange("U2").setFormula('=COUNTIF(Latest!B2:B,"NVR")').setFontWeight("bold")
    .setFontSize(15).setFontColor("#0f766e").setHorizontalAlignment("center").setVerticalAlignment("middle");
  dash.getRange("T3").setValue("Cameras").setFontWeight("bold").setFontColor("#ffffff")
    .setBackground("#7c3aed").setHorizontalAlignment("center").setVerticalAlignment("middle");
  dash.getRange("U3").setFormula('=COUNTIF(Latest!B2:B,"Camera")').setFontWeight("bold")
    .setFontSize(15).setFontColor("#7c3aed").setHorizontalAlignment("center").setVerticalAlignment("middle");
  dash.getRange("T4").setValue("Branches").setFontWeight("bold").setFontColor("#ffffff")
    .setBackground("#b45309").setHorizontalAlignment("center").setVerticalAlignment("middle");
  dash.getRange("U4").setFormula('=IFERROR(COUNTA(UNIQUE(FILTER(Latest!G2:G,Latest!B2:B="NVR"))),0)')
    .setFontWeight("bold").setFontSize(15).setFontColor("#b45309")
    .setHorizontalAlignment("center").setVerticalAlignment("middle");
  dash.getRange("T1:U4").setBorder(true, true, true, true, true, true, "#334155", SpreadsheetApp.BorderStyle.SOLID);
  dash.setRowHeights(2, 3, 26);
  dash.autoResizeColumns(20, 2); // columns T:U

  var existingCharts = dash.getCharts();
  for (var ci = 0; ci < existingCharts.length; ci++) {
    dash.removeChart(existingCharts[ci]);
  }
  var chart = dash.newChart()
    .setChartType(Charts.ChartType.PIE)
    .addRange(dash.getRange("T2:U3"))
    .setPosition(1, 22, 0, 0) // column V
    .setOption("title", "NVRs vs Cameras")
    .setOption("titleTextStyle", { fontSize: 14, bold: true })
    .setOption("pieSliceText", "value")
    .setOption("colors", ["#0f766e", "#7c3aed"])
    .setOption("legend", { position: "bottom" })
    .setOption("width", 360)
    .setOption("height", 280)
    .build();
  dash.insertChart(chart);

  // Clicking the D1 icon opens the searchable branch sidebar (same as
  // the CCTV Tool menu). The "Assign script" call needs the icon to be
  // the cell's VALUE - it may land one run later, hence the guard.
  try {
    dash.getRange("D1").assignScript("openBranchSidebar");
  } catch (eAssign) { /* non-fatal - menu item still works */ }
  try { dash.hideColumns(30); } catch (e) { /* helper column may not exist yet */ }
  dash.setFrozenRows(4);
  dash.setRowHeight(1, 30);
}

/** Modal, SEARCHABLE branch picker - handy when the branch list grows.
 *  Picking a branch writes it into Dashboard!B1 (the live filter cell). */
function showBranchPicker() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var latest = ss.getSheetByName("Latest");
  var stats = {};   // branch -> {nvr, cam}
  var order = ["ALL"];
  if (latest && latest.getLastRow() > 1) {
    var n = latest.getLastRow() - 1;
    var types = latest.getRange(2, 2, n, 1).getValues();     // B Row Type
    var branch = latest.getRange(2, 7, n, 1).getValues();    // G Branch Name
    var helper = latest.getRange(2, HEADERS.length, n, 1).getValues(); // M hidden
    for (var i = 0; i < n; i++) {
      var isNvr = String(types[i][0]) === "NVR";
      var b = String((isNvr ? branch[i][0] : helper[i][0]) || "").trim();
      if (!b) continue;
      if (!stats[b]) { stats[b] = { nvr: 0, cam: 0 }; order.push(b); }
      if (isNvr) stats[b].nvr++; else stats[b].cam++;
    }
  }
  var t = HtmlService.createTemplateFromString(_pickerHtml());
  t.branches = JSON.stringify(order);
  t.stats = JSON.stringify(stats);
  SpreadsheetApp.getUi().showModalDialog(
    t.evaluate().setWidth(380).setHeight(520), "\uD83D\uDD0E Select Branch");
}

function _pickerHtml() {
  return '<!DOCTYPE html><html><head><base target="_top"><style>'
    + '*{box-sizing:border-box}'
    + 'body{margin:0;font-family:"Segoe UI",system-ui,Arial,sans-serif;background:#ffffff;color:#1e293b}'
    + '.wrap{padding:16px}'
    + '.searchwrap{position:relative}'
    + '.search{width:100%;padding:12px 14px 12px 40px;border-radius:10px;'
    + 'border:1px solid #10b981;background:#fff;color:#1e293b;font-size:14px;outline:none}'
    + '.search:focus{border-color:#059669;box-shadow:0 0 0 3px rgba(16,185,129,.18)}'
    + '.searchwrap:before{content:"\\1F50D";position:absolute;left:12px;top:50%;'
    + 'transform:translateY(-50%);font-size:15px;opacity:.7}'
    + '.list{margin-top:12px;max-height:400px;overflow-y:auto;display:flex;flex-direction:column}'
    + '.item{display:flex;justify-content:space-between;align-items:center;gap:8px;'
    + 'padding:11px 12px;border-bottom:1px solid #f1f5f9;cursor:pointer;transition:background .1s}'
    + '.item:hover{background:#ecfdf5}'
    + '.name{font-weight:600;font-size:13.5px;word-break:break-word}'
    + '.badge{flex:0 0 auto;font-size:10.5px;font-weight:700;color:#047857;white-space:nowrap}'
    + '.item.all .name{color:#059669}'
    + '.empty{color:#94a3b8;font-size:13px;text-align:center;padding:18px 0}'
    + '</style></head><body><div class="wrap">'
    + '<div class="searchwrap"><input class="search" id="q" '
    + 'placeholder="Click & search branch..." autofocus></div>'
    + '<div class="list" id="list"></div>'
    + '</div><script>'
    + 'var BRANCHES = <?!= branches ?>;'
    + 'var STATS = <?!= stats ?>;'
    + 'function esc(s){return String(s).replace(/[&<>\"]/g,function(c){'
    + 'return {"&":"&amp;","<":"&lt;",">":"&gt;","\\\"":"&quot;"}[c];});}'
    + 'function render(){'
    + 'var q=document.getElementById("q").value.toLowerCase();'
    + 'var el=document.getElementById("list");el.innerHTML="";'
    + 'var shown=0;'
    + 'BRANCHES.forEach(function(b){'
    + 'if(q && b.toLowerCase().indexOf(q)===-1)return;'
    + 'shown++;'
    + 'var d=document.createElement("div");'
    + 'd.className="item"+(b==="ALL"?" all":"");'
    + 'var badge=(b==="ALL")?"":(STATS[b]?STATS[b].nvr+" NVR \u00B7 "+STATS[b].cam+" CAM":"");'
    + 'd.innerHTML=\'<span class="name">\'+esc(b)+\'</span><span class="badge">\'+badge+\'</span>\';'
    + 'd.onclick=function(){google.script.run.setDashboardBranch(b);google.script.host.close();};'
    + 'el.appendChild(d);});'
    + 'if(!shown)el.innerHTML=\'<div class="empty">No matching branch found</div>\';}'
    + 'document.getElementById("q").addEventListener("input",render);'
    + 'render();'
    + '<\\/script></body></html>';
}

/** Opens the searchable branch picker as a slim SIDEBAR - stays open,
 *  search + click without ever covering the dashboard. */
function openBranchSidebar() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var latest = ss.getSheetByName("Latest");
  var stats = {};   // branch -> {nvr, cam}
  var order = ["ALL"];
  if (latest && latest.getLastRow() > 1) {
    var n = latest.getLastRow() - 1;
    var types = latest.getRange(2, 2, n, 1).getValues();      // B Row Type
    var branch = latest.getRange(2, 7, n, 1).getValues();     // G Branch Name
    var helper = latest.getRange(2, HEADERS.length, n, 1).getValues(); // M hidden
    for (var i = 0; i < n; i++) {
      var isNvr = String(types[i][0]) === "NVR";
      var b = String((isNvr ? branch[i][0] : helper[i][0]) || "").trim();
      if (!b) continue;
      if (!stats[b]) { stats[b] = { nvr: 0, cam: 0 }; order.push(b); }
      if (isNvr) stats[b].nvr++; else stats[b].cam++;
    }
  }
  var t = HtmlService.createTemplateFromString(_pickerHtml());
  t.branches = JSON.stringify(order);
  t.stats = JSON.stringify(stats);
  SpreadsheetApp.getUi().showSidebar(t.evaluate().setTitle("Select Branch"));
}

/** Written by the sidebar - sets the live filter cell. */
function setDashboardBranch(name) {
  var dash = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Dashboard");
  if (dash) dash.getRange("B1").setValue(name || "ALL");
}

/** Makes a dropdown cell look like a solid button instead of a plain cell. */
function styleDropdownButton(range, hexColor) {
  range
    .setBackground(hexColor)
    .setFontColor("#ffffff")
    .setFontWeight("bold")
    .setFontSize(11)
    .setHorizontalAlignment("center")
    .setVerticalAlignment("middle")
    .setBorder(true, true, true, true, false, false, "#000000", SpreadsheetApp.BorderStyle.SOLID_MEDIUM);
}

/**
 * Optional: lets you read the full log as JSON if you ever build
 * something else on top of it. Not needed for the Dashboard above,
 * which works entirely with in-sheet formulas.
 */
function doGet(e) {
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName("Devices");
    if (!sheet) {
      return ContentService.createTextOutput(JSON.stringify({ ok: true, rows: [] }))
        .setMimeType(ContentService.MimeType.JSON);
    }
    var data = sheet.getDataRange().getValues();
    var headers = data[0];
    var rows = [];
    for (var i = 1; i < data.length; i++) {
      var row = {};
      for (var j = 0; j < headers.length; j++) {
        var val = data[i][j];
        row[headers[j]] = (val instanceof Date) ? val.toISOString() : val;
      }
      rows.push(row);
    }
    return ContentService.createTextOutput(JSON.stringify({ ok: true, rows: rows }))
      .setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({ ok: false, error: err.toString() }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}
