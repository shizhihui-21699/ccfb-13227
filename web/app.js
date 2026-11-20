/* SolRecon — audit desk front end.
 * Talks to the Go engine compiled to WebAssembly (window.solrecon.analyze).
 */
(function () {
  'use strict';

  var SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
  var SEV_LABEL = { high: '高', medium: '中', low: '低', info: '提示' };
  var CAT_LABEL = {
    reentrancy: '重入', 'unchecked-call': '未检查返回值',
    'access-control': '权限', randomness: '随机数', integer: '整数',
  };

  var state = {
    groups: [],
    files: [],          // working set: {id,name,src,variant,group,lines}
    activeId: null,
    report: null,
    filter: 'all',
    openFindings: {},   // rule@file:line -> expanded
    selected: null,
    engineReady: false,
  };

  var el = {};
  function $(id) { return document.getElementById(id); }

  // ---------- engine ----------
  function setEngineStatus(text, cls) {
    el.status.textContent = text;
    el.status.className = 'engine-status ' + (cls || '');
  }

  async function bootEngine() {
    if (typeof Go === 'undefined' || typeof WebAssembly === 'undefined') {
      setEngineStatus('浏览器不支持 WebAssembly', 'error');
      return;
    }
    try {
      var go = new Go();
      var resp = await fetch('audit.wasm');
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      var buf = await resp.arrayBuffer();
      var mod = await WebAssembly.instantiate(buf, go.importObject);
      go.run(mod.instance);
      // wait briefly for the module to install its global
      var deadline = Date.now() + 8000;
      while (typeof window.solrecon === 'undefined' && Date.now() < deadline) {
        await new Promise(function (r) { setTimeout(r, 30); });
      }
      if (typeof window.solrecon === 'undefined') throw new Error('模块未初始化');
      state.engineReady = true;
      setEngineStatus('引擎就绪 · wasm', 'ready');
      el.analyzeBtn.disabled = false;
      el.exportBtn.disabled = false;
      runAnalysis();
    } catch (err) {
      setEngineStatus('引擎加载失败：' + err.message, 'error');
      el.parseNote.textContent = '无法加载 audit.wasm。请通过本地 HTTP 服务打开页面（例如 python3 -m http.server），或确认 audit.wasm 与页面在同一目录。';
      el.parseNote.className = 'parse-note warn';
    }
  }

  function callEngine(files) {
    var payload = JSON.stringify({ files: files.map(function (f) { return { name: f.name, src: f.src }; }) });
    var raw = window.solrecon.analyze(payload);
    var rep = JSON.parse(raw);
    if (rep.error) throw new Error(rep.error);
    return rep;
  }

  // ---------- analysis ----------
  function runAnalysis() {
    if (!state.engineReady) return;
    try {
      state.report = callEngine(state.files);
    } catch (err) {
      el.parseNote.textContent = '分析失败：' + err.message;
      el.parseNote.className = 'parse-note warn';
      return;
    }
    renderResults();
    renderEditor();
  }

  // ---------- sample list ----------
  function renderSamples() {
    var host = el.sampleList;
    host.innerHTML = '';
    state.groups.forEach(function (g) {
      var wrap = document.createElement('div');
      wrap.className = 'sample-group';
      var title = document.createElement('div');
      title.className = 'sample-group-title';
      title.innerHTML = '<span class="dot"></span>' + escapeHtml(g.title);
      wrap.appendChild(title);
      g.items.forEach(function (item) {
        var btn = document.createElement('button');
        btn.className = 'sample-item' + (item.id === state.activeId ? ' active' : '');
        btn.dataset.id = item.id;
        var bad = item.variant === 'vulnerable';
        btn.innerHTML =
          '<span class="name">' + escapeHtml(item.name) + '</span>' +
          '<span class="meta"><span class="badge ' + (bad ? 'bad' : 'good') + '">' +
          (bad ? '问题版' : '修复版') + '</span></span>';
        btn.addEventListener('click', function () { openSample(item); });
        wrap.appendChild(btn);
      });
      host.appendChild(wrap);
    });
  }

  function openSample(item) {
    // replace the working set with this group's vulnerable+fixed pair, so the
    // comparison tabs are always side by side
    var g = state.groups.filter(function (x) { return x.id === item.group; })[0];
    state.files = g.items.map(toFile);
    state.activeId = item.id;
    state.selected = null;
    state.openFindings = {};
    state.filter = 'all';
    el.fileInput.value = '';
    syncChips();
    renderSamples();
    renderTabs();
    runAnalysis();
  }

  function toFile(item) {
    // The engine identifies files by name, so the working name must be unique
    // even when the vulnerable and fixed samples share a basename. The tab and
    // headings use `label`.
    return {
      id: item.id,
      name: item.id,
      label: item.name,
      src: item.src,
      variant: item.variant,
      group: item.group,
      lines: item.src.replace(/\r\n/g, '\n').split('\n'),
    };
  }

  // ---------- tabs ----------
  function renderTabs() {
    el.tabs.innerHTML = '';
    state.files.forEach(function (f) {
      var t = document.createElement('button');
      t.className = 'tab' + (f.id === state.activeId ? ' active' : '');
      var count = findingsForFile(f.name).length;
      var vlabel = f.variant === 'vulnerable' ? '问题版' : f.variant === 'fixed' ? '修复版' : '本地';
      t.innerHTML = escapeHtml(f.label || f.name) +
        '<span class="tl">' + vlabel + (count ? ' · ' + count : '') + '</span>';
      t.addEventListener('click', function () {
        state.activeId = f.id;
        state.selected = null;
        renderTabs();
        renderEditor();
        renderResults();
      });
      el.tabs.appendChild(t);
    });
  }

  function activeFile() {
    return state.files.filter(function (f) { return f.id === state.activeId; })[0] || state.files[0];
  }

  // ---------- findings ----------
  function findingsForFile(name) {
    if (!state.report) return [];
    return state.report.findings.filter(function (f) { return f.file === name; });
  }

  function visibleFindings() {
    if (!state.report) return [];
    return state.report.findings.filter(function (f) {
      return state.filter === 'all' || f.severity === state.filter;
    });
  }

  // ---------- editor ----------
  function renderEditor() {
    var f = activeFile();
    if (!f) {
      el.code.innerHTML = '<div class="empty-state">从左侧选择一个样例，或打开本地文件</div>';
      el.meta.textContent = '';
      return;
    }
    var fileFindings = findingsForFile(f.name);
    var hitsByLine = {};
    fileFindings.forEach(function (fd) {
      var key = fd.line;
      if (!hitsByLine[key] || SEV_ORDER[fd.severity] < SEV_ORDER[hitsByLine[key].severity]) {
        hitsByLine[key] = fd;
      }
    });

    var hl = window.SolHighlight.highlightLine;
    var gutter = document.createElement('div');
    gutter.className = 'gutter';
    var lines = document.createElement('div');
    lines.className = 'lines';

    f.lines.forEach(function (text, idx) {
      var lineNo = idx + 1;
      var hit = hitsByLine[lineNo];
      var g = document.createElement('div');
      g.className = 'ln' + (hit ? ' hit-' + hit.severity : '');
      g.textContent = lineNo;
      g.dataset.line = lineNo;
      g.addEventListener('click', function () {
        if (hit) revealFinding(hit);
      });
      gutter.appendChild(g);

      var row = document.createElement('div');
      row.className = 'line' + (hit ? ' mark mark-' + hit.severity : '');
      row.dataset.line = lineNo;
      row.innerHTML = hl(text) || '&nbsp;';
      if (hit) {
        var marker = document.createElement('span');
        marker.className = 'marker s-' + hit.severity;
        marker.title = hit.rule + ' · ' + SEV_LABEL[hit.severity] + ' · ' + hit.title;
        marker.addEventListener('click', function () { revealFinding(hit); });
        row.appendChild(marker);
      }
      lines.appendChild(row);
    });

    el.code.innerHTML = '';
    el.code.appendChild(gutter);
    el.code.appendChild(lines);

    var meta = state.report && state.report.files.filter(function (m) { return m.name === f.name; })[0];
    el.meta.textContent = (meta ? (meta.pragma || '无 pragma') + ' · ' : '') + f.lines.length + ' 行 · ' + fileFindings.length + ' 个问题';
    renderParseNote(f);
  }

  function renderParseNote(f) {
    var rep = state.report;
    if (!rep) return;
    var diags = (rep.diagnostics || []).filter(function (d) { return d.file === f.name; });
    if (diags.length) {
      var first = diags[0];
      el.parseNote.textContent = '解析提示 ' + diags.length + ' 条（首个：第 ' + first.line + ' 行 ' + first.message + '）— 文件其余部分仍会被分析';
      el.parseNote.className = 'parse-note warn';
    } else {
      el.parseNote.textContent = '解析完成，无语法告警';
      el.parseNote.className = 'parse-note';
    }
  }

  // ---------- results ----------
  function renderResults() {
    if (!state.report) return;
    var s = state.report.summary;
    var bySev = s.bySeverity || {};
    $('c-all').textContent = s.total || 0;
    $('c-high').textContent = bySev.high || 0;
    $('c-medium').textContent = bySev.medium || 0;
    $('c-low').textContent = bySev.low || 0;
    $('c-info').textContent = bySev.info || 0;

    var catBits = Object.keys(CAT_LABEL).map(function (c) {
      var n = (s.byCategory || {})[c] || 0;
      return n ? '<span>' + CAT_LABEL[c] + ' <b>' + n + '</b></span>' : '';
    }).join('');
    el.summary.innerHTML =
      '<span>共 <b>' + (s.total || 0) + '</b> 项</span>' +
      '<span>文件 <b>' + s.files + '</b> · 合约 <b>' + s.contracts + '</b> · 函数 <b>' + s.functions + '</b></span>' +
      (catBits || (s.total === 0 ? '<span class="no-findings">未发现问题</span>' : ''));

    var list = visibleFindings();
    if (!list.length) {
      el.findingList.innerHTML = '<div class="empty-state">' +
        (s.total === 0
          ? '<div class="big">✓</div>对照样例在这一组规则下没有告警。<br>切换左侧“问题版”查看命中示例。'
          : '当前筛选下没有问题。') +
        '</div>';
      return;
    }

    var host = el.findingList;
    host.innerHTML = '';
    list.forEach(function (fd, i) {
      host.appendChild(renderFindingCard(fd, i));
    });
  }

  function findingKey(fd) {
    return fd.rule + '@' + fd.file + ':' + fd.line + ':' + fd.function;
  }

  function renderFindingCard(fd, index) {
    var key = findingKey(fd);
    var open = state.openFindings[key] || (state.selected && findingKey(state.selected) === key);
    var card = document.createElement('div');
    card.className = 'finding' + (open ? ' selected' : '');
    card.dataset.key = key;

    var head = document.createElement('div');
    head.className = 'finding-head';
    head.innerHTML =
      '<span class="sev-bar ' + fd.severity + '"></span>' +
      '<div class="finding-title">' +
        '<div class="t">' + escapeHtml(fd.title) + '</div>' +
        '<div class="loc">' +
          '<span class="rule-tag">' + fd.rule + '</span>' +
          '<span>' + escapeHtml(labelFor(fd.file)) + ':' + fd.line + '</span>' +
          '<span>' + escapeHtml(fd.contract || '') + (fd.function ? ' · ' + escapeHtml(fd.function) : '') + '</span>' +
          '<span>' + SEV_LABEL[fd.severity] + '危 · 置信度 ' + (fd.confidence || '-') + '</span>' +
        '</div>' +
      '</div>';
    head.addEventListener('click', function () {
      state.openFindings[key] = !open;
      if (!open) {
        state.selected = fd;
        state.activeId = fileIdFor(fd.file);
        renderEditor();
        scrollToLine(fd.line);
        renderTabs();
      }
      renderResults();
    });
    card.appendChild(head);

    if (open) {
      state.selected = fd;
      var body = document.createElement('div');
      body.className = 'finding-body';
      var snippet = fd.snippet ? renderSnippet(fd) : '';
      body.innerHTML =
        '<div class="label">问题</div><p>' + escapeHtml(fd.message) + '</p>' +
        snippet +
        '<div class="label">怎么被利用</div><p class="exploit">' + escapeHtml(fd.exploit) + '</p>' +
        '<div class="label">怎么修</div><p class="fix">' + escapeHtml(fd.fix) + '</p>' +
        (fd.relatedLine ? '<div class="label">关联位置</div><p>第 ' + fd.relatedLine + ' 行 · ' + escapeHtml(fd.relatedTag || '') + '</p>' : '');
      card.appendChild(body);
    }
    return card;
  }

  function renderSnippet(fd) {
    var f = state.files.filter(function (x) { return x.name === fd.file; })[0];
    if (!f) return '';
    var from = Math.max(1, fd.line - 1);
    var to = Math.min(f.lines.length, (fd.endLine || fd.line) + 1);
    var out = [];
    for (var n = from; n <= to; n++) {
      var text = f.lines[n - 1] || '';
      var cls = n === fd.line || (fd.relatedLine && n === fd.relatedLine) ? ' class="hl"' : '';
      out.push('<span' + cls + '>' + String(n).padStart(4, ' ') + '  ' + escapeHtml(text) + '</span>');
    }
    return '<div class="snippet">' + out.join('\n') + '</div>';
  }

  function labelFor(name) {
    var f = state.files.filter(function (x) { return x.name === name; })[0];
    return f ? (f.label || f.name) : name;
  }

  function fileIdFor(name) {
    var f = state.files.filter(function (x) { return x.name === name; })[0];
    return f ? f.id : state.activeId;
  }

  function revealFinding(fd) {
    state.selected = fd;
    state.openFindings[findingKey(fd)] = true;
    state.filter = 'all';
    syncChips();
    state.activeId = fileIdFor(fd.file);
    renderTabs();
    renderEditor();
    renderResults();
    scrollToLine(fd.line);
    // scroll the finding card into view
    var card = el.findingList.querySelector('.finding.selected');
    if (card) card.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }

  function scrollToLine(line) {
    var row = el.code.querySelector('.line[data-line="' + line + '"]');
    if (row) row.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }

  // ---------- filters ----------
  function syncChips() {
    Array.prototype.forEach.call(el.sevFilters.querySelectorAll('.chip'), function (c) {
      c.classList.toggle('active', c.dataset.sev === state.filter);
    });
  }

  // ---------- dialogs ----------
  function openDialog(title, html) {
    $('dialog-title').textContent = title;
    $('dialog-body').innerHTML = html;
    el.dialog.showModal();
  }

  function showCoverage() {
    var cov = state.report && state.report.coverage;
    if (!cov) return;
    function list(items) {
      return '<ul>' + items.map(function (x) { return '<li>' + escapeHtml(x) + '</li>'; }).join('') + '</ul>';
    }
    openDialog('支持的 Solidity 语法范围',
      '<h3>完整支持</h3>' + list(cov.supported) +
      '<h3>部分支持（可能漏报或需人工复核）</h3>' + list(cov.partial) +
      '<h3>不在范围内</h3>' + list(cov.notCovered) +
      '<h3>说明</h3><p>解析器是手写的容错递归下降实现，遇到不认识的语法会跳过该声明并记录一条解析提示，而不是整份文件失败。分析结论是静态启发式，用于自查与外包代码初审，不能替代人工审计。</p>');
  }

  function showRules() {
    var cat = state.report && state.report.catalog;
    if (!cat) return;
    var html = cat.map(function (r) {
      return '<div class="rule-card">' +
        '<div class="rh"><span class="rule-tag">' + r.id + '</span>' +
        '<span class="t">' + escapeHtml(r.title) + '</span>' +
        '<span class="chip ' + r.defaultSeverity + ' active">' + SEV_LABEL[r.defaultSeverity] + '</span></div>' +
        '<div>' + escapeHtml(r.summary) + '</div>' +
        '<div style="margin-top:5px;color:var(--fg-faint)">判定方式：' + escapeHtml(r.how) + '</div>' +
        '</div>';
    }).join('');
    openDialog('检查规则', html);
  }

  // ---------- files ----------
  function openLocalFiles(fileList) {
    var files = Array.prototype.slice.call(fileList).filter(function (f) {
      return /\.sol$/i.test(f.name) || f.type === 'text/plain';
    });
    if (!files.length) return;
    Promise.all(files.map(function (f) {
      return f.text().then(function (text) {
        return { name: f.name, src: text, variant: 'local' };
      });
    })).then(function (loaded) {
      state.files = loaded.map(function (x, i) {
        var id = 'local:' + i + ':' + x.name;
        return {
          id: id, name: id, label: x.name, src: x.src,
          variant: 'local', group: null,
          lines: x.src.replace(/\r\n/g, '\n').split('\n'),
        };
      });
      state.activeId = state.files[0].id;
      state.selected = null;
      state.openFindings = {};
      el.fileInput.value = '';
      renderTabs();
      runAnalysis();
    });
  }

  // ---------- export ----------
  function exportJson() {
    if (!state.report) return;
    var blob = new Blob([JSON.stringify(state.report, null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'solrecon-report.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }

  // ---------- utils ----------
  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ---------- boot ----------
  function init() {
    el.status = $('engine-status');
    el.analyzeBtn = $('btn-analyze');
    el.exportBtn = $('btn-export');
    el.sampleList = $('sample-list');
    el.tabs = $('tabs');
    el.meta = $('editor-meta');
    el.code = $('code');
    el.parseNote = $('parse-note');
    el.summary = $('summary');
    el.findingList = $('finding-list');
    el.sevFilters = $('sev-filters');
    el.dialog = $('info-dialog');
    el.fileInput = $('file-input');

    state.groups = window.SOL_SAMPLES || [];
    var first = null;
    state.groups.forEach(function (g) {
      g.items.forEach(function (it) { if (!first && it.variant === 'vulnerable') first = it; });
    });
    if (first) {
      var g = state.groups.filter(function (x) { return x.id === first.group; })[0];
      state.files = g.items.map(toFile);
      state.activeId = first.id;
    }
    renderSamples();
    renderTabs();
    renderEditor();

    el.analyzeBtn.addEventListener('click', runAnalysis);
    el.exportBtn.addEventListener('click', exportJson);
    el.fileInput.addEventListener('change', function (e) { openLocalFiles(e.target.files); });
    $('btn-coverage').addEventListener('click', showCoverage);
    $('btn-rules').addEventListener('click', showRules);
    $('dialog-close').addEventListener('click', function () { el.dialog.close(); });

    Array.prototype.forEach.call(el.sevFilters.querySelectorAll('.chip'), function (c) {
      c.addEventListener('click', function () {
        state.filter = c.dataset.sev;
        syncChips();
        renderResults();
      });
    });

    bootEngine();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
