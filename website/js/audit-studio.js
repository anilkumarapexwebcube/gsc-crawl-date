/* GSC Audit Studio - Web Edition
 * Replaces the Chrome-extension service worker with browser equivalents:
 *   - chrome.identity.launchWebAuthFlow  ->  Google Identity Services token client
 *   - chrome.storage.local               ->  localStorage
 *   - chrome.downloads                   ->  blob / data-URL anchor download
 *   - chrome.debugger screenshot capture ->  manual screenshot upload
 * The PPTX builders (report-builder.js / format-omega.js / format-neon.js) are reused unchanged.
 */
(function () {
  'use strict';

  // ---- Defaults ----
  // NOTE: No OAuth Client ID is shipped on purpose. OAuth clients are tied to an exact
  // origin ("Authorized JavaScript origins"), so a shared/hardcoded client ID can never
  // work on someone else's deployment - that is exactly what produces Google's
  // "no registered origin / Error 401: invalid_client" page. Each deployment registers
  // its OWN Web OAuth client and enters the Client ID in the Setup tab.
  const DEFAULTS = {
    appsScriptUrl: 'https://script.google.com/macros/s/AKfycbydUPonVySIRG_Icz2ygWRmDJ1_qEGjhS9vMP9INZF5_f_sD1ZX2d7kRnOqN8YbWeN_/exec'
  };

  const SCOPES = [
    'https://www.googleapis.com/auth/webmasters.readonly',
    'https://www.googleapis.com/auth/userinfo.email'
  ].join(' ');

  const API_BASE = 'https://searchconsole.googleapis.com/v1';
  const API_BASE_OLD = 'https://www.googleapis.com/webmasters/v3';

  const LS_CONFIG = 'gsc_audit_config';
  const LS_ACCOUNTS = 'gsc_audit_accounts';
  const LS_MAPPING = 'gsc_audit_mapping';
  const LS_MAPPING_META = 'gsc_audit_mapping_meta';

  const $ = (id) => document.getElementById(id);

  // ===================== storage helpers =====================
  function getConfig() {
    try {
      const c = JSON.parse(localStorage.getItem(LS_CONFIG) || '{}');
      return { clientId: c.clientId || '', appsScriptUrl: c.appsScriptUrl || '' };
    } catch (_) { return { clientId: '', appsScriptUrl: '' }; }
  }
  function saveConfig(cfg) { localStorage.setItem(LS_CONFIG, JSON.stringify(cfg)); }
  // Access tokens grant access to the user's Search Console data, so they are kept in
  // sessionStorage (cleared when the tab closes) rather than localStorage (persists
  // indefinitely and is readable long after the user walks away). Non-sensitive config
  // and the domain mapping stay in localStorage.
  function getAccounts() {
    try { return JSON.parse(sessionStorage.getItem(LS_ACCOUNTS) || '{}'); } catch (_) { return {}; }
  }
  function saveAccounts(a) { sessionStorage.setItem(LS_ACCOUNTS, JSON.stringify(a)); }

  let MAPPING = {};
  let MAPPING_META = {};
  function loadMappingFromLS() {
    try { MAPPING = JSON.parse(localStorage.getItem(LS_MAPPING) || '{}'); } catch (_) { MAPPING = {}; }
    try { MAPPING_META = JSON.parse(localStorage.getItem(LS_MAPPING_META) || '{}'); } catch (_) { MAPPING_META = {}; }
  }
  function saveMappingToLS() {
    localStorage.setItem(LS_MAPPING, JSON.stringify(MAPPING));
    localStorage.setItem(LS_MAPPING_META, JSON.stringify(MAPPING_META));
  }

  // Screenshots uploaded by the user (data URLs), shared across the run
  const SHOTS = { sitemap: null, manualAction: null, performance: null, security: null };
  const DOMAIN_FORMATS = {};

  // ===================== logging =====================
  const logEl = $('audit-log');
  const progressFill = $('audit-progress-fill');
  function log(msg, cls = '') {
    const time = new Date().toLocaleTimeString();
    const line = document.createElement('span');
    line.className = cls;
    line.textContent = `[${time}] ${msg}\n`;
    logEl.appendChild(line);
    logEl.scrollTop = logEl.scrollHeight;
  }
  const progressPct = $('audit-progress-pct');
  function setProgress(pct) {
    const v = Math.max(0, Math.min(100, Math.round(pct)));
    progressFill.style.width = v + '%';
    if (progressPct) progressPct.textContent = v + '%';
  }
  function escapeHtml(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

  // ===================== OAuth (Google Identity Services) =====================
  function gisReady() { return !!(window.google && google.accounts && google.accounts.oauth2); }

  // Turn Google's terse OAuth failures into a clear, actionable message. The most common
  // one is "no registered origin / invalid_client": the OAuth client doesn't list this
  // page's address under Authorized JavaScript origins.
  function friendlyOauthError(e) {
    const origin = window.location.origin;
    const msg = (e && (e.message || e.type)) ? (e.message || e.type) : String(e);
    if (/registered origin|invalid_client|redirect_uri|access blocked|\b401\b/i.test(msg)) {
      return 'Google blocked sign-in: this page\'s address is not authorized on your OAuth client.\n\n' +
        'Fix it in Google Cloud Console -> your OAuth Web client -> "Authorized JavaScript origins" -> add exactly:\n\n    ' + origin + '\n\n' +
        'then paste that client\'s ID in the Setup tab. (Google said: ' + msg + ')';
    }
    if (/popup_closed|popup_failed|user.?cancel|cancelled|canceled/i.test(msg)) {
      return 'Sign-in window closed before finishing. If you saw "Access blocked: no registered origin", add this origin to your OAuth client\'s Authorized JavaScript origins:\n\n    ' + origin;
    }
    return msg;
  }

  function requestToken(email, interactive) {
    return new Promise((resolve, reject) => {
      if (!gisReady()) return reject(new Error('Google sign-in library not loaded yet. Check your internet connection and reload.'));
      const cfg = getConfig();
      if (!cfg.clientId) return reject(new Error('OAuth Client ID not set. Open the Setup tab.'));
      let settled = false;
      const client = google.accounts.oauth2.initTokenClient({
        client_id: cfg.clientId,
        scope: SCOPES,
        hint: email || undefined,
        prompt: interactive ? 'consent' : '',
        callback: (resp) => {
          if (settled) return; settled = true;
          if (resp.error) return reject(new Error(resp.error_description || resp.error));
          resolve(resp); // { access_token, expires_in, ... }
        },
        error_callback: (err) => {
          if (settled) return; settled = true;
          reject(new Error((err && (err.message || err.type)) || 'OAuth was cancelled or failed.'));
        }
      });
      client.requestAccessToken();
    });
  }

  async function oauthLogin(emailHint) {
    const resp = await requestToken(emailHint, true);
    const token = resp.access_token;
    let email = (emailHint || '').toLowerCase();
    try {
      const u = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', { headers: { Authorization: 'Bearer ' + token } });
      const user = await u.json();
      if (user.email) email = user.email.toLowerCase();
    } catch (_) { /* keep hint */ }

    const accounts = getAccounts();
    accounts[email] = {
      email,
      access_token: token,
      expires_at: Date.now() + ((resp.expires_in || 3600) * 1000) - 60000,
      last_login: Date.now()
    };
    saveAccounts(accounts);
    return { email };
  }

  async function getAccessToken(email) {
    email = (email || '').toLowerCase();
    const accounts = getAccounts();
    const acc = accounts[email];
    if (acc && acc.access_token && acc.expires_at > Date.now()) return acc.access_token;

    // Token missing or expired: try a silent refresh (no UI if session + grant exist)
    const resp = await requestToken(email, false);
    const token = resp.access_token;
    accounts[email] = {
      email,
      access_token: token,
      expires_at: Date.now() + ((resp.expires_in || 3600) * 1000) - 60000,
      last_login: (acc && acc.last_login) || Date.now()
    };
    saveAccounts(accounts);
    return token;
  }

  function listStoredAccounts() {
    return Object.values(getAccounts()).map(a => ({ email: a.email, last_login: a.last_login }));
  }
  function removeAccount(email) {
    const accounts = getAccounts();
    delete accounts[(email || '').toLowerCase()];
    saveAccounts(accounts);
  }

  // ===================== Apps Script bridge =====================
  async function fetchAppsScriptConfig(url) {
    if (!url) throw new Error('Apps Script URL not configured. Open Setup.');
    const fullUrl = url + (url.includes('?') ? '&' : '?') + 'action=get_config';
    const resp = await fetch(fullUrl, { method: 'GET', redirect: 'follow', cache: 'no-cache', credentials: 'omit', headers: { 'Accept': 'application/json, text/plain, */*' } });
    if (!resp.ok) throw new Error(`Apps Script returned HTTP ${resp.status}.`);
    const text = await resp.text();
    let data;
    try { data = JSON.parse(text); }
    catch (e) { throw new Error('Apps Script did not return JSON. Set its deployment access to "Anyone". Response: ' + text.substring(0, 160)); }
    if (!data.success) throw new Error('Apps Script error: ' + (data.error || 'unknown'));
    return data;
  }
  async function pingAppsScript(url) {
    if (!url) throw new Error('Apps Script URL not configured.');
    const fullUrl = url + (url.includes('?') ? '&' : '?') + 'action=ping';
    const resp = await fetch(fullUrl, { method: 'GET', redirect: 'follow', credentials: 'omit', headers: { 'Accept': 'application/json, text/plain, */*' } });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}.`);
    const text = await resp.text();
    try { return JSON.parse(text); } catch (_) { return { raw: text }; }
  }

  // ===================== GSC API helpers =====================
  async function apiCall(token, url, body = null) {
    const opts = { method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${token}` } };
    if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    const resp = await fetch(url, opts);
    if (!resp.ok) { const txt = await resp.text(); throw new Error(`API ${resp.status}: ${txt.substring(0, 200)}`); }
    return resp.json();
  }

  async function resolveProperty(token, domain, accessLevel) {
    const candidates = [];
    if (accessLevel && accessLevel.toLowerCase().includes('domain')) {
      candidates.push(`sc-domain:${domain}`, `https://${domain}/`, `https://www.${domain}/`);
    } else {
      candidates.push(`https://www.${domain}/`, `https://${domain}/`, `sc-domain:${domain}`, `http://www.${domain}/`, `http://${domain}/`);
    }
    const sitesResp = await apiCall(token, `${API_BASE_OLD}/sites`);
    const accessibleSites = (sitesResp.siteEntry || []).map(s => s.siteUrl);
    for (const c of candidates) if (accessibleSites.includes(c)) return c;
    for (const s of accessibleSites) if (s.includes(domain)) return s;
    throw new Error(`No property found for ${domain} on this account. Accessible sites: ${accessibleSites.slice(0, 5).join(', ')}`);
  }

  async function fetchAllApiData(token, propertyUrl, startDate, endDate, prevStart, prevEnd) {
    const encoded = encodeURIComponent(propertyUrl);
    const [sitemapsResp, perfDaily, perfQuery, perfPage, perfImage, perfPrev] = await Promise.all([
      apiCall(token, `${API_BASE_OLD}/sites/${encoded}/sitemaps`).catch(e => ({ sitemap: [], _err: e.message })),
      apiCall(token, `${API_BASE_OLD}/sites/${encoded}/searchAnalytics/query`, { startDate, endDate, dimensions: ['date'], rowLimit: 1000 }).catch(e => ({ rows: [], _err: e.message })),
      apiCall(token, `${API_BASE_OLD}/sites/${encoded}/searchAnalytics/query`, { startDate, endDate, dimensions: ['query'], rowLimit: 10 }).catch(e => ({ rows: [], _err: e.message })),
      apiCall(token, `${API_BASE_OLD}/sites/${encoded}/searchAnalytics/query`, { startDate, endDate, dimensions: ['page'], rowLimit: 10 }).catch(e => ({ rows: [], _err: e.message })),
      apiCall(token, `${API_BASE_OLD}/sites/${encoded}/searchAnalytics/query`, { startDate, endDate, dimensions: ['query'], type: 'image', rowLimit: 100 }).catch(e => ({ rows: [], _err: e.message })),
      apiCall(token, `${API_BASE_OLD}/sites/${encoded}/searchAnalytics/query`, { startDate: prevStart, endDate: prevEnd, dimensions: ['query'], rowLimit: 50 }).catch(e => ({ rows: [], _err: e.message }))
    ]);
    return {
      sitemaps: sitemapsResp.sitemap || [],
      perfDaily: perfDaily.rows || [],
      topQueries: perfQuery.rows || [],
      topPages: perfPage.rows || [],
      imagePerf: perfImage.rows || [],
      prevPerf: perfPrev.rows || []
    };
  }

  function buildInspectionList(propertyUrl, topPages) {
    const urls = new Set();
    if (propertyUrl.startsWith('sc-domain:')) urls.add(`https://www.${propertyUrl.replace('sc-domain:', '')}/`);
    else urls.add(propertyUrl);
    topPages.slice(0, 10).forEach(p => urls.add(p.keys[0]));
    return [...urls].slice(0, 11);
  }
  async function inspectUrl(token, propertyUrl, inspectionUrl) {
    const result = await apiCall(token, `${API_BASE}/urlInspection/index:inspect`, { inspectionUrl, siteUrl: propertyUrl, languageCode: 'en-US' });
    return result.inspectionResult || {};
  }

  function daysAgo(n) { const d = new Date(); d.setDate(d.getDate() - n); return d; }
  function ymd(d) { return d.toISOString().slice(0, 10); }
  function cleanDomain(d) { return d.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, ''); }
  function formatTime(iso) { if (!iso) return 'never'; try { return new Date(iso).toLocaleString(); } catch (_) { return iso; } }

  // ===================== Run audit =====================
  async function runAuditForDomain(domain, opts) {
    const info = MAPPING[domain];
    if (!info || !info.email) throw new Error(`Domain "${domain}" not found in master sheet. Add it to GSC_Config, or click "Refresh domain list" and retry.`);

    const format = DOMAIN_FORMATS[domain] || $('default-format').value || 'james';
    log(`  Format: ${format.toUpperCase()}`);
    log(`  Account: ${info.email}`);

    let token;
    try { token = await getAccessToken(info.email); }
    catch (e) {
      log(`  Need to connect ${info.email}, launching sign-in...`, 'warn');
      await oauthLogin(info.email);
      token = await getAccessToken(info.email);
    }

    const propertyUrl = await resolveProperty(token, domain, info.accessLevel);
    log(`  Property: ${propertyUrl}`);

    const endDate = ymd(daysAgo(opts.endOffset));
    const startDate = ymd(daysAgo(opts.endOffset + opts.periodDays - 1));
    const prevEnd = ymd(daysAgo(opts.endOffset + opts.periodDays));
    const prevStart = ymd(daysAgo(opts.endOffset + opts.periodDays * 2 - 1));

    let reportData = { domain, propertyUrl, startDate, endDate, prevStart, prevEnd, periodDays: opts.periodDays };

    if (format === 'james') {
      log(`  Period: ${startDate} -> ${endDate}  vs  ${prevStart} -> ${prevEnd}`);
      log(`  Fetching API data...`);
      const apiData = await fetchAllApiData(token, propertyUrl, startDate, endDate, prevStart, prevEnd);
      log(`  API data fetched. ${apiData.sitemaps.length} sitemap(s), ${apiData.topPages.length} top pages.`);

      log(`  Inspecting URLs...`);
      const urlsToInspect = buildInspectionList(propertyUrl, apiData.topPages);
      apiData.inspections = [];
      for (const url of urlsToInspect) {
        try { const insp = await inspectUrl(token, propertyUrl, url); apiData.inspections.push({ url, ...insp }); }
        catch (e) { apiData.inspections.push({ url, error: e.message }); }
      }
      log(`  Inspected ${apiData.inspections.length} URLs.`);
      Object.assign(reportData, apiData);

      if (opts.includeManualAction && SHOTS.manualAction) { reportData.manualActionScreenshot = SHOTS.manualAction; log(`  Manual Action screenshot attached.`, 'ok'); }
      else if (opts.includeManualAction) log(`  No Manual Action screenshot uploaded — slide skipped.`, 'warn');
      if (opts.includeSecurity && SHOTS.security) { reportData.securityScreenshot = SHOTS.security; log(`  Security screenshot attached.`, 'ok'); }
      else if (opts.includeSecurity) log(`  No Security screenshot uploaded — slide skipped.`, 'warn');
    } else {
      // Omega / Neon: screenshot-driven. Use uploaded screenshots (placeholders if blank).
      reportData.sitemapScreenshot = SHOTS.sitemap;
      reportData.manualActionScreenshot = SHOTS.manualAction;
      reportData.performanceScreenshot = SHOTS.performance;
      reportData.securityScreenshot = SHOTS.security;
      const have = ['sitemap', 'manualAction', 'performance', 'security'].filter(k => SHOTS[k]).length;
      log(`  ${have}/4 screenshots provided. Missing ones render a placeholder slide.`, have === 4 ? 'ok' : 'warn');
    }

    log(`  Building PPTX (${format})...`);
    const dataUrl = await buildPptxReport(reportData, format);
    const filename = `GSC_Audit_${format}_${domain.replace(/[^a-z0-9]/gi, '_')}_${endDate}.pptx`;
    deliverReport(dataUrl, filename);
    log(`  Report ready — click Download below: ${filename}`, 'ok');
  }

  // ===================== report delivery + list =====================
  const GENERATED = []; // { filename, url(blob), size }

  function dataUrlToBlob(dataUrl) {
    const [head, b64] = dataUrl.split(',');
    const mime = (head.match(/data:([^;]+)/) || [])[1] || 'application/octet-stream';
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new Blob([bytes], { type: mime });
  }

  function deliverReport(dataUrl, filename) {
    // No auto-download. The report is only added to the list once it is fully built,
    // so its Download button is the only way to save it — and it only exists when ready.
    const blob = dataUrlToBlob(dataUrl);
    const url = URL.createObjectURL(blob); // kept alive so the Download button works
    GENERATED.unshift({ filename, url, size: blob.size });
    renderReports();
  }

  function fmtSize(bytes) {
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
    return Math.max(1, Math.round(bytes / 1024)) + ' KB';
  }

  function renderReports() {
    const card = $('audit-reports-card');
    const list = $('audit-reports');
    if (!card || !list) return;
    if (!GENERATED.length) { card.style.display = 'none'; list.innerHTML = ''; return; }
    card.style.display = 'block';
    list.innerHTML = GENERATED.map((r) =>
      `<div class="report-row">
        <div class="report-meta">
          <span class="report-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>
          </span>
          <div><div class="report-name">${escapeHtml(r.filename)}</div><div class="report-size mono">${fmtSize(r.size)} · PPTX</div></div>
        </div>
        <a class="btn btn-primary btn-sm" href="${r.url}" download="${escapeHtml(r.filename)}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          Download
        </a>
      </div>`).join('');
  }

  const reportsClearBtn = $('audit-reports-clear');
  if (reportsClearBtn) reportsClearBtn.addEventListener('click', () => {
    GENERATED.forEach(r => { try { URL.revokeObjectURL(r.url); } catch (_) {} });
    GENERATED.length = 0;
    renderReports();
  });

  // ===================== UI: subtabs =====================
  function switchSub(name) {
    // Domain List + Setup are admin-only. Block access for regular users and offer unlock.
    if ((name === 'domains' || name === 'setup') && !(window.GSCAdmin && GSCAdmin.isAdmin())) {
      if (window.GSCAdmin) GSCAdmin.requestUnlock();
      return;
    }
    document.querySelectorAll('.subtab').forEach(b => b.classList.toggle('active', b.dataset.sub === name));
    document.querySelectorAll('.subpanel').forEach(p => p.classList.toggle('active', p.id === 'sub-' + name));
    if (name === 'accounts') refreshAccounts();
    if (name === 'domains') refreshMapping();
    if (name === 'setup') loadSettingsUI();
  }
  document.getElementById('auditSubtabs').addEventListener('click', (e) => {
    const b = e.target.closest('.subtab'); if (b) switchSub(b.dataset.sub);
  });
  document.addEventListener('click', (e) => {
    const l = e.target.closest('[data-sub-link]'); if (l) { e.preventDefault(); switchSub(l.dataset.subLink); }
  });

  // ===================== UI: setup =====================
  function loadSettingsUI() {
    const cfg = getConfig();
    $('client-id').value = cfg.clientId || '';
    $('apps-script-url').value = cfg.appsScriptUrl || '';
    $('page-origin').textContent = window.location.origin || '(open this page from a web server)';
  }
  $('save-settings-btn').addEventListener('click', () => {
    const cfg = getConfig();
    cfg.clientId = $('client-id').value.trim();
    saveConfig(cfg);
    updateOauthBanner();
    GSCUI.toast('OAuth Client ID saved.', 'success');
  });
  $('save-apps-script-btn').addEventListener('click', async () => {
    const cfg = getConfig();
    cfg.appsScriptUrl = $('apps-script-url').value.trim();
    saveConfig(cfg);
    log('Apps Script URL saved.', 'ok');
    GSCUI.toast('Apps Script URL saved. Refreshing domain list…', 'success');
    await fetchMappingFromAppsScript();
  });
  $('test-apps-script-btn').addEventListener('click', async () => {
    const url = $('apps-script-url').value.trim();
    if (!url) return GSCUI.toast('Enter the Apps Script URL first.', 'warn');
    try { const res = await pingAppsScript(url); await GSCUI.alert(JSON.stringify(res, null, 2), { title: 'Connection OK', type: 'success' }); }
    catch (e) { await GSCUI.alert(e.message, { title: 'Connection failed', type: 'error' }); }
  });

  function updateOauthBanner() {
    const cfg = getConfig();
    const banner = $('oauthNotReady');
    if (banner) banner.style.display = cfg.clientId ? 'none' : 'flex';
  }

  // ===================== UI: accounts =====================
  function refreshAccounts() {
    const accounts = listStoredAccounts();
    const tbody = $('accounts-tbody');
    tbody.innerHTML = '';
    if (accounts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#8a7860">No accounts connected yet.</td></tr>';
      return;
    }
    accounts.forEach(a => {
      const tr = document.createElement('tr');
      const ago = a.last_login ? new Date(a.last_login).toLocaleString() : '-';
      tr.innerHTML = `<td>${escapeHtml(a.email)}</td><td>${ago}</td><td><span class="status-pill ok">Connected</span></td>
        <td><button class="btn btn-ghost btn-sm">Disconnect</button></td>`;
      tr.querySelector('button').addEventListener('click', async () => {
        const ok = await GSCUI.confirm(`Disconnect ${a.email}? You'll need to sign in again next time.`, { title: 'Disconnect account', okLabel: 'Disconnect', danger: true });
        if (ok) { removeAccount(a.email); refreshAccounts(); updateDomainPreview(); GSCUI.toast(`Disconnected ${a.email}.`, 'info'); }
      });
      tbody.appendChild(tr);
    });
  }
  function setAccountsMsg(text, kind) {
    const el = $('accounts-msg');
    if (!el) return;
    if (!text) { el.style.display = 'none'; return; }
    el.className = 'alert ' + (kind === 'ok' ? 'alert-info' : 'alert-warn');
    el.querySelector('.alert-text').textContent = text;
    el.style.display = 'flex';
  }
  $('connect-account-btn').addEventListener('click', async () => {
    const email = $('new-account-email').value.trim();
    const btn = $('connect-account-btn');
    setAccountsMsg('');
    if (!getConfig().clientId) {
      setAccountsMsg('Add your OAuth Client ID in the Setup tab before connecting an account.', 'warn');
      switchSub('setup');
      return;
    }
    btn.disabled = true;
    try {
      const result = await oauthLogin(email || undefined);
      log(`Connected: ${result.email}`, 'ok');
      setAccountsMsg(`Connected ${result.email}.`, 'ok');
      $('new-account-email').value = '';
      refreshAccounts();
      updateDomainPreview();
    } catch (e) {
      const friendly = friendlyOauthError(e);
      log(`Login failed: ${e.message}`, 'err');
      setAccountsMsg(friendly, 'warn');
    } finally { btn.disabled = false; }
  });

  // ===================== UI: domain mapping =====================
  function setMappingStatus(msg, cls) {
    const el = $('mapping-status'); if (!el) return;
    el.textContent = msg;
    el.style.borderLeftColor = cls === 'err' ? 'var(--danger)' : (cls === 'warn' ? 'var(--warning)' : (cls === 'ok' ? 'var(--success)' : 'var(--accent)'));
  }
  async function fetchMappingFromAppsScript() {
    const cfg = getConfig();
    if (!cfg.appsScriptUrl) { setMappingStatus('Apps Script URL not configured. Open Setup.', 'warn'); return null; }
    try {
      setMappingStatus('Fetching from Apps Script...', 'info');
      const data = await fetchAppsScriptConfig(cfg.appsScriptUrl);
      MAPPING = data.mapping || {};
      MAPPING_META = { total: data.total || Object.keys(MAPPING).length, generated: data.generated || new Date().toISOString(), fetchedAt: new Date().toISOString() };
      saveMappingToLS();
      setMappingStatus(`Loaded ${MAPPING_META.total} domains. Last sheet sync: ${formatTime(data.generated)}.`, 'ok');
      renderMappingTable();
      log(`Domain mapping refreshed: ${MAPPING_META.total} domains.`, 'ok');
      return data;
    } catch (e) {
      setMappingStatus(`Fetch failed: ${e.message}`, 'err');
      log(`Apps Script fetch failed: ${e.message}`, 'err');
      return null;
    }
  }
  function renderMappingTable(filter = '') {
    const tbody = $('mapping-tbody');
    tbody.innerHTML = '';
    const rows = Object.entries(MAPPING)
      .filter(([d, info]) => !filter || d.includes(filter) || (info.email || '').includes(filter))
      .sort(([a], [b]) => a.localeCompare(b));
    if (rows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#8a7860">No domains loaded. Click "Refresh from Apps Script".</td></tr>';
      return;
    }
    rows.forEach(([domain, info]) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${escapeHtml(domain)}</td><td>${escapeHtml(info.email)}</td><td>${escapeHtml(info.accessLevel || '')}</td>
        <td><button class="btn btn-ghost btn-sm use-domain-btn">Use</button></td>`;
      tr.querySelector('.use-domain-btn').addEventListener('click', () => {
        const input = $('domains-input');
        const current = input.value.trim();
        input.value = current ? current + '\n' + domain : domain;
        updateDomainPreview();
        switchSub('run');
      });
      tbody.appendChild(tr);
    });
  }
  function refreshMapping() {
    loadMappingFromLS();
    if (Object.keys(MAPPING).length === 0) fetchMappingFromAppsScript();
    else { setMappingStatus(`Showing ${Object.keys(MAPPING).length} cached domains. Last refreshed: ${formatTime(MAPPING_META.fetchedAt)}.`, 'ok'); renderMappingTable(); }
  }
  $('refresh-mapping-btn').addEventListener('click', fetchMappingFromAppsScript);
  $('refresh-mapping-btn-2').addEventListener('click', fetchMappingFromAppsScript);
  $('domain-filter').addEventListener('input', (e) => renderMappingTable(e.target.value.trim().toLowerCase()));
  $('export-mapping-btn').addEventListener('click', () => {
    const rows = [['Domain', 'Account Email', 'Access Level']];
    Object.entries(MAPPING).forEach(([d, info]) => rows.push([d, info.email, info.accessLevel || '']));
    const csv = rows.map(r => r.map(c => `"${(c || '').replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'gsc-audit-mapping.csv'; a.click();
  });

  // ===================== UI: domain preview =====================
  async function updateDomainPreview() {
    loadMappingFromLS();
    const raw = $('domains-input').value.trim();
    const previewEl = $('domain-preview');
    if (!raw) { previewEl.innerHTML = ''; return; }
    const domains = raw.split('\n').map(d => cleanDomain(d)).filter(Boolean);
    const connectedEmails = new Set(listStoredAccounts().map(a => a.email.toLowerCase()));
    const defaultFormat = $('default-format').value;

    previewEl.innerHTML = domains.map(d => {
      const info = MAPPING[d];
      const fmt = DOMAIN_FORMATS[d] || defaultFormat;
      if (!info) {
        return `<div class="domain-preview-row row-err"><span>${escapeHtml(d)}</span><span>Not in master sheet</span><span></span></div>`;
      }
      const connected = connectedEmails.has((info.email || '').toLowerCase());
      const cls = connected ? 'row-ok' : 'row-warn';
      const status = connected ? 'Connected' : 'Sign-in required';
      return `<div class="domain-preview-row ${cls}"><span>${escapeHtml(d)}</span>
        <span>${escapeHtml(info.email)} (${status})</span>
        <select class="format-select" data-domain="${escapeHtml(d)}">
          <option value="james" ${fmt === 'james' ? 'selected' : ''}>James</option>
          <option value="omega" ${fmt === 'omega' ? 'selected' : ''}>Omega</option>
          <option value="neon" ${fmt === 'neon' ? 'selected' : ''}>Neon</option>
        </select></div>`;
    }).join('');

    previewEl.querySelectorAll('.format-select').forEach(sel => {
      sel.addEventListener('change', (e) => { DOMAIN_FORMATS[e.target.dataset.domain] = e.target.value; });
    });
  }
  $('domains-input').addEventListener('input', updateDomainPreview);
  $('default-format').addEventListener('change', updateDomainPreview);

  // ===================== UI: run =====================
  $('run-btn').addEventListener('click', async () => {
    const runBtn = $('run-btn');
    runBtn.disabled = true;
    setProgress(0);
    try {
      log('Refreshing domain list from Apps Script...', 'info');
      try { await fetchMappingFromAppsScript(); }
      catch (e) { log(`  Could not refresh domain list: ${e.message}. Using cached list.`, 'warn'); loadMappingFromLS(); }

      const domainsRaw = $('domains-input').value.trim();
      if (!domainsRaw) { GSCUI.toast('Enter at least one domain.', 'warn'); return; }
      const domains = domainsRaw.split('\n').map(d => cleanDomain(d)).filter(Boolean);

      const opts = {
        includeManualAction: $('include-manual-action').checked,
        includeSecurity: $('include-security').checked,
        periodDays: parseInt($('period-days').value, 10) || 28,
        endOffset: parseInt($('end-offset').value, 10) || 3
      };

      log(`Starting audit for ${domains.length} domain(s)`, 'info');
      for (let i = 0; i < domains.length; i++) {
        const domain = domains[i];
        log(`\n[${i + 1}/${domains.length}] ${domain}`, 'info');
        try { await runAuditForDomain(domain, opts); }
        catch (e) { log(`  FAILED: ${e.message}`, 'err'); }
        setProgress(((i + 1) / domains.length) * 100);
      }
      log('\nAll done.', 'ok');
    } finally { runBtn.disabled = false; }
  });
  $('clear-log-btn').addEventListener('click', () => { logEl.innerHTML = ''; setProgress(0); });

  // ===================== UI: screenshots =====================
  const SHOT_SLOTS = [
    { key: 'sitemap', label: 'Sitemap' },
    { key: 'manualAction', label: 'Manual Action' },
    { key: 'performance', label: 'Performance' },
    { key: 'security', label: 'Security Issues' }
  ];
  function buildShotGrid() {
    const grid = $('shot-grid');
    grid.innerHTML = '';
    SHOT_SLOTS.forEach(slot => {
      const div = document.createElement('div');
      div.className = 'shot-slot';
      div.innerHTML = `
        <button class="ss-clear" title="Remove">&times;</button>
        <div class="ss-label">${slot.label}</div>
        <div class="ss-hint">Click to upload PNG / JPG</div>
        <img alt="" style="display:none">
        <input type="file" accept="image/png,image/jpeg">`;
      const input = div.querySelector('input');
      const img = div.querySelector('img');
      const hint = div.querySelector('.ss-hint');
      const clear = div.querySelector('.ss-clear');

      div.addEventListener('click', (e) => { if (e.target === clear) return; input.click(); });
      input.addEventListener('change', () => {
        const file = input.files[0]; if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
          SHOTS[slot.key] = reader.result;
          img.src = reader.result; img.style.display = 'inline-block';
          hint.textContent = file.name;
          div.classList.add('filled');
        };
        reader.readAsDataURL(file);
      });
      clear.addEventListener('click', (e) => {
        e.stopPropagation();
        SHOTS[slot.key] = null; input.value = '';
        img.src = ''; img.style.display = 'none';
        hint.textContent = 'Click to upload PNG / JPG';
        div.classList.remove('filled');
      });
      grid.appendChild(div);
    });
  }

  // ===================== clear all data =====================
  function clearAllData() {
    [LS_CONFIG, LS_MAPPING, LS_MAPPING_META, LS_ACCOUNTS].forEach(k => localStorage.removeItem(k));
    sessionStorage.removeItem(LS_ACCOUNTS);
    MAPPING = {}; MAPPING_META = {};
    SHOT_SLOTS.forEach(s => { SHOTS[s.key] = null; });
  }
  const clearBtn = $('clear-data-btn');
  if (clearBtn) clearBtn.addEventListener('click', async () => {
    const ok = await GSCUI.confirm('Remove every saved account token, OAuth Client ID, Apps Script URL and cached domain list from this browser?', { title: 'Clear all saved data', okLabel: 'Clear everything', danger: true });
    if (!ok) return;
    clearAllData();
    buildShotGrid();
    loadSettingsUI();
    updateOauthBanner();
    refreshAccounts();
    renderMappingTable();
    setMappingStatus('All saved data cleared.', 'ok');
    GSCUI.toast('All saved data cleared from this browser.', 'success');
  });

  // ===================== init =====================
  (function init() {
    // Security hygiene: purge any access tokens an older build may have persisted in
    // localStorage. Tokens now live only in sessionStorage.
    try { localStorage.removeItem(LS_ACCOUNTS); } catch (_) {}

    // Seed non-sensitive defaults on first run. (No Client ID is seeded — it must be the
    // deployment's own OAuth Web client, see the DEFAULTS note above.)
    const cfg = getConfig();
    let changed = false;
    if (!cfg.appsScriptUrl && DEFAULTS.appsScriptUrl) { cfg.appsScriptUrl = DEFAULTS.appsScriptUrl; changed = true; }
    if (changed) saveConfig(cfg);

    loadMappingFromLS();
    loadSettingsUI();
    updateOauthBanner();
    buildShotGrid();

    if (Object.keys(MAPPING).length > 0) log(`Loaded ${Object.keys(MAPPING).length} cached domains.`, 'info');
  })();
})();
