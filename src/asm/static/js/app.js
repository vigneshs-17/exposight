/* Exposight Dashboard - Client Application Logic
   Uses Supabase JS (UMD) and HTMX.
   Strict Security Constraints:
   - Zero DOM property mutations with raw untrusted data (textContent only)
   - htmx.config.allowEval = false
   - htmx.config.allowScriptTags = false
   - Tokens in module memory, backed by sessionStorage
*/

(function () {
  'use strict';

  // Configure HTMX security settings immediately
  if (window.htmx) {
    window.htmx.config.allowEval = false;
    window.htmx.config.allowScriptTags = false;
  }

  // Module variable holding current JWT access token
  let currentAccessToken = null;
  let isAuthenticated = false;
  let isRefreshing = false;
  let supabaseClient = null;

  // Retrieve configuration from data attributes on document body
  const bodyEl = document.body;
  const supabaseUrl = bodyEl.getAttribute('data-supabase-url') || '';
  const supabaseKey = bodyEl.getAttribute('data-supabase-key') || '';

  if (window.supabase && supabaseUrl && supabaseKey) {
    supabaseClient = window.supabase.createClient(supabaseUrl, supabaseKey, {
      auth: {
        persistSession: true,
        storage: window.sessionStorage,
        autoRefreshToken: true,
        detectSessionInUrl: false,
      },
    });

    supabaseClient.auth.onAuthStateChange(function (event, session) {
      if (session && session.access_token) {
        currentAccessToken = session.access_token;
        if (event === 'TOKEN_REFRESHED') {
          return;
        }
        if ((event === 'SIGNED_IN' || event === 'INITIAL_SESSION') && !isAuthenticated) {
          isAuthenticated = true;
          onUserAuthenticated(session.user);
        }
      } else if (event === 'SIGNED_OUT' || !session) {
        currentAccessToken = null;
        isAuthenticated = false;
        onUserSignedOut();
      }
    });
  }

  // Inject Authorization Bearer token into all HTMX requests synchronously
  document.body.addEventListener('htmx:configRequest', function (evt) {
    if (currentAccessToken) {
      evt.detail.headers['Authorization'] = 'Bearer ' + currentAccessToken;
    }
  });

  // Handle HTMX response errors (e.g. 401 token expiration)
  document.body.addEventListener('htmx:responseError', async function (evt) {
    const xhr = evt.detail.xhr;
    if (xhr && xhr.status === 401 && !isRefreshing && supabaseClient) {
      isRefreshing = true;
      try {
        const { data, error } = await supabaseClient.auth.refreshSession();
        if (error || !data || !data.session) {
          throw error || new Error('Session refresh failed');
        }
        currentAccessToken = data.session.access_token;
        isRefreshing = false;
        // Retry the failed HTMX request once, keeping the original element's swap style.
        // The scan detail poller uses hx-target="this" + hx-swap="outerHTML"; retrying with
        // htmx's default swap (replace the target's children) would nest a second polling
        // <section> inside the first.
        if (evt.detail.requestConfig) {
          const cfg = evt.detail.requestConfig;
          const sourceElt = evt.detail.elt;
          const swapStyle = sourceElt && sourceElt.getAttribute
            ? sourceElt.getAttribute('hx-swap')
            : null;
          const retryContext = {
            target: evt.detail.target,
            headers: Object.assign({}, cfg.headers, {
              Authorization: 'Bearer ' + currentAccessToken,
            }),
          };
          if (swapStyle) {
            retryContext.swap = swapStyle;
          }
          window.htmx.ajax(cfg.verb.toUpperCase(), cfg.path, retryContext);
        }
      } catch (err) {
        isRefreshing = false;
        currentAccessToken = null;
        await supabaseClient.auth.signOut();
        onUserSignedOut();
      }
    }
  });

  // UI state toggles
  function onUserAuthenticated(user) {
    const authContainer = document.getElementById('auth-section');
    const appShell = document.getElementById('app-shell');
    const userDisplay = document.getElementById('user-email-display');

    if (authContainer) authContainer.classList.add('hidden');
    if (appShell) appShell.classList.remove('hidden');
    if (userDisplay && user && user.email) {
      userDisplay.textContent = user.email;
    }

    // Load user organizations
    loadOrgSwitcher();
  }

  function onUserSignedOut() {
    isAuthenticated = false;
    currentAccessToken = null;
    const authContainer = document.getElementById('auth-section');
    const appShell = document.getElementById('app-shell');
    const contentArea = document.getElementById('main-content-area');
    const orgSelector = document.getElementById('org-switcher-select');

    if (authContainer) authContainer.classList.remove('hidden');
    if (appShell) appShell.classList.add('hidden');
    if (contentArea) {
      while (contentArea.firstChild) {
        contentArea.removeChild(contentArea.firstChild);
      }
    }
    if (orgSelector) {
      while (orgSelector.firstChild) {
        orgSelector.removeChild(orgSelector.firstChild);
      }
    }
  }

  // Load organizations list for current user
  async function loadOrgSwitcher() {
    if (!currentAccessToken) return;
    try {
      const resp = await authenticatedFetch('/orgs');
      if (resp.status === 401) return;
      if (!resp.ok) {
        throw new Error('Failed to fetch organizations');
      }
      const orgs = await resp.json();
      const orgSelect = document.getElementById('org-switcher-select');
      if (!orgSelect) return;

      while (orgSelect.firstChild) {
        orgSelect.removeChild(orgSelect.firstChild);
      }

      if (!orgs || orgs.length === 0) {
        // User has no organizations; render empty org creation screen
        loadEmptyOrgView();
        return;
      }

      orgs.forEach(function (org) {
        const opt = document.createElement('option');
        opt.value = String(org.id);
        opt.textContent = org.name + ' (' + org.role + ')';
        orgSelect.appendChild(opt);
      });

      // Default to first organization
      const selectedOrgId = orgs[0].id;
      loadDomainsList(selectedOrgId);
    } catch (err) {
      showError('Failed to load organizations: ' + err.message);
    }
  }

  function loadEmptyOrgView() {
    return window.htmx.ajax('GET', '/ui/empty-org', {
      target: '#main-content-area',
    });
  }

  function loadDomainsList(orgId) {
    if (!orgId) return Promise.resolve();
    return window.htmx.ajax('GET', '/ui/orgs/' + orgId + '/domains', {
      target: '#main-content-area',
    });
  }

  function loadDomainDetail(orgId, domainId) {
    if (!orgId || !domainId) return Promise.resolve();
    return window.htmx.ajax('GET', '/ui/orgs/' + orgId + '/domains/' + domainId, {
      target: '#main-content-area',
    });
  }

  function loadScansList(orgId, domainId) {
    if (!orgId || !domainId) return Promise.resolve();
    return window.htmx.ajax('GET', '/ui/orgs/' + orgId + '/domains/' + domainId + '/scans', {
      target: '#main-content-area',
    });
  }

  function loadScanDetail(orgId, scanId) {
    if (!orgId || !scanId) return Promise.resolve();
    return window.htmx.ajax('GET', '/ui/orgs/' + orgId + '/scans/' + scanId, {
      target: '#main-content-area',
    });
  }

  function loadAlertNotifications(orgId, domainId, offset) {
    if (!orgId || !domainId) return Promise.resolve();
    const off = offset || 0;
    return window.htmx.ajax('GET', '/ui/orgs/' + orgId + '/domains/' + domainId + '/alert-notifications?offset=' + off, {
      target: '#main-content-area',
    });
  }

  function loadAuditLog(orgId, params) {
    if (!orgId) return Promise.resolve();
    const p = params || {};
    let url = '/ui/orgs/' + orgId + '/audit-events';
    const queryParts = [];
    if (p.action) queryParts.push('action=' + encodeURIComponent(p.action));
    if (p.domain_id) queryParts.push('domain_id=' + encodeURIComponent(p.domain_id));
    if (p.before_id) queryParts.push('before_id=' + encodeURIComponent(p.before_id));
    if (queryParts.length > 0) {
      url += '?' + queryParts.join('&');
    }
    return window.htmx.ajax('GET', url, {
      target: '#main-content-area',
    });
  }


  // Authenticated fetch wrapper
  async function authenticatedFetch(url, options) {
    const opts = options || {};
    opts.headers = opts.headers || {};
    if (currentAccessToken) {
      opts.headers['Authorization'] = 'Bearer ' + currentAccessToken;
    }
    let resp = await fetch(url, opts);
    if (resp.status === 401 && supabaseClient && !isRefreshing) {
      isRefreshing = true;
      try {
        const { data, error } = await supabaseClient.auth.refreshSession();
        if (error || !data || !data.session) {
          throw error || new Error('Refresh failed');
        }
        currentAccessToken = data.session.access_token;
        isRefreshing = false;
        opts.headers['Authorization'] = 'Bearer ' + currentAccessToken;
        resp = await fetch(url, opts);
      } catch (err) {
        isRefreshing = false;
        currentAccessToken = null;
        isAuthenticated = false;
        await supabaseClient.auth.signOut();
        onUserSignedOut();
      }
    }
    return resp;
  }

  function formatErrorMessage(detailOrMsg, fallback) {
    if (!detailOrMsg) return fallback || 'An unexpected error occurred.';
    if (Array.isArray(detailOrMsg)) {
      // FastAPI 422 validation errors: array of objects with 'msg'
      const messages = detailOrMsg.map(function (item) {
        return item && item.msg ? item.msg : String(item);
      });
      return messages.join('; ');
    }
    if (typeof detailOrMsg === 'object') {
      if (detailOrMsg.detail) {
        return formatErrorMessage(detailOrMsg.detail, fallback);
      }
      if (detailOrMsg.message) {
        return String(detailOrMsg.message);
      }
      return JSON.stringify(detailOrMsg);
    }
    return String(detailOrMsg);
  }

  function showError(detailOrMsg, fallback) {
    const errBox = document.getElementById('global-error-box');
    if (errBox) {
      errBox.textContent = formatErrorMessage(detailOrMsg, fallback);
      errBox.classList.remove('hidden');
    }
  }

  function clearError() {
    const errBox = document.getElementById('global-error-box');
    if (errBox) {
      errBox.textContent = '';
      errBox.classList.add('hidden');
    }
  }

  // Global Event Delegation (Form submissions, Actions, Copy buttons)
  document.addEventListener('submit', async function (evt) {
    const form = evt.target;

    // 1. Sign-in Form
    if (form && form.id === 'signin-form') {
      evt.preventDefault();
      clearError();
      const emailInput = form.querySelector('input[name="email"]');
      const passInput = form.querySelector('input[name="password"]');
      const email = emailInput ? emailInput.value.trim() : '';
      const password = passInput ? passInput.value : '';

      if (!email || !password) {
        showError('Email and password are required.');
        return;
      }

      if (!supabaseClient) {
        showError('Authentication client is not configured.');
        return;
      }

      const { data, error } = await supabaseClient.auth.signInWithPassword({
        email: email,
        password: password,
      });

      if (error) {
        showError(error.message);
      }
      // On success, onAuthStateChange fires SIGNED_IN and calls onUserAuthenticated once.
      return;
    }

    // 2. Create Organization Form (POST /orgs)
    if (form && form.id === 'create-org-form') {
      evt.preventDefault();
      clearError();
      const nameInput = form.querySelector('input[name="name"]');
      const name = nameInput ? nameInput.value.trim() : '';
      if (!name) {
        showError('Organization name is required.');
        return;
      }

      try {
        const resp = await authenticatedFetch('/orgs', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: name }),
        });

        if (!resp.ok) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'Failed to create organization.');
          return;
        }

        const newOrg = await resp.json();
        await loadOrgSwitcher();
      } catch (err) {
        showError('Error creating organization: ' + err.message);
      }
      return;
    }

    // 3. Add Domain Form (POST /orgs/{org_id}/domains)
    if (form && form.id === 'add-domain-form') {
      evt.preventDefault();
      clearError();
      const orgId = form.getAttribute('data-org-id');
      const nameInput = form.querySelector('input[name="name"]');
      const name = nameInput ? nameInput.value.trim() : '';

      if (!name) {
        showError('Domain name is required.');
        return;
      }

      try {
        const resp = await authenticatedFetch('/orgs/' + orgId + '/domains', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: name }),
        });

        if (!resp.ok) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'Failed to add domain.');
          return;
        }

        loadDomainsList(orgId);
      } catch (err) {
        showError('Error adding domain: ' + err.message);
      }
      return;
    }

    // 4. Schedule Settings Form (PUT /orgs/{org_id}/domains/{domain_id}/schedule)
    if (form && form.id === 'schedule-settings-form') {
      evt.preventDefault();
      clearError();
      const orgId = form.getAttribute('data-org-id');
      const domainId = form.getAttribute('data-domain-id');
      const intervalSelect = form.querySelector('select[name="interval_hours"]');
      const intervalVal = intervalSelect ? intervalSelect.value : '';
      const intervalHours = (intervalVal === '' || intervalVal === 'null') ? null : parseInt(intervalVal, 10);

      try {
        const resp = await authenticatedFetch(
          '/orgs/' + orgId + '/domains/' + domainId + '/schedule',
          {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interval_hours: intervalHours }),
          }
        );

        if (!resp.ok) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(formatErrorMessage(errData.detail, 'Failed to update scan schedule.'));
          return;
        }

        loadDomainDetail(orgId, domainId);
      } catch (err) {
        showError('Error updating schedule: ' + err.message);
      }
      return;
    }

    // 5. Alerts Settings Form (PUT /orgs/{org_id}/domains/{domain_id}/alerts)
    if (form && form.id === 'alerts-settings-form') {
      evt.preventDefault();
      clearError();
      const orgId = form.getAttribute('data-org-id');
      const domainId = form.getAttribute('data-domain-id');
      const enabledCheckbox = form.querySelector('#alerts-enabled-checkbox');
      const alertsEnabled = enabledCheckbox ? enabledCheckbox.checked : false;
      const severitySelect = form.querySelector('#alerts-min-severity-select');
      const minSeverity = severitySelect ? severitySelect.value : 'MEDIUM';

      const emailChips = form.querySelectorAll('#alert-emails-list .email-chip-text');
      const alertEmails = Array.prototype.map.call(emailChips, function (el) {
        return el.textContent.trim();
      });

      try {
        const resp = await authenticatedFetch(
          '/orgs/' + orgId + '/domains/' + domainId + '/alerts',
          {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              alerts_enabled: alertsEnabled,
              alert_emails: alertEmails,
              alert_min_severity: minSeverity,
            }),
          }
        );

        if (!resp.ok) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(formatErrorMessage(errData.detail, 'Failed to update alert settings.'));
          return;
        }

        loadDomainDetail(orgId, domainId);
      } catch (err) {
        showError('Error updating alert settings: ' + err.message);
      }
      return;
    }

    // 6. Audit Filter Form
    if (form && form.id === 'audit-filter-form') {
      evt.preventDefault();
      clearError();
      const orgId = form.getAttribute('data-org-id');
      const actionSelect = form.querySelector('#audit-filter-action');
      const domainSelect = form.querySelector('#audit-filter-domain');
      const actionVal = actionSelect ? actionSelect.value : '';
      const domainVal = domainSelect ? domainSelect.value : '';

      loadAuditLog(orgId, {
        action: actionVal,
        domain_id: domainVal,
      });
      return;
    }
  });

  // Click handler delegation
  document.addEventListener('click', async function (evt) {
    const target = evt.target;
    if (!target) return;

    // Sign out button
    if (target.id === 'signout-button') {
      evt.preventDefault();
      if (supabaseClient) {
        await supabaseClient.auth.signOut();
      }
      currentAccessToken = null;
      onUserSignedOut();
      return;
    }

    // Copy to clipboard
    if (target.classList.contains('btn-copy')) {
      evt.preventDefault();
      const copyValue = target.getAttribute('data-copy-value') || '';
      if (copyValue) {
        navigator.clipboard.writeText(copyValue).then(function () {
          const origText = target.textContent;
          target.textContent = 'Copied!';
          setTimeout(function () {
            target.textContent = origText;
          }, 2000);
        });
      }
      return;
    }

    // Navigation: View domain details
    if (target.classList.contains('btn-view-domain')) {
      evt.preventDefault();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');
      loadDomainDetail(orgId, domainId);
      return;
    }

    // Navigation: Back to domains list
    if (target.id === 'btn-back-domains') {
      evt.preventDefault();
      const orgId = target.getAttribute('data-org-id');
      loadDomainsList(orgId);
      return;
    }

    // Action: Check Verification Now (POST /orgs/{org_id}/domains/{domain_id}/verification/check)
    if (target.id === 'btn-check-verification') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');

      target.disabled = true;
      const originalBtnText = target.textContent;
      target.textContent = 'Checking...';

      try {
        const resp = await authenticatedFetch(
          '/orgs/' + orgId + '/domains/' + domainId + '/verification/check',
          { method: 'POST' }
        );

        target.disabled = false;
        target.textContent = originalBtnText;

        if (resp.status === 429) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'Verification check is on cooldown.');
          return;
        }

        if (!resp.ok) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'Verification check failed.');
          return;
        }

        const data = await resp.json();

        // Refresh domain detail FIRST, then render check_outcome/check_detail into #verification-check-result AFTER swap finishes
        loadDomainDetail(orgId, domainId).then(function () {
          const freshResultContainer = document.getElementById('verification-check-result');
          if (freshResultContainer) {
            while (freshResultContainer.firstChild) {
              freshResultContainer.removeChild(freshResultContainer.firstChild);
            }

            const box = document.createElement('div');
            box.className = 'alert-box alert-info';

            const title = document.createElement('strong');
            title.textContent = 'Check outcome: ' + (data.check_outcome || 'unknown');
            box.appendChild(title);

            if (data.check_detail) {
              const detailPara = document.createElement('p');
              detailPara.className = 'text-muted';
              detailPara.textContent = data.check_detail;
              box.appendChild(detailPara);
            }

            freshResultContainer.appendChild(box);
          }
        });
      } catch (err) {
        target.disabled = false;
        target.textContent = originalBtnText;
        showError('Verification check error: ' + err.message);
      }
      return;
    }

    // Action: Rotate Verification Token (POST /orgs/{org_id}/domains/{domain_id}/verification/rotate)
    if (target.id === 'btn-rotate-token') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');

      if (!window.confirm('Rotating the token will invalidate the current DNS verification record. Continue?')) {
        return;
      }

      try {
        const resp = await authenticatedFetch(
          '/orgs/' + orgId + '/domains/' + domainId + '/verification/rotate',
          { method: 'POST' }
        );

        if (!resp.ok) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'Token rotation failed.');
          return;
        }

        // Refresh domain detail
        loadDomainDetail(orgId, domainId);
      } catch (err) {
        showError('Token rotation error: ' + err.message);
      }
      return;
    }

    // Navigation: View domain scans list
    if (target.classList.contains('btn-view-scans')) {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');
      loadScansList(orgId, domainId);
      return;
    }

    // Navigation: View scan detail
    if (target.classList.contains('btn-view-scan')) {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const scanId = target.getAttribute('data-scan-id');
      loadScanDetail(orgId, scanId);
      return;
    }

    // Navigation: Back to domain detail
    if (target.id === 'btn-back-domain-detail') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');
      loadDomainDetail(orgId, domainId);
      return;
    }

    // Action: Manually refresh a scan whose automatic polling stopped (15-minute cap)
    if (target.id === 'btn-refresh-scan') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const scanId = target.getAttribute('data-scan-id');
      loadScanDetail(orgId, scanId);
      return;
    }

    // Navigation: Back to scans list
    if (target.id === 'btn-back-scans') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');
      loadScansList(orgId, domainId);
      return;
    }

    // Action: Run Scan (POST /orgs/{org_id}/domains/{domain_id}/scans)
    if (target.id === 'btn-run-scan') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');

      target.disabled = true;
      const originalBtnText = target.textContent;
      target.textContent = 'Starting scan...';

      const idempotencyKey = (window.crypto && window.crypto.randomUUID)
        ? window.crypto.randomUUID()
        : String(Date.now());

      try {
        const resp = await authenticatedFetch(
          '/orgs/' + orgId + '/domains/' + domainId + '/scans',
          {
            method: 'POST',
            headers: {
              'Idempotency-Key': idempotencyKey,
            },
          }
        );

        target.disabled = false;
        target.textContent = originalBtnText;

        if (resp.status === 409) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'A scan is already active for this domain.');
          return;
        }

        if (resp.status === 422) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'Domain ownership verification required before scanning.');
          return;
        }

        if (!resp.ok) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'Failed to start scan.');
          return;
        }

        const scanData = await resp.json();
        loadScanDetail(orgId, scanData.id);
      } catch (err) {
        target.disabled = false;
        target.textContent = originalBtnText;
        showError('Run scan error: ' + err.message);
      }
      return;
    }

    // Action: Add Alert Email Chip
    if (target.id === 'btn-add-alert-email') {
      evt.preventDefault();
      clearError();
      const input = document.getElementById('input-alert-email');
      if (!input) return;
      const val = input.value.trim();
      if (!val) {
        showError('Email address is required.');
        return;
      }
      if (!input.checkValidity() || val.indexOf('@') === -1 || val.indexOf('.') === -1) {
        showError('Please enter a valid email address.');
        return;
      }
      const list = document.getElementById('alert-emails-list');
      if (!list) return;

      if (list.children.length >= 5) {
        showError('Maximum of 5 alert emails allowed.');
        return;
      }

      const existingChips = list.querySelectorAll('.email-chip-text');
      const lowerVal = val.toLowerCase();
      let isDuplicate = false;
      for (let i = 0; i < existingChips.length; i++) {
        if (existingChips[i].textContent.trim().toLowerCase() === lowerVal) {
          isDuplicate = true;
          break;
        }
      }
      if (isDuplicate) {
        showError('Email address is already in the list.');
        return;
      }

      const li = document.createElement('li');
      li.className = 'email-chip';

      const span = document.createElement('span');
      span.className = 'email-chip-text';
      span.textContent = val;

      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'btn btn-secondary btn-xs btn-remove-email';
      removeBtn.textContent = 'Remove';

      li.appendChild(span);
      li.appendChild(removeBtn);
      list.appendChild(li);

      input.value = '';
      return;
    }

    // Action: Remove Alert Email Chip
    if (target.classList.contains('btn-remove-email')) {
      evt.preventDefault();
      const chip = target.closest('.email-chip');
      if (chip) {
        chip.remove();
      }
      return;
    }

    // Navigation: View Alert Notifications
    if (target.id === 'btn-view-alert-notifications') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');
      loadAlertNotifications(orgId, domainId, 0);
      return;
    }

    // Navigation: Alert Notifications Pagination
    if (target.classList.contains('btn-page-alert-notifications')) {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');
      const offset = parseInt(target.getAttribute('data-offset') || '0', 10);
      loadAlertNotifications(orgId, domainId, offset);
      return;
    }

    // Navigation: View Audit Log
    if (target.id === 'btn-nav-audit-log') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      loadAuditLog(orgId);
      return;
    }

    // Navigation: Audit Log Older Events
    if (target.id === 'btn-audit-older') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const beforeId = target.getAttribute('data-before-id');
      const action = target.getAttribute('data-action');
      const domainId = target.getAttribute('data-domain-id');
      loadAuditLog(orgId, {
        action: action,
        domain_id: domainId,
        before_id: beforeId,
      });
      return;
    }

    // Navigation: Audit Log Newest Events
    if (target.id === 'btn-audit-newest') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const action = target.getAttribute('data-action');
      const domainId = target.getAttribute('data-domain-id');
      loadAuditLog(orgId, {
        action: action,
        domain_id: domainId,
      });
      return;
    }
  });

  // Org switcher change handler
  document.addEventListener('change', function (evt) {
    if (evt.target && evt.target.id === 'org-switcher-select') {
      const orgId = evt.target.value;
      clearError();
      loadDomainsList(orgId);
    }
  });
})();
