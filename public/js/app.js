/* ============================================
   Shared client utilities
   ============================================ */

const TOKEN_KEY = 'sspr_token';
const REFRESH_KEY = 'sspr_refresh';
const USER_KEY = 'sspr_user';
const ACTIVITY_KEY = 'sspr_last_activity';
// Signed-in pages sign out after this long without a click, key press or request
const IDLE_LIMIT_MS = 30 * 60 * 1000;

// ---- Token storage ----

function getToken() {
    return localStorage.getItem(TOKEN_KEY);
}

function setToken(token, refreshToken) {
    localStorage.setItem(TOKEN_KEY, token);
    if (refreshToken) localStorage.setItem(REFRESH_KEY, refreshToken);
}

function clearToken() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(USER_KEY);
    localStorage.removeItem(ACTIVITY_KEY);
}

// ---- Idle sign-out ----

function markActivity() {
    if (getToken()) localStorage.setItem(ACTIVITY_KEY, String(Date.now()));
}

// Shared by all tabs through localStorage, so activity in one tab keeps the others signed in
function idleTooLong() {
    const last = parseInt(localStorage.getItem(ACTIVITY_KEY), 10);
    return Boolean(getToken()) && Number.isFinite(last) && Date.now() - last > IDLE_LIMIT_MS;
}

function startIdleWatch() {
    if (idleTooLong()) {
        clearToken();
        window.location.href = '/index.html?idle=1';
        return;
    }
    markActivity();
    ['click', 'keydown'].forEach((type) => document.addEventListener(type, markActivity, { passive: true }));
    setInterval(() => {
        if (idleTooLong()) logout('/index.html?idle=1');
    }, 60 * 1000);
}

function getCachedUser() {
    try {
        return JSON.parse(localStorage.getItem(USER_KEY));
    } catch {
        return null;
    }
}

function setCachedUser(user) {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
}

// ---- API wrapper ----

class ApiError extends Error {
    constructor(message, status, code, data) {
        super(message);
        this.status = status;
        this.code = code;
        // Extra detail some errors carry, e.g. { problems: [{ rule, message }] } for PASSWORD_POLICY
        this.data = data || null;
    }
}

let refreshPromise = null;

async function refreshAccessToken() {
    const refreshToken = localStorage.getItem(REFRESH_KEY);
    if (!refreshToken) return false;

    // Share a single in-flight refresh across concurrent requests
    if (!refreshPromise) {
        refreshPromise = fetch('/api/auth/refresh', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken }),
        })
            .then(async (res) => {
                const json = await res.json().catch(() => ({}));
                if (res.ok && json.success && json.data?.token) {
                    localStorage.setItem(TOKEN_KEY, json.data.token);
                    return true;
                }
                return false;
            })
            .catch(() => false)
            .finally(() => { refreshPromise = null; });
    }
    return refreshPromise;
}

async function api(method, url, body, { retry = true } = {}) {
    const headers = { Accept: 'application/json' };
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) headers['Content-Type'] = 'application/json';

    let res;
    try {
        res = await fetch(url, {
            method,
            headers,
            body: body !== undefined ? JSON.stringify(body) : undefined,
        });
    } catch {
        throw new ApiError('Unable to reach the server. Check your connection and try again.', 0);
    }

    const json = await res.json().catch(() => ({}));

    if (res.ok) markActivity();

    // Logout elsewhere, an admin lock or a password change ended this session
    if (res.status === 401 && json.code === 'SESSION_REVOKED') {
        clearToken();
        window.location.href = '/index.html?revoked=1';
        throw new ApiError(json.message, 401, 'SESSION_EXPIRED');
    }

    if (res.status === 401 && json.code === 'TOKEN_EXPIRED' && retry) {
        if (await refreshAccessToken()) {
            return api(method, url, body, { retry: false });
        }
        clearToken();
        window.location.href = '/index.html?expired=1';
        throw new ApiError('Your session has expired. Please sign in again.', 401, 'SESSION_EXPIRED');
    }

    if (!res.ok || json.success === false) {
        const message = json.message
            || (res.status === 429 ? 'Too many attempts. Please wait and try again.' : 'Request failed. Please try again.');
        throw new ApiError(message, res.status, json.code, json.data);
    }

    return json;
}

// ---- Route guards ----

function redirectIfNotAuthenticated() {
    if (!getToken()) {
        window.location.href = '/index.html';
        return true;
    }
    return false;
}

function redirectIfNotEnrolled(user) {
    if (user && !user.isEnrolled) {
        window.location.href = '/enroll.html';
        return true;
    }
    return false;
}

// Loads the current user from the server; redirects to login on failure.
async function loadCurrentUser() {
    if (redirectIfNotAuthenticated()) return null;
    startIdleWatch();
    try {
        const { data } = await api('GET', '/api/auth/me');
        setCachedUser(data);
        return data;
    } catch (err) {
        if (err.code !== 'SESSION_EXPIRED') {
            clearToken();
            window.location.href = '/index.html';
        }
        return null;
    }
}

async function logout(target = '/index.html') {
    try {
        await api('POST', '/api/auth/logout', {}, { retry: false });
    } catch {
        // Logout is client-side; ignore server errors
    }
    clearToken();
    window.location.href = typeof target === 'string' ? target : '/index.html';
}

// ---- Toast notifications ----

function showToast(message, type = 'info', duration = 5000) {
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        container.setAttribute('aria-live', 'polite');
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.setAttribute('role', type === 'error' ? 'alert' : 'status');

    const msg = document.createElement('div');
    msg.className = 'toast-message';
    msg.textContent = message;

    const close = document.createElement('button');
    close.className = 'toast-close';
    close.setAttribute('aria-label', 'Dismiss');
    close.textContent = '×';

    toast.append(msg, close);
    container.appendChild(toast);

    const remove = () => {
        if (!toast.isConnected || toast.classList.contains('removing')) return;
        toast.classList.add('removing');
        toast.addEventListener('animationend', () => toast.remove(), { once: true });
    };
    close.addEventListener('click', remove);
    setTimeout(remove, duration);
}

// ---- Loading states ----

function setButtonLoading(button, loading, loadingText) {
    if (loading) {
        button.dataset.originalText = button.textContent;
        button.disabled = true;
        button.textContent = '';
        const spinner = document.createElement('span');
        spinner.className = 'spinner';
        button.append(spinner, document.createTextNode(loadingText || 'Please wait...'));
    } else {
        button.disabled = false;
        button.textContent = button.dataset.originalText || button.textContent;
    }
}

function showOverlay() {
    let overlay = document.querySelector('.loading-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.className = 'loading-overlay';
        overlay.innerHTML = '<div class="loading-spinner"></div>';
        document.body.appendChild(overlay);
    }
    overlay.classList.add('visible');
}

function hideOverlay() {
    document.querySelector('.loading-overlay')?.classList.remove('visible');
}

// ---- Form helpers ----

function setFieldError(input, message) {
    input.classList.toggle('error', Boolean(message));
    const errorEl = input.closest('.form-group')?.querySelector('.form-error');
    if (errorEl) {
        errorEl.textContent = message || '';
        errorEl.classList.toggle('visible', Boolean(message));
    }
}

/**
 * A lead sentence plus one line per broken rule, under the field (one problem: just the sentence).
 * @param {HTMLInputElement} input
 * @param {string} lead
 * @param {string[]} messages
 */
function showProblemList(input, lead, messages) {
    setFieldError(input, lead);
    const errorEl = input.closest('.form-group')?.querySelector('.form-error');
    if (!errorEl || messages.length <= 1) return;
    const list = document.createElement('ul');
    list.className = 'policy-problems';
    messages.forEach((message) => {
        const item = document.createElement('li');
        item.textContent = message;
        list.appendChild(item);
    });
    errorEl.appendChild(list);
}

/**
 * A new password refused by the server (PASSWORD_POLICY carries data.problems); any other error as a plain
 * field error.
 */
function showPasswordError(input, err) {
    const problems = err?.code === 'PASSWORD_POLICY' ? (err.data?.problems || []) : [];
    showProblemList(input, err.message, problems.map((p) => p.message));
}

/**
 * The same rules the server checks first (length, character types, username, name parts), worded the same way,
 * so the page can say what is wrong before anything is sent. History and the minimum age only the server knows.
 * @returns {string[]} empty = nothing found
 */
function passwordProblems(password, identity = {}) {
    const problems = [];
    const length = [...password].length;
    if (length < passwordRules.minLength) {
        problems.push(`Use at least ${passwordRules.minLength} characters (this one has ${length}).`);
    }
    if (!passwordRules.complexity) return problems;

    const c = getPasswordChecks(password, identity);
    const kinds = [['uppercase letters', c.upper], ['lowercase letters', c.lower], ['numbers', c.digit], ['symbols', c.symbol]]
        .filter(([, present]) => present).map(([name]) => name);
    if (kinds.length < 3) {
        const found = kinds.length > 1 ? `${kinds.slice(0, -1).join(', ')} and ${kinds[kinds.length - 1]}` : kinds[0];
        problems.push(`Use at least 3 of these: uppercase letters, lowercase letters, numbers, symbols (it has ${found ? `only ${found}` : 'none of them'}).`);
    }
    const lower = password.toLowerCase();
    const name = String(identity.username || '');
    const hasUsername = name.length >= 3 && lower.includes(name.toLowerCase());
    if (hasUsername) problems.push(`It must not contain your username (${name}).`);
    const parts = String(identity.displayName || '').split(/[,.\-_#\t ]+/)
        .filter((part) => part.length >= 3 && lower.includes(part.toLowerCase()))
        .filter((part) => !(hasUsername && name.toLowerCase().includes(part.toLowerCase())));
    if (parts.length) problems.push(`It must not contain ${parts.length === 1 ? 'a part' : 'parts'} of your name (${parts.join(', ')}).`);
    return problems;
}

/** Shows passwordProblems() under the field; returns true when the password may be sent. */
function checkNewPassword(input, identity) {
    const problems = passwordProblems(input.value, identity);
    if (!problems.length) return true;
    const lead = problems.length === 1
        ? `The new password does not meet the domain password policy: ${problems[0]}`
        : 'The new password does not meet the domain password policy. Please fix the points below.';
    showProblemList(input, lead, problems);
    return false;
}

// Sign-in and reset take the domain username only, not an email address or DOMAIN\user
function usernameFormatError(username) {
    if (username.includes('@')) {
        return 'Enter your domain username only, not your email address.';
    }
    if (username.includes('\\')) {
        return 'Enter your domain username only, without the domain name and \\ in front.';
    }
    return null;
}

// A typed DOMAIN\user is accepted when the page shows the domain in front of the field
function stripDomainPrefix(username) {
    return String(username).replace(/^[^\\@]+\\/, '');
}

/**
 * Shows the sign-in domain (GET /api/auth/sign-in-info) as a fixed prefix in front of a username input.
 * @returns {Promise<string|null>} the prefix, or null when none is configured
 */
async function applyDomainPrefix(input) {
    let prefix = null;
    try {
        const res = await fetch('/api/auth/sign-in-info', { headers: { Accept: 'application/json' } });
        const json = await res.json();
        if (res.ok && json.success) prefix = json.data?.domainPrefix || null;
    } catch {
        return null;
    }
    if (!prefix || input.closest('.input-group')) return prefix;
    const group = document.createElement('div');
    group.className = 'input-group';
    const tag = document.createElement('span');
    tag.className = 'input-prefix';
    tag.setAttribute('aria-hidden', 'true');
    tag.textContent = `${prefix}\\`;
    input.parentNode.insertBefore(group, input);
    group.append(tag, input);
    const label = document.querySelector(`label[for="${input.id}"]`);
    if (label) {
        const sr = document.createElement('span');
        sr.className = 'sr-only';
        sr.textContent = ` (domain ${prefix})`;
        label.appendChild(sr);
    }
    return prefix;
}

// The "not your email address" hint only shows while the value looks like one
function bindUsernameHint(input, hint) {
    if (!hint) return;
    const update = () => hint.classList.toggle('hidden', !input.value.includes('@'));
    input.addEventListener('input', update);
    update();
}

function clearFieldErrors(form) {
    form.querySelectorAll('.form-input, .form-select').forEach((el) => setFieldError(el, ''));
}

function initPasswordToggles(root = document) {
    root.querySelectorAll('.password-toggle').forEach((btn) => {
        btn.textContent = 'Show';
        btn.addEventListener('click', () => {
            const input = btn.parentElement.querySelector('input');
            const show = input.type === 'password';
            input.type = show ? 'text' : 'password';
            btn.textContent = show ? 'Hide' : 'Show';
            btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
        });
    });
}

// ---- Password rules and strength ----

// What the server checks (GET /api/password/rules); defaults until it has answered
let passwordRules = { minLength: 8, complexity: true };

async function loadPasswordRules() {
    try {
        const res = await fetch('/api/password/rules', { headers: { Accept: 'application/json' } });
        const json = await res.json();
        if (res.ok && json.success) passwordRules = json.data;
    } catch {
        // Keep the defaults; the server checks the password anyway
    }
    return passwordRules;
}

// AD complexity also refuses the account name (3+ characters) and any display-name part of 3+ characters
function containsIdentity(password, identity = {}) {
    const lower = password.toLowerCase();
    const name = String(identity.username || '').toLowerCase();
    if (name.length >= 3 && lower.includes(name)) return true;
    return String(identity.displayName || '')
        .split(/[,.\-_#\t ]+/)
        .some((part) => part.length >= 3 && lower.includes(part.toLowerCase()));
}

function getPasswordChecks(password, identity) {
    return {
        length: password.length >= passwordRules.minLength,
        lower: /[a-z]/.test(password),
        upper: /[A-Z]/.test(password),
        digit: /\d/.test(password),
        symbol: /[^A-Za-z0-9]/.test(password),
        noname: password.length > 0 && !containsIdentity(password, identity),
    };
}

// Minimum length, plus 3 of 4 character categories when the domain has complexity on
function meetsComplexity(password, identity) {
    const c = getPasswordChecks(password, identity);
    const categories = [c.lower, c.upper, c.digit, c.symbol].filter(Boolean).length;
    if (!c.length) return false;
    if (!passwordRules.complexity) return true;
    return categories >= 3 && c.noname;
}

// "At least N characters" in a requirements list, from the server's rule
function renderLengthRule(reqList) {
    const item = reqList?.querySelector('[data-req="length"]');
    if (item) item.firstChild.textContent = `At least ${passwordRules.minLength} characters`;
}

// Rules the page cannot check while typing (AD remembers old passwords; the minimum age depends on the last change)
function renderPolicyNotes() {
    const history = Number(passwordRules.historyCount) || 0;
    const minAge = Number(passwordRules.minAgeDays) || 0;
    // In a requirements list (li) the rule reads as one more item, checked by AD on submit
    document.querySelectorAll('[data-policy-note="history"]').forEach((el) => {
        el.textContent = !history ? ''
            : el.tagName === 'LI' ? `Not one of your last ${history} passwords (checked when you submit)`
                : `Your last ${history} passwords cannot be used again.`;
        el.classList.toggle('hidden', !history);
    });
    document.querySelectorAll('[data-policy-note="min-age"]').forEach((el) => {
        const days = Number.isInteger(minAge) ? minAge : minAge.toFixed(1);
        el.textContent = !minAge ? ''
            : el.tagName === 'LI' ? `${days} day${days === 1 ? '' : 's'} since your last change (checked when you submit)`
                : `After a change, the next change is possible after ${days} day${days === 1 ? '' : 's'}.`;
        el.classList.toggle('hidden', !minAge);
    });
}

function evaluatePasswordStrength(password) {
    if (!password) return { level: '', label: '' };
    const c = getPasswordChecks(password);
    let score = [c.lower, c.upper, c.digit, c.symbol].filter(Boolean).length;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;
    if (!c.length) score = Math.min(score, 1);

    if (score <= 1) return { level: 'weak', label: 'Weak' };
    if (score <= 3) return { level: 'fair', label: 'Fair' };
    if (score <= 4) return { level: 'good', label: 'Good' };
    return { level: 'strong', label: 'Strong' };
}

// Wires a password input to a strength meter and optional requirements list.
// identity: () => ({ username, displayName }) for the "does not contain your name" rule
// confirm: optional confirmation input, checked by a data-req="match" item.
// Items are pending (hollow), met (check) or, after markPasswordAttempt(), failed (cross); a hidden suffix
// says the state to screen readers.
function bindPasswordStrength(input, meterRoot, reqList, identity = () => ({}), confirm = null) {
    const fill = meterRoot.querySelector('.strength-fill');
    const text = meterRoot.querySelector('.strength-text');
    const update = () => {
        const { level, label } = evaluatePasswordStrength(input.value);
        fill.className = `strength-fill ${level}`;
        text.textContent = label ? `Strength: ${label}` : '';
        if (reqList) {
            const checks = getPasswordChecks(input.value, identity());
            if (confirm) checks.match = confirm.value.length > 0 && confirm.value === input.value;
            const attempted = reqList.dataset.attempted === '1';
            reqList.querySelectorAll('[data-req]').forEach((li) => {
                const met = Boolean(checks[li.dataset.req]);
                li.classList.toggle('met', met);
                li.classList.toggle('failed', attempted && !met);
                let state = li.querySelector('.req-state');
                if (!state) {
                    state = document.createElement('span');
                    state.className = 'sr-only req-state';
                    li.appendChild(state);
                }
                state.textContent = met ? ' (met)' : ' (not met)';
            });
        }
    };
    if (reqList) reqList.refreshRules = update;
    input.addEventListener('input', update);
    if (confirm) confirm.addEventListener('input', update);
    loadPasswordRules().then(() => {
        renderLengthRule(reqList);
        renderPolicyNotes();
        // The complexity items only matter when the domain enforces them
        reqList?.querySelectorAll('[data-req="lower"], [data-req="upper"], [data-req="digit"], [data-req="symbol"]')
            .forEach((li) => li.classList.toggle('hidden', !passwordRules.complexity));
        document.querySelectorAll('[data-complexity-only]')
            .forEach((el) => el.classList.toggle('hidden', !passwordRules.complexity));
        update();
    });
    update();
}

// After a submit attempt, unmet rules show as failed (not only "not yet met")
function markPasswordAttempt(reqList) {
    if (!reqList) return;
    reqList.dataset.attempted = '1';
    reqList.refreshRules?.();
}

function resetPasswordAttempt(reqList) {
    if (!reqList) return;
    delete reqList.dataset.attempted;
    reqList.refreshRules?.();
}

// "Matches the new password" item for a confirmation field (its own list, under that field)
function bindMatchRule(input, confirm, list) {
    const item = list?.querySelector('[data-req="match"]');
    if (!item) return;
    const update = () => {
        const met = confirm.value.length > 0 && confirm.value === input.value;
        item.classList.toggle('met', met);
        item.classList.toggle('failed', list.dataset.attempted === '1' && !met);
        let state = item.querySelector('.req-state');
        if (!state) {
            state = document.createElement('span');
            state.className = 'sr-only req-state';
            item.appendChild(state);
        }
        state.textContent = met ? ' (met)' : ' (not met)';
    };
    list.refreshRules = update;
    input.addEventListener('input', update);
    confirm.addEventListener('input', update);
    update();
}

/**
 * What a successful change or reset did, as a short list (data from the change/reset response).
 * @param {HTMLUListElement} list
 * @param {{domain?: string, sync?: {domain: string, status: string}|null, unlocked?: boolean}} data
 */
function renderDoneList(list, data = {}) {
    if (!list) return;
    list.textContent = '';
    const add = (text, failed = false) => {
        const li = document.createElement('li');
        if (failed) li.className = 'done-failed';
        li.textContent = text;
        list.appendChild(li);
    };
    add(`Password changed in ${data.domain || 'Active Directory'}`);
    if (data.sync?.status === 'synced') add(`${data.sync.domain} updated with the same password`);
    if (data.sync?.status === 'failed') add(`${data.sync.domain} not updated (see below)`, true);
    if (data.unlocked) add('Your account was locked out and is unlocked now');
    add('Signed out of the portal on every other device');
}

// ---- Custom dropdowns ----
// Every <select class="form-select"> gets a styled button + listbox (WAI-ARIA select-only combobox).
// The native select stays in the DOM, hidden, as the source of truth: page code keeps reading .value,
// setting .value, rebuilding options and listening for 'change'. Phones keep the native picker.

const SELECT_ENHANCE = !window.matchMedia || !window.matchMedia('(pointer: coarse)').matches;
let selectUid = 0;
let openSelect = null;

function enhanceSelect(select) {
    if (!SELECT_ENHANCE || select.dataset.enhanced || select.multiple || select.size > 1) return;
    select.dataset.enhanced = '1';
    const uid = `cs${++selectUid}`;
    if (!select.id) select.id = `${uid}-native`;

    const wrap = document.createElement('div');
    wrap.className = 'cselect';
    if (select.classList.contains('w-auto')) wrap.classList.add('cselect-auto');
    select.parentNode.insertBefore(wrap, select);
    wrap.appendChild(select);
    select.classList.add('cselect-native');
    select.tabIndex = -1;
    select.setAttribute('aria-hidden', 'true');

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'cselect-button';
    button.id = `${uid}-button`;
    button.setAttribute('role', 'combobox');
    button.setAttribute('aria-haspopup', 'listbox');
    button.setAttribute('aria-expanded', 'false');
    button.setAttribute('aria-controls', `${uid}-list`);
    const label = document.querySelector(`label[for="${select.id}"]`);
    if (label) {
        if (!label.id) label.id = `${uid}-label`;
        button.setAttribute('aria-labelledby', `${label.id} ${button.id}`);
        label.htmlFor = button.id;
    } else if (select.getAttribute('aria-label')) {
        button.setAttribute('aria-label', select.getAttribute('aria-label'));
    }
    const value = document.createElement('span');
    value.className = 'cselect-value';
    // Every option label sits invisibly in the same grid cell, so the button is as wide as the longest one
    const sizer = document.createElement('span');
    sizer.className = 'cselect-sizer';
    sizer.setAttribute('aria-hidden', 'true');
    const face = document.createElement('span');
    face.className = 'cselect-face';
    face.append(value, sizer);
    const chevron = document.createElement('span');
    chevron.className = 'cselect-chevron';
    chevron.setAttribute('aria-hidden', 'true');
    button.append(face, chevron);
    wrap.appendChild(button);

    const list = document.createElement('ul');
    list.className = 'cselect-list hidden';
    list.id = `${uid}-list`;
    list.setAttribute('role', 'listbox');
    list.tabIndex = -1;
    if (label) list.setAttribute('aria-labelledby', label.id);
    document.body.appendChild(list);

    let active = -1;
    let typed = '';
    let typedTimer = null;

    const options = () => [...select.options];
    const isOpen = () => !list.classList.contains('hidden');

    function render() {
        const opt = select.options[select.selectedIndex];
        value.textContent = opt ? opt.text : '';
        value.classList.toggle('cselect-placeholder', !opt || opt.value === '');
        sizer.textContent = '';
        options().forEach((o) => {
            const s = document.createElement('span');
            s.textContent = o.text;
            sizer.appendChild(s);
        });
        button.disabled = select.disabled;
        button.classList.toggle('error', select.classList.contains('error'));
        if (isOpen()) renderList();
    }

    function renderList() {
        list.textContent = '';
        options().forEach((o, i) => {
            const li = document.createElement('li');
            li.id = `${uid}-opt-${i}`;
            li.className = 'cselect-option';
            li.setAttribute('role', 'option');
            li.setAttribute('aria-selected', String(i === select.selectedIndex));
            if (o.disabled) li.setAttribute('aria-disabled', 'true');
            if (o.value === '') li.classList.add('cselect-placeholder');
            li.textContent = o.text;
            li.addEventListener('mousedown', (e) => e.preventDefault()); // keep focus on the button
            li.addEventListener('click', () => {
                if (o.disabled) return;
                choose(i);
                close();
            });
            li.addEventListener('mousemove', () => { if (!o.disabled && active !== i) setActive(i); });
            list.appendChild(li);
        });
        setActive(active);
    }

    function setActive(i) {
        active = i;
        list.querySelectorAll('.cselect-option').forEach((li, idx) => li.classList.toggle('active', idx === i));
        const li = list.children[i];
        if (li) {
            button.setAttribute('aria-activedescendant', li.id);
            const top = li.offsetTop;
            if (top < list.scrollTop) list.scrollTop = top;
            else if (top + li.offsetHeight > list.scrollTop + list.clientHeight) {
                list.scrollTop = top + li.offsetHeight - list.clientHeight;
            }
        } else {
            button.removeAttribute('aria-activedescendant');
        }
    }

    function position() {
        const r = button.getBoundingClientRect();
        const below = window.innerHeight - r.bottom - 8;
        const above = r.top - 8;
        const wanted = Math.min(list.scrollHeight, 320);
        const up = below < Math.min(wanted, 200) && above > below;
        list.style.left = `${Math.max(8, Math.min(r.left, window.innerWidth - Math.max(r.width, 200) - 8))}px`;
        list.style.minWidth = `${r.width}px`;
        list.style.maxWidth = `${Math.max(r.width, Math.min(560, window.innerWidth - 16))}px`;
        list.style.maxHeight = `${Math.max(120, Math.min(320, up ? above : below))}px`;
        list.style.top = up ? '' : `${r.bottom + 4}px`;
        list.style.bottom = up ? `${window.innerHeight - r.top + 4}px` : '';
        list.classList.toggle('cselect-up', up);
    }

    function open() {
        if (button.disabled || isOpen()) return;
        if (openSelect && openSelect !== api) openSelect.close();
        openSelect = api;
        active = select.selectedIndex;
        list.classList.remove('hidden');
        renderList();
        position();
        setActive(active);
        button.setAttribute('aria-expanded', 'true');
        wrap.classList.add('open');
    }

    function close() {
        if (!isOpen()) return;
        list.classList.add('hidden');
        button.setAttribute('aria-expanded', 'false');
        button.removeAttribute('aria-activedescendant');
        wrap.classList.remove('open');
        if (openSelect === api) openSelect = null;
    }

    function choose(i) {
        if (i < 0 || i === select.selectedIndex || select.options[i]?.disabled) return;
        select.selectedIndex = i;
        render();
        select.dispatchEvent(new Event('input', { bubbles: true }));
        select.dispatchEvent(new Event('change', { bubbles: true }));
    }

    function step(from, dir) {
        const opts = options();
        for (let i = from + dir; i >= 0 && i < opts.length; i += dir) {
            if (!opts[i].disabled) return i;
        }
        return from;
    }

    function typeahead(ch) {
        typed += ch.toLowerCase();
        clearTimeout(typedTimer);
        typedTimer = setTimeout(() => { typed = ''; }, 600);
        const opts = options();
        const start = isOpen() ? active : select.selectedIndex;
        for (let n = 1; n <= opts.length; n++) {
            const i = (start + (typed.length > 1 ? n - 1 : n) + opts.length) % opts.length;
            if (!opts[i].disabled && opts[i].text.toLowerCase().startsWith(typed)) return i;
        }
        return -1;
    }

    button.addEventListener('click', () => (isOpen() ? close() : open()));
    button.addEventListener('blur', () => setTimeout(() => { if (document.activeElement !== button) close(); }, 0));
    button.addEventListener('keydown', (e) => {
        const opts = options();
        const last = opts.length - 1;
        switch (e.key) {
            case 'ArrowDown':
            case 'ArrowUp': {
                e.preventDefault();
                const dir = e.key === 'ArrowDown' ? 1 : -1;
                if (!isOpen()) {
                    open();
                    return;
                }
                if (e.altKey && dir === -1) { choose(active); close(); return; }
                setActive(step(active, dir));
                return;
            }
            case 'Home':
            case 'End':
                if (!isOpen()) open();
                e.preventDefault();
                setActive(e.key === 'Home' ? step(-1, 1) : step(last + 1, -1));
                return;
            case 'PageDown':
            case 'PageUp':
                if (!isOpen()) return;
                e.preventDefault();
                setActive(e.key === 'PageDown' ? Math.min(last, step(Math.min(last, active + 9), -1)) : step(Math.max(0, active - 9), 1));
                return;
            case 'Enter':
            case ' ':
                if (e.key === ' ' && typed) { e.preventDefault(); const t = typeahead(' '); if (t >= 0) (isOpen() ? setActive(t) : choose(t)); return; }
                e.preventDefault();
                if (isOpen()) { choose(active); close(); } else open();
                return;
            case 'Escape':
                if (isOpen()) { e.preventDefault(); e.stopPropagation(); close(); }
                return;
            case 'Tab':
                if (isOpen()) { choose(active); close(); }
                return;
            default:
                if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
                    const t = typeahead(e.key);
                    if (t >= 0) (isOpen() ? setActive(t) : choose(t));
                }
        }
    });

    // Focus sent to the hidden select (label click, focus() from page code) goes to the button
    select.addEventListener('focus', () => button.focus());
    select.addEventListener('change', render);
    select.form?.addEventListener('reset', () => setTimeout(render, 0));

    // Page code sets .value / .selectedIndex directly: re-render after the native setter
    ['value', 'selectedIndex'].forEach((prop) => {
        const desc = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, prop);
        Object.defineProperty(select, prop, {
            configurable: true,
            get() { return desc.get.call(this); },
            set(v) { desc.set.call(this, v); render(); },
        });
    });
    // Options rebuilt or disabled, the select disabled, a field error added
    new MutationObserver(render).observe(select, {
        childList: true, subtree: true, attributes: true, attributeFilter: ['disabled', 'class', 'selected', 'label'],
    });
    // Removed from the page (modal closed): drop the list too
    new MutationObserver(() => {
        if (!document.body.contains(wrap)) list.remove();
    }).observe(document.body, { childList: true, subtree: true });

    const api = { close, position };
    render();
}

function enhanceSelects(root = document) {
    root.querySelectorAll('select.form-select').forEach(enhanceSelect);
}

if (SELECT_ENHANCE) {
    const reposition = () => openSelect?.position();
    window.addEventListener('resize', reposition);
    document.addEventListener('scroll', (e) => {
        // Scrolling inside the list itself is fine; anything else moves the button
        if (openSelect && !(e.target instanceof Element && e.target.classList.contains('cselect-list'))) reposition();
    }, true);
    document.addEventListener('mousedown', (e) => {
        if (!openSelect) return;
        if (e.target.closest?.('.cselect-list') || e.target.closest?.('.cselect.open')) return;
        openSelect.close();
    });
    const start = () => {
        enhanceSelects();
        // Selects added later (modals, rebuilt forms)
        new MutationObserver((records) => {
            records.forEach((r) => r.addedNodes.forEach((n) => {
                if (n.nodeType !== 1) return;
                if (n.matches?.('select.form-select')) enhanceSelect(n);
                else if (n.querySelectorAll) enhanceSelects(n);
            }));
        }).observe(document.body, { childList: true, subtree: true });
    };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();
}

// ---- Navbar ----

function renderNavbar(user, activePage) {
    const nav = document.getElementById('navbar');
    if (!nav) return;

    const links = [
        { href: '/dashboard.html', label: 'Home', key: 'dashboard' },
        ...(user.isEnrolled ? [{ href: '/change-password.html', label: 'Change Password', key: 'change-password' }] : []),
        { href: '/enroll.html', label: user.isEnrolled ? 'Security Settings' : 'Complete Enrollment', key: 'enroll' },
    ];
    if (user.isAdmin) links.push({ href: '/admin.html', label: 'Administration', key: 'admin' });

    nav.className = 'navbar';
    nav.innerHTML = `
        <a class="navbar-brand" href="/dashboard.html">
            <img class="navbar-brand-logo" src="/assets/logo.svg" alt="" width="36" height="36">
            <span class="navbar-brand-text">Password Self-Service</span>
        </a>
        <ul class="navbar-nav"></ul>
        <div class="navbar-user">
            <span class="navbar-user-name"></span>
            <span class="navbar-user-avatar"></span>
            <button type="button" class="btn btn-ghost btn-sm" id="logoutBtn">Sign out</button>
        </div>`;

    const list = nav.querySelector('.navbar-nav');
    links.forEach((link) => {
        const li = document.createElement('li');
        const a = document.createElement('a');
        a.href = link.href;
        a.textContent = link.label;
        if (link.key === activePage) a.classList.add('active');
        li.appendChild(a);
        list.appendChild(li);
    });

    const name = user.displayName || user.username;
    nav.querySelector('.navbar-user-name').textContent = name;
    nav.querySelector('.navbar-user-avatar').textContent = getInitials(name);
    nav.querySelector('#logoutBtn').addEventListener('click', logout);
}

// ---- Formatting ----

function getInitials(name) {
    return (name || '?')
        .split(/[\s._-]+/)
        .filter(Boolean)
        .slice(0, 2)
        .map((p) => p[0].toUpperCase())
        .join('');
}

function formatDate(value) {
    if (!value) return '—';
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function debounce(fn, delay = 300) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), delay);
    };
}
