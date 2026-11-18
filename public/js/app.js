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
    constructor(message, status, code) {
        super(message);
        this.status = status;
        this.code = code;
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
        throw new ApiError(message, res.status, json.code);
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
    if (item) item.textContent = `At least ${passwordRules.minLength} characters`;
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
function bindPasswordStrength(input, meterRoot, reqList, identity = () => ({})) {
    const fill = meterRoot.querySelector('.strength-fill');
    const text = meterRoot.querySelector('.strength-text');
    const update = () => {
        const { level, label } = evaluatePasswordStrength(input.value);
        fill.className = `strength-fill ${level}`;
        text.textContent = label ? `Strength: ${label}` : '';
        if (reqList) {
            const checks = getPasswordChecks(input.value, identity());
            reqList.querySelectorAll('[data-req]').forEach((li) => {
                li.classList.toggle('met', Boolean(checks[li.dataset.req]));
            });
        }
    };
    input.addEventListener('input', update);
    loadPasswordRules().then(() => {
        renderLengthRule(reqList);
        // The complexity items only matter when the domain enforces them
        reqList?.querySelectorAll('[data-req="lower"], [data-req="upper"], [data-req="digit"], [data-req="symbol"]')
            .forEach((li) => li.classList.toggle('hidden', !passwordRules.complexity));
        document.querySelectorAll('[data-complexity-only]')
            .forEach((el) => el.classList.toggle('hidden', !passwordRules.complexity));
        update();
    });
    update();
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
