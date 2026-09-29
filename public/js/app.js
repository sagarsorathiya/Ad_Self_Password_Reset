/* ============================================
   Shared client utilities
   ============================================ */

const TOKEN_KEY = 'sspr_token';
const REFRESH_KEY = 'sspr_refresh';
const USER_KEY = 'sspr_user';

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

async function logout() {
    try {
        await api('POST', '/api/auth/logout', {}, { retry: false });
    } catch {
        // Logout is client-side; ignore server errors
    }
    clearToken();
    window.location.href = '/index.html';
}

// ---- Toast notifications ----

const TOAST_ICONS = { success: '✅', error: '⛔', warning: '⚠️', info: 'ℹ️' };

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

    const icon = document.createElement('span');
    icon.className = 'toast-icon';
    icon.textContent = TOAST_ICONS[type] || TOAST_ICONS.info;

    const msg = document.createElement('div');
    msg.className = 'toast-message';
    msg.textContent = message;

    const close = document.createElement('button');
    close.className = 'toast-close';
    close.setAttribute('aria-label', 'Dismiss');
    close.textContent = '×';

    toast.append(icon, msg, close);
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

// ---- Password strength ----

function getPasswordChecks(password) {
    return {
        length: password.length >= 8,
        lower: /[a-z]/.test(password),
        upper: /[A-Z]/.test(password),
        digit: /\d/.test(password),
        symbol: /[^A-Za-z0-9]/.test(password),
    };
}

// AD default complexity: 3 of 4 character categories + minimum length
function meetsComplexity(password) {
    const c = getPasswordChecks(password);
    const categories = [c.lower, c.upper, c.digit, c.symbol].filter(Boolean).length;
    return c.length && categories >= 3;
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
function bindPasswordStrength(input, meterRoot, reqList) {
    const fill = meterRoot.querySelector('.strength-fill');
    const text = meterRoot.querySelector('.strength-text');
    const update = () => {
        const { level, label } = evaluatePasswordStrength(input.value);
        fill.className = `strength-fill ${level}`;
        text.textContent = label ? `Strength: ${label}` : '';
        if (reqList) {
            const checks = getPasswordChecks(input.value);
            reqList.querySelectorAll('[data-req]').forEach((li) => {
                li.classList.toggle('met', Boolean(checks[li.dataset.req]));
            });
        }
    };
    input.addEventListener('input', update);
    update();
}

// ---- Navbar ----

function renderNavbar(user, activePage) {
    const nav = document.getElementById('navbar');
    if (!nav) return;

    const links = [
        { href: '/dashboard.html', label: 'Home', key: 'dashboard' },
        { href: '/change-password.html', label: 'Change Password', key: 'change-password' },
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
