(function () {
    const form = document.getElementById('loginForm');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const loginBtn = document.getElementById('loginBtn');

    initPasswordToggles();
    applyDomainPrefix(usernameInput);
    bindUsernameHint(usernameInput, document.getElementById('usernameHint'));

    const expiredPanel = document.getElementById('expiredPanel');
    document.getElementById('expiredBackBtn').addEventListener('click', () => {
        expiredPanel.classList.add('hidden');
        form.classList.remove('hidden');
        document.getElementById('loginFooter').classList.remove('hidden');
        usernameInput.value = '';
        passwordInput.value = '';
        usernameInput.focus();
    });

    const params = new URLSearchParams(window.location.search);
    if (params.get('expired')) {
        showAlert('Your session has expired. Please sign in again.');
    } else if (params.get('revoked')) {
        showAlert('You were signed out because your password or access changed. Please sign in again.');
    } else if (params.get('idle')) {
        showAlert('You were signed out after 30 minutes without activity.');
    } else if (params.get('changed')) {
        showToast('Password changed. Please sign in with your new password.', 'success');
    }

    // Already signed in? Skip the login form.
    if (getToken()) {
        api('GET', '/api/auth/me')
            .then(({ data }) => {
                setCachedUser(data);
                goToLanding(data);
            })
            .catch(() => clearToken());
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearFieldErrors(form);
        hideAlert();

        const username = stripDomainPrefix(usernameInput.value.trim());
        const password = passwordInput.value;
        let valid = true;

        if (!username) {
            setFieldError(usernameInput, 'Username is required.');
            valid = false;
        } else if (usernameFormatError(username)) {
            setFieldError(usernameInput, usernameFormatError(username));
            valid = false;
        }
        if (!password) {
            setFieldError(passwordInput, 'Password is required.');
            valid = false;
        }
        if (!valid) return;

        setButtonLoading(loginBtn, true, 'Signing in...');
        try {
            const { data } = await api('POST', '/api/auth/login', { username, password }, { retry: false });
            setToken(data.token, data.refreshToken);
            setCachedUser(data.user);
            goToLanding(data.user);
        } catch (err) {
            passwordInput.value = '';
            setButtonLoading(loginBtn, false);
            if (err.code === 'PASSWORD_EXPIRED') {
                // Signing in cannot work until the password is reset: one path there, with the name filled in
                showExpiredPanel(username);
                return;
            }
            showAlert(err.message);
            passwordInput.focus();
        }
    });

    function goToLanding(user) {
        window.location.href = user.isEnrolled ? '/dashboard.html' : '/enroll.html';
    }

    function showExpiredPanel(username) {
        document.getElementById('expiredUser').textContent = username;
        document.getElementById('expiredResetLink').href = `/reset.html?username=${encodeURIComponent(username)}`;
        form.classList.add('hidden');
        document.getElementById('loginFooter').classList.add('hidden');
        expiredPanel.classList.remove('hidden');
        document.getElementById('expiredTitle').focus();
    }

    function showAlert(message) {
        document.getElementById('loginAlertText').textContent = message;
        document.getElementById('loginAlert').classList.remove('hidden');
    }

    function hideAlert() {
        document.getElementById('loginAlert').classList.add('hidden');
    }
})();
