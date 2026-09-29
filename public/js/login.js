(function () {
    const form = document.getElementById('loginForm');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const loginBtn = document.getElementById('loginBtn');

    initPasswordToggles();

    const params = new URLSearchParams(window.location.search);
    if (params.get('expired')) {
        showAlert('Your session has expired. Please sign in again.');
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

        const username = usernameInput.value.trim();
        const password = passwordInput.value;
        let valid = true;

        if (!username) {
            setFieldError(usernameInput, 'Username is required.');
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
            showAlert(err.message);
            passwordInput.value = '';
            passwordInput.focus();
            setButtonLoading(loginBtn, false);
        }
    });

    function goToLanding(user) {
        window.location.href = user.isEnrolled ? '/dashboard.html' : '/enroll.html';
    }

    function showAlert(message) {
        document.getElementById('loginAlertText').textContent = message;
        document.getElementById('loginAlert').classList.remove('hidden');
    }

    function hideAlert() {
        document.getElementById('loginAlert').classList.add('hidden');
    }
})();
