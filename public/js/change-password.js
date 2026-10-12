(async function () {
    const user = await loadCurrentUser();
    if (!user) return;

    renderNavbar(user, 'change-password');
    document.getElementById('content').classList.remove('hidden');

    const form = document.getElementById('changeForm');
    const current = document.getElementById('currentPassword');
    const next = document.getElementById('newPassword');
    const confirm = document.getElementById('confirmPassword');
    const submitBtn = document.getElementById('submitBtn');

    initPasswordToggles();
    bindPasswordStrength(next, document.getElementById('strength'), document.getElementById('reqList'));

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearFieldErrors(form);

        let valid = true;
        if (!current.value) {
            setFieldError(current, 'Current password is required.');
            valid = false;
        }
        if (!meetsComplexity(next.value)) {
            setFieldError(next, 'Password does not meet the complexity requirements.');
            valid = false;
        } else if (next.value === current.value) {
            setFieldError(next, 'New password must be different from your current password.');
            valid = false;
        }
        if (confirm.value !== next.value) {
            setFieldError(confirm, 'Passwords do not match.');
            valid = false;
        }
        if (!valid) return;

        setButtonLoading(submitBtn, true, 'Updating...');
        try {
            const res = await api('POST', '/api/password/change', {
                currentPassword: current.value,
                newPassword: next.value,
                confirmPassword: confirm.value,
            });
            form.reset();
            // The password changed in the main domain but the second domain rejected it: give time to read why
            const partial = res.data?.sync?.status === 'failed';
            if (partial) {
                showToast(`${res.message} Signing you out...`, 'warning', 12000);
            } else {
                showToast('Password changed successfully. Signing you out...', 'success');
            }
            setTimeout(() => {
                clearToken();
                window.location.href = '/index.html?changed=1';
            }, partial ? 12000 : 2000);
        } catch (err) {
            if (err.status === 401 && err.code !== 'SESSION_EXPIRED') {
                setFieldError(current, err.message);
            } else {
                showToast(err.message, 'error');
            }
            setButtonLoading(submitBtn, false);
        }
    });
})();
