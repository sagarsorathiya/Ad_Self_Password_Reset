(async function () {
    const user = await loadCurrentUser();
    if (!user || redirectIfNotEnrolled(user)) return;

    renderNavbar(user, 'dashboard');

    document.getElementById('welcomeTitle').textContent = `Welcome, ${user.displayName || user.username}`;
    document.getElementById('infoUsername').textContent = user.username;
    document.getElementById('infoDisplayName').textContent = user.displayName || '—';
    document.getElementById('infoEmail').textContent = user.email || '—';

    setBadge('sqBadge', user.securityQuestionsSet, 'Configured', 'Not set');
    setBadge('totpBadge', user.totpEnabled, 'Enabled', 'Not set');
    setBadge('enrolledBadge', user.isEnrolled, 'Enrolled', 'Incomplete');

    if (user.isAdmin) document.getElementById('adminLink').classList.remove('hidden');

    document.getElementById('content').classList.remove('hidden');

    function setBadge(id, ok, okText, pendingText) {
        const el = document.getElementById(id);
        el.className = `badge ${ok ? 'badge-success' : 'badge-warning'}`;
        el.textContent = ok ? okText : pendingText;
    }
})();
