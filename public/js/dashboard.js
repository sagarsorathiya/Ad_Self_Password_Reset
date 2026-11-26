(async function () {
    const DATE = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
    // Expiry within this many days shows the warning tone
    const EXPIRY_WARN_DAYS = 14;

    const user = await loadCurrentUser();
    if (!user || redirectIfNotEnrolled(user)) return;

    renderNavbar(user, 'dashboard');

    document.getElementById('welcomeTitle').textContent = `Welcome, ${user.displayName || user.username}`;
    document.getElementById('infoUsername').textContent = user.username;
    document.getElementById('infoDisplayName').textContent = user.displayName || '—';
    document.getElementById('infoEmail').textContent = user.email || '—';
    if (user.isAdmin) document.getElementById('adminLink').classList.remove('hidden');

    // Until account-status answers: the factors the user holds
    render({ factors: { totp: user.totpEnabled, sms: user.smsEnabled }, resetPolicy: null, passwordExpiry: null });
    showContent();

    try {
        const { data } = await api('GET', '/api/auth/account-status');
        render(data);
    } catch {
        // The dashboard still works without the expiry and policy details
    }

    function showContent() {
        document.getElementById('loadingSkeleton').remove();
        document.getElementById('content').classList.remove('hidden');
    }

    function render(status) {
        const factors = status.factors || {};
        renderRecovery();
        renderRow('questions', user.securityQuestionsSet, true, ['Change answers', 'Set up']);
        renderRow('totp', user.totpEnabled, factors.totp, ['Replace device', 'Set up']);
        renderRow('sms', user.smsEnabled, factors.sms, ['Change number', 'Add']);
        renderExpiry(status.passwordExpiry);
        renderHelp(status.resetPolicy, factors);
    }

    function heldMethods() {
        const names = [];
        if (user.securityQuestionsSet) names.push('Security questions');
        if (user.totpEnabled) names.push('an authenticator app');
        if (user.smsEnabled) names.push('a text-message number');
        return names;
    }

    function renderRecovery() {
        const card = document.getElementById('recoveryCard');
        const ready = Boolean(user.isEnrolled);
        card.classList.toggle('tone-success', ready);
        card.classList.toggle('tone-warning', !ready);
        document.getElementById('recoveryKicker').textContent = ready ? 'Recovery ready' : 'Setup incomplete';
        document.getElementById('recoveryTitle').textContent = ready
            ? 'You can reset your password yourself'
            : 'Finish setup to reset your password yourself';
        const names = heldMethods();
        document.getElementById('recoveryText').textContent = names.length
            ? `${joinWords(names)} ${names.length > 1 || user.securityQuestionsSet ? 'are' : 'is'} set up.`
            : 'No recovery method is set up yet.';
        document.getElementById('recoveryAction').classList.toggle('hidden', ready);
    }

    // A factor the admin turned off stays listed only for users who already hold it
    function renderRow(key, isSet, offered, [setLabel, newLabel]) {
        const row = document.getElementById(`row-${key}`);
        row.classList.toggle('hidden', !isSet && !offered);
        const badge = row.querySelector('[data-badge]');
        badge.className = `badge ${isSet ? 'badge-success' : 'badge-warning'}`;
        badge.textContent = isSet ? 'Set up' : 'Not set up';
        const action = row.querySelector('[data-action]');
        action.textContent = isSet ? setLabel : newLabel;
        action.classList.toggle('btn-secondary', isSet);
        action.classList.toggle('btn-primary', !isSet);
    }

    function renderExpiry(expiry) {
        const card = document.getElementById('expiryCard');
        if (!expiry || expiry.neverExpires || !expiry.expiresAt) {
            card.classList.add('hidden');
            return;
        }
        const days = Number(expiry.daysLeft);
        const when = DATE.format(new Date(expiry.expiresAt));
        const warn = days <= EXPIRY_WARN_DAYS;
        card.classList.toggle('tone-warning', warn);
        card.classList.toggle('tone-neutral', !warn);
        document.getElementById('expiryKicker').textContent = warn ? 'Password expires soon' : 'Password expiry';
        let title;
        if (days <= 0) title = `Expires today, ${when}`;
        else if (days === 1) title = `Tomorrow, on ${when}`;
        else title = `In ${days} days, on ${when}`;
        document.getElementById('expiryTitle').textContent = title;
        document.getElementById('expiryText').textContent = expiry.domain
            ? `The date your ${expiry.domain} password expires. Changing it here updates every connected domain.`
            : 'Changing it here updates every connected domain.';
        card.classList.remove('hidden');
    }

    // Built from the reset policy and the codes this user can receive
    function renderHelp(policy, factors) {
        const codes = [];
        if (user.totpEnabled && factors.totp !== false) codes.push('your authenticator app');
        if (user.smsEnabled && factors.sms !== false) codes.push('a text message');
        const codeText = codes.length ? `enter a code from ${codes.join(' or ')}` : '';
        let how;
        if (policy === 'both' && codeText) how = `answer your security questions, then ${codeText}`;
        else if (policy === 'totp_only' && codeText) how = codeText;
        else if (codeText) how = `answer your security questions, or ${codeText}`;
        else how = 'answer your security questions';

        const help = document.getElementById('helpText');
        help.textContent = 'Use ';
        const strong = document.createElement('strong');
        strong.textContent = 'Forgot password';
        help.append(strong, ` on the sign-in page and ${how}.`);
        document.getElementById('methodsNote').textContent = policy === 'both'
            ? 'A reset needs your questions and a code'
            : policy === 'totp_only' ? 'A reset needs one code' : '';
    }

    function joinWords(items) {
        if (items.length <= 1) return items.join('');
        return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
    }
})();
