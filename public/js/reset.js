(function () {
    const RESET_TOKEN_TTL_MS = 10 * 60 * 1000;
    const SECTIONS = ['step1', 'step2', 'step3sq', 'step3totp', 'step3sms', 'step4', 'stepDone'];

    // Kept in memory only — never persisted
    const state = {
        username: '', methods: [], questions: [], resetToken: null, policy: 'either',
        stepToken: null, mobileMasked: '',
    };
    let countdownTimer = null;
    let smsResendTimer = null;

    initPasswordToggles();
    bindPasswordStrength(
        document.getElementById('newPassword'),
        document.getElementById('strength'),
        document.getElementById('reqList')
    );

    document.querySelectorAll('[data-back]').forEach((btn) => {
        btn.addEventListener('click', () => {
            // Back to the method cards when there was a choice, otherwise to the username
            const toChoice = Number(btn.dataset.back) !== 1 && hasMethodChoice();
            stopSmsCountdown();
            show(toChoice ? 'step2' : 'step1', toChoice ? 2 : 1);
        });
    });

    // ---- Navigation ----

    function show(sectionId, stepNumber) {
        SECTIONS.forEach((id) => document.getElementById(id).classList.toggle('hidden', id !== sectionId));
        const steps = document.querySelectorAll('#stepper .step');
        const connectors = document.querySelectorAll('#stepper .step-connector');
        steps.forEach((el, idx) => {
            el.classList.toggle('active', idx + 1 === stepNumber);
            el.classList.toggle('completed', idx + 1 < stepNumber);
        });
        connectors.forEach((el, idx) => el.classList.toggle('active', idx + 1 < stepNumber));
        document.getElementById('footer').classList.toggle('hidden', sectionId === 'stepDone');
    }

    // ---- Step 1: Username ----

    const userForm = document.getElementById('userForm');
    const usernameInput = document.getElementById('username');
    const userBtn = document.getElementById('userBtn');

    userForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearFieldErrors(userForm);

        const username = usernameInput.value.trim();
        if (!username) {
            setFieldError(usernameInput, 'Username is required.');
            return;
        }
        if (usernameFormatError(username)) {
            setFieldError(usernameInput, usernameFormatError(username));
            return;
        }

        setButtonLoading(userBtn, true, 'Checking...');
        try {
            const { data } = await api('POST', '/api/password/reset/verify-user', { username });
            state.username = data.username;
            state.methods = data.availableMethods || [];
            state.policy = data.policy || 'either';
            state.questions = [];
            state.stepToken = null;
            state.mobileMasked = data.mobileMasked || '';
            document.getElementById('totpStepHint').classList.add('hidden');
            document.getElementById('smsStepHint').classList.add('hidden');
            if (state.mobileMasked) {
                document.getElementById('smsMethodHint').textContent =
                    `We text a 6-digit code to ${state.mobileMasked}.`;
            }

            if (state.methods.length === 0) {
                setFieldError(usernameInput, 'No verification methods are available for this account. Contact your administrator.');
                return;
            }

            if (state.policy === 'both') {
                await loadQuestions();
                return;
            }
            // Nothing to choose when only one method is available (e.g. the totp_only policy)
            if (state.methods.length === 1) {
                await startMethod(state.methods[0]);
                return;
            }
            showMethodChoice(state.methods);
        } catch (err) {
            setFieldError(usernameInput, err.message);
        } finally {
            setButtonLoading(userBtn, false);
        }
    });

    // ---- Step 2: Method ----

    // Which methods are offered; under the 'both' policy this is used again for the second factor
    let choiceMethods = [];

    function showMethodChoice(methods, stepNumber = 2) {
        choiceMethods = methods;
        document.querySelectorAll('.method-card').forEach((card) => {
            card.classList.toggle('hidden', !methods.includes(card.dataset.method));
            card.classList.remove('selected');
        });
        show('step2', stepNumber);
    }

    // True while a Back button should return to the method cards rather than to the username
    function hasMethodChoice() {
        return choiceMethods.length > 1;
    }

    async function startMethod(method) {
        if (method === 'security_questions') return loadQuestions();
        if (method === 'totp') {
            show('step3totp', 3);
            totpInput.focus();
            return undefined;
        }
        return startSms();
    }

    document.querySelectorAll('.method-card').forEach((card) => {
        card.addEventListener('click', () => {
            document.querySelectorAll('.method-card').forEach((c) => c.classList.remove('selected'));
            card.classList.add('selected');
            startMethod(card.dataset.method);
        });
    });

    // ---- Step 3a: Security questions ----

    async function loadQuestions() {
        if (state.questions.length === 0) {
            showOverlay();
            try {
                const { data } = await api('POST', '/api/password/reset/get-questions', { username: state.username });
                state.questions = data;
            } catch (err) {
                showToast(err.message, 'error');
                return;
            } finally {
                hideOverlay();
            }
        }
        renderQuestions();
        show('step3sq', 3);
        document.getElementById('sqAnswer0')?.focus();
    }

    function renderQuestions() {
        const container = document.getElementById('sqFields');
        container.innerHTML = '';
        state.questions.forEach((q, i) => {
            const group = document.createElement('div');
            group.className = 'form-group';

            const label = document.createElement('label');
            label.className = 'form-label';
            label.htmlFor = `sqAnswer${i}`;
            label.textContent = q.question_text;

            const wrapper = document.createElement('div');
            wrapper.className = 'password-wrapper';
            wrapper.innerHTML = `
                <input class="form-input" type="password" id="sqAnswer${i}" data-question-id="${Number(q.id)}"
                       maxlength="256" autocomplete="off" placeholder="Your answer">
                <button type="button" class="password-toggle" aria-label="Show answer">👁️</button>`;

            const error = document.createElement('div');
            error.className = 'form-error';

            group.append(label, wrapper, error);
            container.appendChild(group);
        });
        initPasswordToggles(container);
    }

    const sqForm = document.getElementById('sqForm');
    const sqBtn = document.getElementById('sqBtn');

    sqForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearFieldErrors(sqForm);

        const inputs = [...sqForm.querySelectorAll('input[data-question-id]')];
        let valid = true;
        inputs.forEach((input) => {
            if (!input.value.trim()) {
                setFieldError(input, 'Please provide an answer.');
                valid = false;
            }
        });
        if (!valid) return;

        const answers = inputs.map((input) => ({
            questionId: Number(input.dataset.questionId),
            answer: input.value,
        }));

        setButtonLoading(sqBtn, true, 'Verifying...');
        try {
            const { data } = await api('POST', '/api/password/reset/verify-questions', {
                username: state.username,
                answers,
            });
            inputs.forEach((input) => { input.value = ''; });
            if (data.stepToken) {
                state.stepToken = data.stepToken;
                // 'both' policy: the answers were step 1; now one of the user's one-time codes
                const next = data.nextSteps?.length ? data.nextSteps : [data.nextStep || 'totp'];
                // Each hint only shows inside its own section, so both can be enabled here
                document.getElementById('totpStepHint').classList.remove('hidden');
                document.getElementById('smsStepHint').classList.remove('hidden');
                if (next.length > 1) showMethodChoice(next, 3);
                else await startMethod(next[0]);
                return;
            }
            onVerified(data.resetToken);
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            setButtonLoading(sqBtn, false);
        }
    });

    // ---- Step 3b: TOTP ----

    const totpForm = document.getElementById('totpForm');
    const totpInput = document.getElementById('totpCode');
    const totpBtn = document.getElementById('totpBtn');

    totpInput.addEventListener('input', () => {
        totpInput.value = totpInput.value.replace(/\D/g, '').slice(0, 6);
    });

    totpForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearFieldErrors(totpForm);

        const code = totpInput.value;
        if (!/^\d{6}$/.test(code)) {
            setFieldError(totpInput, 'Enter the 6-digit code from your authenticator app.');
            return;
        }

        setButtonLoading(totpBtn, true, 'Verifying...');
        try {
            const { data } = await api('POST', '/api/password/reset/verify-totp', {
                username: state.username,
                code,
                stepToken: state.stepToken || undefined,
            });
            totpInput.value = '';
            onVerified(data.resetToken);
        } catch (err) {
            setFieldError(totpInput, err.message);
            totpInput.select();
        } finally {
            setButtonLoading(totpBtn, false);
        }
    });

    // ---- Step 3c: SMS code ----

    const smsForm = document.getElementById('smsForm');
    const smsInput = document.getElementById('smsCode');
    const smsBtn = document.getElementById('smsBtn');
    const smsResendBtn = document.getElementById('smsResendBtn');

    smsInput.addEventListener('input', () => {
        smsInput.value = smsInput.value.replace(/\D/g, '').slice(0, 6);
    });

    // Opening the step sends the code; the section is shown either way, so a failed send does not
    // reveal whether the account exists
    async function startSms(resend = false) {
        show('step3sms', 3);
        smsInput.value = '';
        clearFieldErrors(smsForm);
        if (!resend) showOverlay();
        try {
            const { data } = await api('POST', '/api/password/reset/send-sms', {
                username: state.username,
                stepToken: state.stepToken || undefined,
            });
            document.getElementById('smsSentTo').textContent =
                `We sent a 6-digit code to ${data.mobileMasked}. It is valid for ${data.expiresInMinutes} minutes.`;
            startSmsCountdown(data.resendAfter);
            if (resend) showToast('A new code has been sent.', 'success');
            smsInput.focus();
        } catch (err) {
            if (err.code === 'SMS_COOLDOWN') {
                startSmsCountdown(err.data?.resendAfter || 60);
                showToast(err.message, 'warning');
            } else {
                showToast(err.message, 'error');
            }
        } finally {
            if (!resend) hideOverlay();
        }
    }

    smsResendBtn.addEventListener('click', () => startSms(true));

    smsForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearFieldErrors(smsForm);

        const code = smsInput.value;
        if (!/^\d{6}$/.test(code)) {
            setFieldError(smsInput, 'Enter the 6-digit code from the text message.');
            return;
        }

        setButtonLoading(smsBtn, true, 'Verifying...');
        try {
            const { data } = await api('POST', '/api/password/reset/verify-sms', {
                username: state.username,
                code,
                stepToken: state.stepToken || undefined,
            });
            smsInput.value = '';
            stopSmsCountdown();
            onVerified(data.resetToken);
        } catch (err) {
            setFieldError(smsInput, err.message);
            smsInput.select();
        } finally {
            setButtonLoading(smsBtn, false);
        }
    });

    function startSmsCountdown(seconds) {
        let left = Number(seconds) || 0;
        stopSmsCountdown();
        const tick = () => {
            if (left <= 0) {
                stopSmsCountdown();
                return;
            }
            smsResendBtn.disabled = true;
            smsResendBtn.textContent = `Resend in ${left}s`;
            left -= 1;
        };
        tick();
        smsResendTimer = setInterval(tick, 1000);
    }

    function stopSmsCountdown() {
        clearInterval(smsResendTimer);
        smsResendTimer = null;
        smsResendBtn.disabled = false;
        smsResendBtn.textContent = 'Resend code';
    }

    // ---- Step 4: New password ----

    function onVerified(resetToken) {
        state.resetToken = resetToken;
        show('step4', 4);
        document.getElementById('newPassword').focus();
        startCountdown();
        // Hide back navigation once verified
        document.querySelectorAll('[data-back]').forEach((b) => b.classList.add('hidden'));
    }

    function startCountdown() {
        const el = document.getElementById('countdown');
        const expiresAt = Date.now() + RESET_TOKEN_TTL_MS;
        clearInterval(countdownTimer);
        const tick = () => {
            const remaining = Math.max(0, expiresAt - Date.now());
            const m = Math.floor(remaining / 60000);
            const s = Math.floor((remaining % 60000) / 1000);
            el.textContent = `${m}:${String(s).padStart(2, '0')}`;
            if (remaining === 0) {
                clearInterval(countdownTimer);
                state.resetToken = null;
                showToast('Your verification has expired. Please start again.', 'warning');
                setTimeout(() => window.location.reload(), 2500);
            }
        };
        tick();
        countdownTimer = setInterval(tick, 1000);
    }

    const pwForm = document.getElementById('pwForm');
    const newPw = document.getElementById('newPassword');
    const confirmPw = document.getElementById('confirmPassword');
    const pwBtn = document.getElementById('pwBtn');

    pwForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearFieldErrors(pwForm);

        let valid = true;
        if (!meetsComplexity(newPw.value)) {
            setFieldError(newPw, 'Password does not meet the complexity requirements.');
            valid = false;
        }
        if (confirmPw.value !== newPw.value) {
            setFieldError(confirmPw, 'Passwords do not match.');
            valid = false;
        }
        if (!valid || !state.resetToken) return;

        setButtonLoading(pwBtn, true, 'Resetting...');
        try {
            const res = await api('POST', '/api/password/reset/set-password', {
                resetToken: state.resetToken,
                newPassword: newPw.value,
                confirmPassword: confirmPw.value,
            });
            const syncWarning = document.getElementById('doneSyncWarning');
            syncWarning.textContent = res.data?.sync?.status === 'failed' ? res.message : '';
            syncWarning.classList.toggle('hidden', res.data?.sync?.status !== 'failed');
            state.resetToken = null;
            clearInterval(countdownTimer);
            pwForm.reset();
            show('stepDone', 5);
        } catch (err) {
            setFieldError(newPw, err.message);
        } finally {
            setButtonLoading(pwBtn, false);
        }
    });
})();
