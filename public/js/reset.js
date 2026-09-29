(function () {
    const RESET_TOKEN_TTL_MS = 10 * 60 * 1000;
    const SECTIONS = ['step1', 'step2', 'step3sq', 'step3totp', 'step4', 'stepDone'];

    // Kept in memory only — never persisted
    const state = { username: '', methods: [], questions: [], resetToken: null, policy: 'either', stepToken: null };
    let countdownTimer = null;

    initPasswordToggles();
    bindPasswordStrength(
        document.getElementById('newPassword'),
        document.getElementById('strength'),
        document.getElementById('reqList')
    );

    document.querySelectorAll('[data-back]').forEach((btn) => {
        btn.addEventListener('click', () => {
            const step = Number(btn.dataset.back);
            // Method choice only exists under the 'either' policy
            show(step === 1 || state.policy !== 'either' ? 'step1' : 'step2', step === 1 || state.policy !== 'either' ? 1 : 2);
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

        setButtonLoading(userBtn, true, 'Checking...');
        try {
            const { data } = await api('POST', '/api/password/reset/verify-user', { username });
            state.username = data.username;
            state.methods = data.availableMethods || [];
            state.policy = data.policy || 'either';
            state.questions = [];
            state.stepToken = null;
            document.getElementById('totpStepHint').classList.add('hidden');

            if (state.methods.length === 0) {
                setFieldError(usernameInput, 'No verification methods are available for this account. Contact your administrator.');
                return;
            }

            if (state.policy === 'both') {
                await loadQuestions();
                return;
            }
            if (state.policy === 'totp_only') {
                show('step3totp', 3);
                totpInput.focus();
                return;
            }

            document.querySelectorAll('.method-card').forEach((card) => {
                card.classList.toggle('hidden', !state.methods.includes(card.dataset.method));
            });
            show('step2', 2);
        } catch (err) {
            setFieldError(usernameInput, err.message);
        } finally {
            setButtonLoading(userBtn, false);
        }
    });

    // ---- Step 2: Method ----

    document.querySelectorAll('.method-card').forEach((card) => {
        card.addEventListener('click', () => {
            document.querySelectorAll('.method-card').forEach((c) => c.classList.remove('selected'));
            card.classList.add('selected');
            if (card.dataset.method === 'totp') {
                show('step3totp', 3);
                document.getElementById('totpCode').focus();
            } else {
                loadQuestions();
            }
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
                document.getElementById('totpStepHint').classList.remove('hidden');
                show('step3totp', 3);
                totpInput.focus();
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
            await api('POST', '/api/password/reset/set-password', {
                resetToken: state.resetToken,
                newPassword: newPw.value,
                confirmPassword: confirmPw.value,
            });
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
