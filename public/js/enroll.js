(async function () {
    const QUESTION_COUNT = 3;

    const user = await loadCurrentUser();
    if (!user) return;

    renderNavbar(user, 'enroll');

    let status;
    let questions;
    let myQuestions;
    try {
        const [statusRes, questionsRes, mineRes] = await Promise.all([
            api('GET', '/api/enrollment/status'),
            api('GET', '/api/enrollment/questions'),
            api('GET', '/api/enrollment/security-questions'),
        ]);
        status = statusRes.data;
        questions = questionsRes.data;
        myQuestions = mineRes.data;
    } catch (err) {
        showToast(err.message, 'error');
        return;
    }

    // A saved question may since have been deactivated by an admin; keep it selectable for this user
    myQuestions.forEach((q) => {
        if (!questions.some((x) => x.id === q.questionId)) questions.push({ id: q.questionId, question_text: q.questionText });
    });

    const manageMode = status.isEnrolled;
    const sections = ['manageView', 'step1', 'step2', 'step3'];

    document.getElementById('content').classList.remove('hidden');
    document.querySelectorAll('.reauth-group').forEach((g) => initPasswordToggles(g));
    initSecurityQuestions();
    initTotp();

    if (manageMode) {
        document.getElementById('pageTitle').textContent = 'Security Settings';
        document.getElementById('pageSubtitle').textContent = 'Manage how you verify your identity when resetting your password.';
        document.getElementById('stepper').classList.add('hidden');
        showOverview();
    } else {
        goToStep(status.securityQuestionsSet ? 2 : 1);
    }

    function showSection(id) {
        sections.forEach((s) => document.getElementById(s).classList.toggle('hidden', s !== id));
    }

    // ---- Setup wizard (not yet enrolled) ----

    function goToStep(n) {
        showSection(`step${n}`);
        const steps = document.querySelectorAll('#stepper .step');
        const connectors = document.querySelectorAll('#stepper .step-connector');
        steps.forEach((el, idx) => {
            el.classList.toggle('active', idx + 1 === n);
            el.classList.toggle('completed', idx + 1 < n);
        });
        connectors.forEach((el, idx) => el.classList.toggle('active', idx + 1 < n));

        if (n === 2) startTotpSetup(false);
        if (n === 3) finishEnrollment();
    }

    // ---- Management view (enrolled) ----

    function showOverview() {
        const list = document.getElementById('currentQuestions');
        list.innerHTML = '';
        myQuestions.forEach((q) => {
            const li = document.createElement('li');
            li.textContent = q.questionText;
            list.appendChild(li);
        });
        showSection('manageView');
    }

    document.getElementById('updateQuestionsBtn').addEventListener('click', () => {
        resetQuestionForm();
        showSection('step1');
    });

    document.getElementById('replaceTotpBtn').addEventListener('click', async () => {
        const pwInput = document.getElementById('totpCurrentPassword');
        setFieldError(pwInput, '');
        if (!pwInput.value) {
            setFieldError(pwInput, 'Enter your current password to continue.');
            pwInput.focus();
            return;
        }
        const ok = await startTotpSetup(true, pwInput.value);
        pwInput.value = '';
        if (ok) showSection('step2');
    });

    // ---- Security questions ----

    function savedIds() {
        return new Set(myQuestions.map((q) => String(q.questionId)));
    }

    function initSecurityQuestions() {
        const container = document.getElementById('sqFields');
        const form = document.getElementById('sqForm');
        const submitBtn = document.getElementById('sqSubmitBtn');
        const cancelBtn = document.getElementById('sqCancelBtn');

        if (questions.length < QUESTION_COUNT) {
            const alert = document.createElement('div');
            alert.className = 'alert alert-error';
            alert.textContent = 'Not enough security questions are configured. Please contact your administrator.';
            container.appendChild(alert);
            submitBtn.disabled = true;
            return;
        }

        for (let i = 0; i < QUESTION_COUNT; i++) {
            const group = document.createElement('div');
            group.className = 'mb-6';
            group.innerHTML = `
                <div class="form-group">
                    <label class="form-label" for="q${i}">Question ${i + 1}</label>
                    <select class="form-select" id="q${i}"></select>
                    <div class="form-error"></div>
                </div>
                <div class="form-group">
                    <label class="form-label" for="a${i}">Answer</label>
                    <div class="password-wrapper">
                        <input class="form-input" type="password" id="a${i}" maxlength="256" autocomplete="off">
                        <button type="button" class="password-toggle" aria-label="Show answer">👁️</button>
                    </div>
                    <div class="form-error"></div>
                </div>`;
            container.appendChild(group);
        }
        initPasswordToggles(container);

        const selects = [...container.querySelectorAll('select')];
        selects.forEach((s) => s.addEventListener('change', () => {
            refreshOptions(selects);
            updatePlaceholders();
        }));

        if (manageMode) {
            document.getElementById('sqExistingAlert').classList.remove('hidden');
            document.getElementById('sqReauthGroup').classList.remove('hidden');
            cancelBtn.classList.remove('hidden');
            submitBtn.textContent = 'Save Changes';
            cancelBtn.addEventListener('click', showOverview);
        }
        resetQuestionForm();

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            clearFieldErrors(form);

            const saved = savedIds();
            const answers = [];
            let valid = true;
            for (let i = 0; i < QUESTION_COUNT; i++) {
                const select = document.getElementById(`q${i}`);
                const input = document.getElementById(`a${i}`);
                const answer = input.value.trim();
                if (!select.value) {
                    setFieldError(select, 'Please choose a question.');
                    valid = false;
                }
                if (answer.length === 0 && saved.has(select.value)) {
                    answers.push({ questionId: Number(select.value), answer: '' });
                    continue;
                }
                if (answer.length < 2) {
                    setFieldError(input, saved.has(select.value)
                        ? 'Answer must be at least 2 characters (or leave blank to keep).'
                        : 'Answer must be at least 2 characters.');
                    valid = false;
                }
                answers.push({ questionId: Number(select.value), answer: input.value });
            }
            if (!valid) return;

            const body = { answers };
            const pwInput = document.getElementById('sqCurrentPassword');
            if (status.securityQuestionsSet) {
                if (!pwInput.value) {
                    setFieldError(pwInput, 'Enter your current password to save changes.');
                    return;
                }
                body.currentPassword = pwInput.value;
            }

            setButtonLoading(submitBtn, true, 'Saving...');
            try {
                await api('POST', '/api/enrollment/security-questions', body);
                pwInput.value = '';
                status.securityQuestionsSet = true;
                myQuestions = answers.map((a) => ({
                    questionId: a.questionId,
                    questionText: questions.find((q) => q.id === a.questionId)?.question_text || '',
                }));
                showToast('Security questions saved.', 'success');
                if (manageMode) showOverview();
                else goToStep(status.totpEnabled ? 3 : 2);
            } catch (err) {
                if (err.code === 'REAUTH_FAILED' || err.code === 'REAUTH_REQUIRED') {
                    setFieldError(pwInput, err.message);
                    pwInput.value = '';
                } else {
                    showToast(err.message, 'error');
                }
            } finally {
                setButtonLoading(submitBtn, false);
            }
        });
    }

    function resetQuestionForm() {
        const selects = [...document.querySelectorAll('#sqFields select')];
        if (selects.length === 0) return;
        selects.forEach((select, i) => {
            select.innerHTML = '';
            select.add(new Option('— Select a question —', ''));
            questions.forEach((q) => select.add(new Option(q.question_text, String(q.id))));
            select.value = myQuestions[i] ? String(myQuestions[i].questionId) : '';
            document.getElementById(`a${i}`).value = '';
        });
        refreshOptions(selects);
        updatePlaceholders();
        clearFieldErrors(document.getElementById('sqForm'));
    }

    function updatePlaceholders() {
        const saved = savedIds();
        for (let i = 0; i < QUESTION_COUNT; i++) {
            const select = document.getElementById(`q${i}`);
            document.getElementById(`a${i}`).placeholder = saved.has(select.value)
                ? '•••••• saved — leave blank to keep'
                : 'Your answer (not case-sensitive)';
        }
    }

    // Prevents the same question from being chosen twice.
    function refreshOptions(selects) {
        const chosen = selects.map((s) => s.value);
        selects.forEach((select, idx) => {
            const current = select.value;
            select.innerHTML = '';
            select.add(new Option('— Select a question —', ''));
            questions.forEach((q) => {
                const id = String(q.id);
                if (id !== current && chosen.includes(id)) return;
                select.add(new Option(q.question_text, id));
            });
            select.value = current;
            chosen[idx] = select.value;
        });
    }

    // ---- Authenticator ----

    let replacing = false;

    function initTotp() {
        const form = document.getElementById('totpForm');
        const codeInput = document.getElementById('totpCode');
        const verifyBtn = document.getElementById('totpVerifyBtn');

        if (manageMode) {
            const cancelBtn = document.getElementById('totpCancelBtn');
            cancelBtn.classList.remove('hidden');
            cancelBtn.addEventListener('click', showOverview);
        }

        codeInput.addEventListener('input', () => {
            codeInput.value = codeInput.value.replace(/\D/g, '').slice(0, 6);
        });

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            clearFieldErrors(form);

            const code = codeInput.value;
            if (!/^\d{6}$/.test(code)) {
                setFieldError(codeInput, 'Enter the 6-digit code from your authenticator app.');
                return;
            }

            setButtonLoading(verifyBtn, true, 'Verifying...');
            try {
                const res = await api('POST', '/api/enrollment/totp/verify', { code });
                status.totpEnabled = true;
                showToast(res.message || 'Authenticator app enabled.', 'success');
                if (manageMode) showOverview();
                else goToStep(3);
            } catch (err) {
                setFieldError(codeInput, err.message);
                codeInput.select();
            } finally {
                setButtonLoading(verifyBtn, false);
            }
        });
    }

    async function startTotpSetup(isReplacement, currentPassword) {
        replacing = isReplacement;
        document.getElementById('totpReplaceAlert').classList.toggle('hidden', !replacing);
        document.getElementById('totpVerifyBtn').textContent = replacing ? 'Verify New Device' : 'Verify & Enable';
        document.getElementById('totpCode').value = '';
        clearFieldErrors(document.getElementById('totpForm'));

        showOverlay();
        try {
            const { data } = await api('POST', '/api/enrollment/totp/setup', currentPassword ? { currentPassword } : {});
            document.getElementById('qrImage').src = data.qrCode;
            document.getElementById('manualKey').textContent = data.secret.replace(/(.{4})/g, '$1 ').trim();
            setTimeout(() => document.getElementById('totpCode').focus(), 0);
            return true;
        } catch (err) {
            if (err.code === 'REAUTH_FAILED' || err.code === 'REAUTH_REQUIRED') {
                setFieldError(document.getElementById('totpCurrentPassword'), err.message);
            } else {
                showToast(err.message, 'error');
            }
            return false;
        } finally {
            hideOverlay();
        }
    }

    // ---- Done ----

    async function finishEnrollment() {
        // Reissue the access token so its isEnrolled claim reflects the new state
        await refreshAccessToken();
        try {
            const { data } = await api('GET', '/api/auth/me');
            setCachedUser(data);
            renderNavbar(data, 'enroll');
        } catch {
            // Non-critical; dashboard reloads the user anyway
        }
    }
})();
