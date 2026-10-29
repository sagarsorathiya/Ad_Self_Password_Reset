(async function () {
    // Set from the enrollment status below; declared here so nothing can hit it in its dead zone
    let QUESTION_COUNT = 3;
    // Declared before the first goToStep(2) call: touching a later `let` there throws silently
    let replacing = false;
    // Which second factors the administrator allows, and the SMS state of this user
    let FACTORS = { totp: true, sms: false };
    let smsReplacing = false;
    let smsResendTimer = null;

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
        // How many questions this user has to set now; an older enrollment may still hold more
        QUESTION_COUNT = Number(status.questionCount) || QUESTION_COUNT;
        FACTORS = status.factors || FACTORS;
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
    initSms();
    applyFactorLabels();

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

        if (n === 2) startSecondFactor();
        if (n === 3) finishEnrollment();
    }

    // ---- Second factor: authenticator app, SMS, or a choice between them ----

    // True once the user holds a second factor the administrator still allows
    function hasSecondFactor() {
        return Boolean((FACTORS.totp && status.totpEnabled) || (FACTORS.sms && status.smsEnabled));
    }

    // The wizard asks only when the administrator allows both; with one factor it goes straight into it
    function startSecondFactor() {
        const choice = document.getElementById('factorChoice');
        if (FACTORS.totp && FACTORS.sms) {
            choice.classList.remove('hidden');
            document.getElementById('totpSetup').classList.add('hidden');
            document.getElementById('smsSetup').classList.add('hidden');
            return;
        }
        choice.classList.add('hidden');
        if (FACTORS.sms) showSmsSetup(false);
        else showTotpSetup(false);
    }

    function showTotpSetup(isReplacement, currentPassword) {
        document.getElementById('factorChoice').classList.add('hidden');
        document.getElementById('smsSetup').classList.add('hidden');
        document.getElementById('totpSetup').classList.remove('hidden');
        return startTotpSetup(isReplacement, currentPassword);
    }

    function showSmsSetup(isReplacement) {
        document.getElementById('factorChoice').classList.add('hidden');
        document.getElementById('totpSetup').classList.add('hidden');
        document.getElementById('smsSetup').classList.remove('hidden');
        resetSmsForms(isReplacement);
    }

    // The step label and the "all set" wording depend on which factors exist
    function applyFactorLabels() {
        const label = document.getElementById('step2Label');
        if (FACTORS.totp && FACTORS.sms) label.textContent = 'Verification';
        else if (FACTORS.sms) label.textContent = 'Text Message';
        document.querySelectorAll('#factorChoice .method-card').forEach((card) => {
            card.addEventListener('click', () => {
                if (card.dataset.factor === 'sms') showSmsSetup(false);
                else showTotpSetup(false);
            });
        });
        const back = document.getElementById('smsBackBtn');
        back.classList.toggle('hidden', manageMode || !(FACTORS.totp && FACTORS.sms));
        back.addEventListener('click', startSecondFactor);
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
        renderSmsCard();
        // Hidden when the administrator has turned authenticator apps off and this user never set one up
        document.getElementById('totpManageCard').classList.toggle('hidden', !FACTORS.totp && !status.totpEnabled);
        const totpBadge = document.getElementById('totpManageBadge');
        totpBadge.textContent = status.totpEnabled ? 'Active' : 'Not set up';
        totpBadge.className = `badge ${status.totpEnabled ? 'badge-success' : 'badge-warning'}`;
        document.getElementById('replaceTotpBtn').textContent = status.totpEnabled
            ? 'Replace authenticator (new device)'
            : 'Set up an authenticator app';
        document.getElementById('totpManageText').textContent = status.totpEnabled
            ? 'Got a new phone or reinstalled your authenticator app? Link the new device here. '
              + 'Your current device keeps working until the new one is verified.'
            : 'Add an authenticator app as another way to confirm it is you.';
        document.getElementById('totpReauthGroup').classList.toggle('hidden', !needsPassword(status.totpEnabled));
        showSection('manageView');
    }

    /**
     * Whether a factor change has to be confirmed with the Windows password, mirroring
     * confirmFactorChange() on the server: once you are enrolled, *adding* a factor counts too, not only
     * replacing the one you have. Keep the two in step - when the field is hidden but the server asks for
     * it, the button silently does nothing (production 2026-10-29).
     */
    function needsPassword(factorEnabled) {
        return Boolean(status.isEnrolled || factorEnabled);
    }

    // The SMS card doubles as "set it up" and "change the number", so an enrolled user can add the
    // second factor later without going through the wizard again.
    function renderSmsCard() {
        const card = document.getElementById('smsManageCard');
        card.classList.toggle('hidden', !FACTORS.sms);
        if (!FACTORS.sms) return;

        const badge = document.getElementById('smsManageBadge');
        badge.textContent = status.smsEnabled ? 'Active' : 'Not set up';
        badge.className = `badge ${status.smsEnabled ? 'badge-success' : 'badge-warning'}`;

        setSmsCardText(status.mobile?.masked || '');

        document.getElementById('smsReauthGroup').classList.toggle('hidden', !needsPassword(status.smsEnabled));
        document.getElementById('smsManageBtn').textContent = status.smsEnabled
            ? 'Change mobile number'
            : 'Send a code to this number';
    }

    /**
     * Write the card's sentence with the number in bold. Rebuilt element by element every time:
     * setting textContent on the paragraph would delete any <strong> inside it, so a second render
     * found nothing to write to ("Cannot set properties of null", production 2026-10-29).
     */
    function setSmsCardText(known) {
        const target = document.getElementById('smsManageText');
        target.textContent = '';

        if (!known) {
            target.textContent = 'Add a mobile number to receive one-time codes by text message.';
            return;
        }

        const number = document.createElement('strong');
        number.textContent = known;
        if (status.smsEnabled) {
            target.append('Codes are sent to ', number, '.');
        } else {
            target.append('We can send codes to ', number, ', the number on your account. '
                + 'Verify it to switch this on.');
        }
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
        showSection('step2');
        // Only a replacement when one is already active; otherwise this is a first authenticator
        const ok = await showTotpSetup(status.totpEnabled, pwInput.value);
        pwInput.value = '';
        if (!ok) showOverview();
    });

    document.getElementById('smsManageBtn').addEventListener('click', async () => {
        const pwInput = document.getElementById('smsCurrentPassword');
        const mobileInput = document.getElementById('smsManageMobile');
        setFieldError(pwInput, '');
        setFieldError(mobileInput, '');

        // A factor change on an enrolled account is confirmed with the password, whether the number is
        // new or replacing a verified one
        if (needsPassword(status.smsEnabled) && !pwInput.value) {
            setFieldError(pwInput, 'Enter your current password to continue.');
            pwInput.focus();
            return;
        }

        showSection('step2');
        showSmsSetup(status.smsEnabled);
        const ok = await sendSmsCode({
            mobile: mobileInput.value.trim() || undefined,
            currentPassword: pwInput.value || undefined,
        });
        pwInput.value = '';
        mobileInput.value = '';
        if (!ok) showOverview();
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
                else goToStep(hasSecondFactor() ? 3 : 2);
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
        const setupError = document.getElementById('totpSetupError');
        document.getElementById('totpRetryBtn').onclick = () => startTotpSetup(isReplacement, currentPassword);

        showOverlay();
        try {
            // Inside the try so any failure shows the error box instead of a silent blank QR code
            replacing = isReplacement;
            document.getElementById('totpReplaceAlert').classList.toggle('hidden', !replacing);
            document.getElementById('totpVerifyBtn').textContent = replacing ? 'Verify New Device' : 'Verify & Enable';
            document.getElementById('totpCode').value = '';
            clearFieldErrors(document.getElementById('totpForm'));
            setupError.classList.add('hidden');

            const { data } = await api('POST', '/api/enrollment/totp/setup', currentPassword ? { currentPassword } : {});
            document.getElementById('qrImage').src = data.qrCode;
            document.getElementById('manualKey').textContent = data.secret.replace(/(.{4})/g, '$1 ').trim();
            setTimeout(() => document.getElementById('totpCode').focus(), 0);
            return true;
        } catch (err) {
            if (err.code === 'REAUTH_FAILED' || err.code === 'REAUTH_REQUIRED') {
                setFieldError(document.getElementById('totpCurrentPassword'), err.message);
            } else {
                // Stay visible: a toast alone leaves a blank QR code with no explanation
                document.getElementById('totpSetupErrorText').textContent =
                    `Could not load the QR code. ${err.message}`;
                setupError.classList.remove('hidden');
                showToast(err.message, 'error');
            }
            return false;
        } finally {
            hideOverlay();
        }
    }

    // ---- Text message (SMS) ----

    function initSms() {
        const mobileForm = document.getElementById('smsMobileForm');
        const codeForm = document.getElementById('smsForm');
        const codeInput = document.getElementById('smsCode');

        document.getElementById('smsOtherNumberBtn').addEventListener('click', () => {
            document.getElementById('smsDirectoryHint').style.display = 'none';
            document.getElementById('smsMobileGroup').style.display = '';
            document.getElementById('smsMobile').focus();
        });

        codeInput.addEventListener('input', () => {
            codeInput.value = codeInput.value.replace(/\D/g, '').slice(0, 6);
        });

        mobileForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const input = document.getElementById('smsMobile');
            const visible = document.getElementById('smsMobileGroup').style.display !== 'none';
            clearFieldErrors(mobileForm);
            if (visible && !input.value.trim()) {
                setFieldError(input, 'Enter your mobile number, including the country code.');
                return;
            }
            const btn = document.getElementById('smsSendBtn');
            setButtonLoading(btn, true, 'Sending...');
            await sendSmsCode({ mobile: visible ? input.value.trim() : undefined });
            setButtonLoading(btn, false);
        });

        document.getElementById('smsResendBtn').addEventListener('click', async () => {
            // The number is already staged on the server, so a resend needs no input
            await sendSmsCode({ resend: true });
        });

        codeForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            clearFieldErrors(codeForm);

            const code = codeInput.value;
            if (!/^\d{6}$/.test(code)) {
                setFieldError(codeInput, 'Enter the 6-digit code from the text message.');
                return;
            }

            const btn = document.getElementById('smsVerifyBtn');
            setButtonLoading(btn, true, 'Verifying...');
            try {
                const res = await api('POST', '/api/enrollment/sms/verify', { code });
                status.smsEnabled = true;
                stopResendCountdown();
                showToast(res.message || 'Mobile number verified.', 'success');
                const fresh = await api('GET', '/api/enrollment/status').catch(() => null);
                if (fresh) status = fresh.data;
                if (manageMode) showOverview();
                else goToStep(3);
            } catch (err) {
                setFieldError(codeInput, err.message);
                codeInput.select();
            } finally {
                setButtonLoading(btn, false);
            }
        });
    }

    // Back to "which number?" before a code has been sent
    function resetSmsForms(isReplacement) {
        smsReplacing = isReplacement;
        stopResendCountdown();
        document.getElementById('smsReplaceAlert').classList.toggle('hidden', !isReplacement);
        document.getElementById('smsForm').classList.add('hidden');
        document.getElementById('smsMobileForm').classList.remove('hidden');
        document.getElementById('smsCode').value = '';
        document.getElementById('smsMobile').value = '';
        clearFieldErrors(document.getElementById('smsMobileForm'));
        clearFieldErrors(document.getElementById('smsForm'));

        // A number already on the account is offered first; only users without one have to type it
        const known = !isReplacement && status.mobile?.masked;
        document.getElementById('smsKnownNumber').textContent = known || '';
        document.getElementById('smsDirectoryHint').style.display = known ? '' : 'none';
        document.getElementById('smsMobileGroup').style.display = known ? 'none' : '';
    }

    /**
     * Ask the server to text a code.
     * @returns {Promise<boolean>} true while the user should stay in the SMS section (code sent, or a
     *   number is still needed), false when the attempt failed and the caller should go back.
     */
    async function sendSmsCode({ mobile, currentPassword, resend } = {}) {
        const body = {};
        if (mobile) body.mobile = mobile;
        if (currentPassword) body.currentPassword = currentPassword;

        try {
            const { data } = await api('POST', '/api/enrollment/sms/setup', body);
            document.getElementById('smsSentTo').textContent = data.mobileMasked;
            document.getElementById('smsMobileForm').classList.add('hidden');
            document.getElementById('smsForm').classList.remove('hidden');
            startResendCountdown(data.resendAfter);
            if (resend) showToast(`New code sent to ${data.mobileMasked}.`, 'success');
            document.getElementById('smsCode').focus();
            return true;
        } catch (err) {
            if (err.code === 'MOBILE_REQUIRED') {
                // Expected for everyone without a number in the directory: ask for one
                document.getElementById('smsDirectoryHint').style.display = 'none';
                document.getElementById('smsMobileGroup').style.display = '';
                document.getElementById('smsMobileForm').classList.remove('hidden');
                document.getElementById('smsForm').classList.add('hidden');
                document.getElementById('smsMobile').focus();
                return true;
            }
            if (err.code === 'MOBILE_INVALID') {
                setFieldError(document.getElementById('smsMobile'), err.message);
                return true;
            }
            if (err.code === 'SMS_COOLDOWN') {
                startResendCountdown(err.data?.resendAfter || 60);
                showToast(err.message, 'warning');
                return true;
            }
            if (err.code === 'REAUTH_FAILED' || err.code === 'REAUTH_REQUIRED') {
                setFieldError(document.getElementById('smsCurrentPassword'), err.message);
                return false;
            }
            showToast(err.message, 'error');
            return false;
        }
    }

    function startResendCountdown(seconds) {
        const btn = document.getElementById('smsResendBtn');
        let left = Number(seconds) || 0;
        stopResendCountdown();
        const tick = () => {
            if (left <= 0) {
                stopResendCountdown();
                return;
            }
            btn.disabled = true;
            btn.textContent = `Resend code in ${left}s`;
            left -= 1;
        };
        tick();
        smsResendTimer = setInterval(tick, 1000);
    }

    function stopResendCountdown() {
        clearInterval(smsResendTimer);
        smsResendTimer = null;
        const btn = document.getElementById('smsResendBtn');
        btn.disabled = false;
        btn.textContent = 'Resend code';
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
