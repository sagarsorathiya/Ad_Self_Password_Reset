(async function () {
    const user = await loadCurrentUser();
    if (!user) return;
    if (!user.isAdmin) {
        window.location.href = '/dashboard.html';
        return;
    }

    renderNavbar(user, 'admin');
    document.getElementById('content').classList.remove('hidden');

    const usersState = { page: 1, limit: 25, search: '', filter: 'all' };
    const auditState = { page: 1, limit: 50, username: '', action: '', startDate: '', endDate: '' };
    const loadedTabs = new Set();

    // ---- Tabs ----

    document.querySelectorAll('#mainTabs .filter-tab').forEach((tab) => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    function switchTab(name) {
        document.querySelectorAll('#mainTabs .filter-tab').forEach((t) => {
            const active = t.dataset.tab === name;
            t.classList.toggle('active', active);
            t.setAttribute('aria-selected', String(active));
        });
        ['users', 'audit', 'questions', 'exceptions'].forEach((n) => {
            document.getElementById(`tab-${n}`).classList.toggle('hidden', n !== name);
        });
        if (!loadedTabs.has(name)) {
            loadedTabs.add(name);
            if (name === 'audit') loadAudit();
            if (name === 'questions') loadQuestions();
            if (name === 'exceptions') loadExceptions();
        }
    }

    // ---- Stats ----

    async function loadStats() {
        try {
            const { data } = await api('GET', '/api/admin/stats');
            document.getElementById('statTotal').textContent = data.total_users;
            document.getElementById('statEnrolled').textContent = data.enrolled_users;
            document.getElementById('statPending').textContent = data.pending_users;
            document.getElementById('statLocked').textContent = data.locked_users;
        } catch (err) {
            showToast(err.message, 'error');
        }
    }

    // ---- Users ----

    const usersBody = document.getElementById('usersBody');

    document.getElementById('userSearch').addEventListener('input', debounce((e) => {
        usersState.search = e.target.value.trim();
        usersState.page = 1;
        loadUsers();
    }, 350));

    document.querySelectorAll('#userFilters .filter-tab').forEach((btn) => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('#userFilters .filter-tab').forEach((b) => b.classList.remove('active'));
            btn.classList.add('active');
            usersState.filter = btn.dataset.filter;
            usersState.page = 1;
            loadUsers();
        });
    });

    async function loadUsers() {
        setTableMessage(usersBody, 8, 'Loading...');
        try {
            const params = new URLSearchParams({
                page: usersState.page,
                limit: usersState.limit,
                filter: usersState.filter,
            });
            if (usersState.search) params.set('search', usersState.search);

            const { data } = await api('GET', `/api/admin/users?${params}`);
            renderUsers(data.users);
            renderPagination('usersPagination', data.pagination, (page) => {
                usersState.page = page;
                loadUsers();
            });
        } catch (err) {
            setTableMessage(usersBody, 8, err.message);
        }
    }

    function renderUsers(users) {
        if (users.length === 0) {
            setTableMessage(usersBody, 8, 'No users match the current filters.');
            return;
        }
        usersBody.innerHTML = users.map((u) => `
            <tr>
                <td>
                    <div><strong>${escapeHtml(u.display_name || u.username)}</strong></div>
                    <div class="text-muted text-sm">${escapeHtml(u.username)}</div>
                </td>
                <td>${escapeHtml(u.email || '—')}</td>
                <td>${u.locked
                    ? '<span class="badge badge-error">Locked</span>'
                    : u.is_enrolled
                        ? '<span class="badge badge-success">Enrolled</span>'
                        : '<span class="badge badge-warning">Pending</span>'}</td>
                <td>${yesNo(u.security_questions_set)}</td>
                <td>${yesNo(u.totp_enabled)}</td>
                <td>${Number(u.failed_attempts) || 0}</td>
                <td>${escapeHtml(formatDate(u.updated_at))}</td>
                <td>
                    <div class="table-actions">
                        <button class="btn btn-secondary btn-sm" data-action="lock" data-id="${Number(u.id)}"
                                data-locked="${u.locked}" data-name="${escapeHtml(u.username)}">${u.locked ? 'Unlock' : 'Lock'}</button>
                        <button class="btn btn-ghost btn-sm" data-action="reset" data-id="${Number(u.id)}"
                                data-name="${escapeHtml(u.username)}">Reset Enrollment</button>
                    </div>
                </td>
            </tr>`).join('');
    }

    usersBody.addEventListener('click', async (e) => {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;
        const id = btn.dataset.id;
        const name = btn.dataset.name;

        if (btn.dataset.action === 'lock') {
            const lock = btn.dataset.locked !== 'true';
            const ok = await confirmDialog({
                title: lock ? 'Lock user?' : 'Unlock user?',
                message: lock
                    ? `${name} will no longer be able to sign in or reset their password through the portal.`
                    : `${name} will regain access to the portal.`,
                confirmText: lock ? 'Lock' : 'Unlock',
                danger: lock,
            });
            if (!ok) return;
            await runAction(btn, () => api('PUT', `/api/admin/users/${id}/lock`, { locked: lock }));
        } else if (btn.dataset.action === 'reset') {
            const ok = await confirmDialog({
                title: 'Reset enrollment?',
                message: `This removes ${name}'s security answers and authenticator app. They must enroll again before they can use self-service reset.`,
                confirmText: 'Reset Enrollment',
                danger: true,
            });
            if (!ok) return;
            await runAction(btn, () => api('PUT', `/api/admin/users/${id}/reset-enrollment`, {}));
        }
    });

    async function runAction(btn, fn) {
        setButtonLoading(btn, true, '...');
        try {
            const res = await fn();
            showToast(res.message || 'Done.', 'success');
            await Promise.all([loadUsers(), loadStats()]);
        } catch (err) {
            showToast(err.message, 'error');
            setButtonLoading(btn, false);
        }
    }

    // ---- Audit log ----

    const auditBody = document.getElementById('auditBody');
    const auditForm = document.getElementById('auditFilters');

    auditForm.addEventListener('submit', (e) => {
        e.preventDefault();
        auditState.username = document.getElementById('auditUsername').value.trim();
        auditState.action = document.getElementById('auditAction').value;
        auditState.startDate = document.getElementById('auditStart').value;
        auditState.endDate = document.getElementById('auditEnd').value;

        if (auditState.startDate && auditState.endDate && auditState.startDate > auditState.endDate) {
            showToast('Start date must be before end date.', 'warning');
            return;
        }
        auditState.page = 1;
        loadAudit();
    });

    auditForm.addEventListener('reset', () => {
        Object.assign(auditState, { page: 1, username: '', action: '', startDate: '', endDate: '' });
        setTimeout(loadAudit, 0);
    });

    async function loadAudit() {
        setTableMessage(auditBody, 7, 'Loading...');
        try {
            const params = new URLSearchParams({ page: auditState.page, limit: auditState.limit });
            if (auditState.username) params.set('username', auditState.username);
            if (auditState.action) params.set('action', auditState.action);
            if (auditState.startDate) params.set('startDate', new Date(`${auditState.startDate}T00:00:00`).toISOString());
            if (auditState.endDate) params.set('endDate', new Date(`${auditState.endDate}T23:59:59.999`).toISOString());

            const { data } = await api('GET', `/api/admin/audit-log?${params}`);
            renderAudit(data.logs);
            renderPagination('auditPagination', data.pagination, (page) => {
                auditState.page = page;
                loadAudit();
            });
        } catch (err) {
            setTableMessage(auditBody, 7, err.message);
        }
    }

    function renderAudit(logs) {
        if (logs.length === 0) {
            setTableMessage(auditBody, 7, 'No audit events found.');
            return;
        }
        auditBody.innerHTML = logs.map((l) => `
            <tr>
                <td>${escapeHtml(formatDate(l.created_at))}</td>
                <td>${escapeHtml(l.username)}</td>
                <td>${escapeHtml(humanize(l.action))}</td>
                <td>${escapeHtml(l.method ? humanize(l.method) : '—')}</td>
                <td>${l.success
                    ? '<span class="badge badge-success">Success</span>'
                    : '<span class="badge badge-error">Failed</span>'}</td>
                <td>${escapeHtml(l.ip_address || '—')}</td>
                <td style="white-space: normal; max-width: 320px;">${escapeHtml(l.details || '')}</td>
            </tr>`).join('');
    }

    // ---- Security questions ----

    const questionsBody = document.getElementById('questionsBody');
    let questionsCache = [];

    document.getElementById('addQuestionBtn').addEventListener('click', () => openQuestionModal());

    async function loadQuestions() {
        setTableMessage(questionsBody, 4, 'Loading...');
        try {
            const { data } = await api('GET', '/api/admin/questions');
            questionsCache = data;
            renderQuestions();
        } catch (err) {
            setTableMessage(questionsBody, 4, err.message);
        }
    }

    function renderQuestions() {
        if (questionsCache.length === 0) {
            setTableMessage(questionsBody, 4, 'No security questions defined.');
            return;
        }
        questionsBody.innerHTML = questionsCache.map((q) => `
            <tr>
                <td>${Number(q.sort_order) || 0}</td>
                <td style="white-space: normal;">${escapeHtml(q.question_text)}</td>
                <td>${q.is_active
                    ? '<span class="badge badge-success">Active</span>'
                    : '<span class="badge badge-warning">Inactive</span>'}</td>
                <td>
                    <div class="table-actions">
                        <button class="btn btn-secondary btn-sm" data-action="edit" data-id="${Number(q.id)}">Edit</button>
                        <button class="btn btn-ghost btn-sm" data-action="toggle" data-id="${Number(q.id)}">
                            ${q.is_active ? 'Deactivate' : 'Activate'}</button>
                    </div>
                </td>
            </tr>`).join('');
    }

    questionsBody.addEventListener('click', async (e) => {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;
        const question = questionsCache.find((q) => q.id === Number(btn.dataset.id));
        if (!question) return;

        if (btn.dataset.action === 'edit') {
            openQuestionModal(question);
        } else if (btn.dataset.action === 'toggle') {
            setButtonLoading(btn, true, '...');
            try {
                await api('PUT', `/api/admin/questions/${question.id}`, { isActive: !question.is_active });
                showToast(`Question ${question.is_active ? 'deactivated' : 'activated'}.`, 'success');
                await loadQuestions();
            } catch (err) {
                showToast(err.message, 'error');
                setButtonLoading(btn, false);
            }
        }
    });

    function openQuestionModal(question) {
        const isEdit = Boolean(question);
        const body = document.createElement('form');
        body.noValidate = true;
        body.innerHTML = `
            <div class="form-group">
                <label class="form-label" for="qText">Question text</label>
                <textarea class="form-input" id="qText" rows="3" maxlength="500"></textarea>
                <div class="form-error"></div>
            </div>
            <div class="form-group">
                <label class="form-label" for="qOrder">Sort order</label>
                <input class="form-input" type="number" id="qOrder" min="0" max="10000" step="1">
            </div>`;
        const textInput = body.querySelector('#qText');
        const orderInput = body.querySelector('#qOrder');
        textInput.value = question?.question_text || '';
        orderInput.value = question?.sort_order ?? nextSortOrder();

        openModal({
            title: isEdit ? 'Edit Question' : 'Add Question',
            content: body,
            confirmText: isEdit ? 'Save Changes' : 'Add Question',
            onConfirm: async () => {
                setFieldError(textInput, '');
                const questionText = textInput.value.trim();
                const sortOrder = Math.max(0, parseInt(orderInput.value, 10) || 0);
                if (questionText.length < 10) {
                    setFieldError(textInput, 'Question must be at least 10 characters.');
                    return false;
                }
                try {
                    if (isEdit) {
                        await api('PUT', `/api/admin/questions/${question.id}`, { questionText, sortOrder });
                    } else {
                        await api('POST', '/api/admin/questions', { questionText, sortOrder });
                    }
                    showToast(isEdit ? 'Question updated.' : 'Question added.', 'success');
                    await loadQuestions();
                    return true;
                } catch (err) {
                    setFieldError(textInput, err.message);
                    return false;
                }
            },
        });
        textInput.focus();
    }

    function nextSortOrder() {
        return questionsCache.reduce((max, q) => Math.max(max, Number(q.sort_order) || 0), 0) + 1;
    }

    // ---- Password exceptions ----

    const exceptionsBody = document.getElementById('exceptionsBody');
    let exceptionsCache = [];

    document.getElementById('addExceptionBtn').addEventListener('click', () => openExceptionModal());

    async function loadExceptions() {
        setTableMessage(exceptionsBody, 6, 'Loading...');
        try {
            const { data } = await api('GET', '/api/admin/password-exceptions');
            exceptionsCache = data;
            renderExceptions();
        } catch (err) {
            setTableMessage(exceptionsBody, 6, err.message);
        }
    }

    function renderExceptions() {
        if (exceptionsCache.length === 0) {
            setTableMessage(exceptionsBody, 6, 'No password exceptions defined.');
            return;
        }
        exceptionsBody.innerHTML = exceptionsCache.map((x) => `
            <tr>
                <td style="white-space: normal;"><strong>${escapeHtml(x.term)}</strong></td>
                <td>${x.match_type === 'exact' ? 'Exact password' : 'Contains'}</td>
                <td>${x.is_active
                    ? '<span class="badge badge-success">Active</span>'
                    : '<span class="badge badge-warning">Inactive</span>'}</td>
                <td>${escapeHtml(x.created_by || '—')}</td>
                <td>${escapeHtml(formatDate(x.updated_at))}</td>
                <td>
                    <div class="table-actions">
                        <button class="btn btn-secondary btn-sm" data-action="edit" data-id="${Number(x.id)}">Edit</button>
                        <button class="btn btn-ghost btn-sm" data-action="toggle" data-id="${Number(x.id)}">
                            ${x.is_active ? 'Deactivate' : 'Activate'}</button>
                        <button class="btn btn-ghost btn-sm" data-action="delete" data-id="${Number(x.id)}">Remove</button>
                    </div>
                </td>
            </tr>`).join('');
    }

    exceptionsBody.addEventListener('click', async (e) => {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;
        const item = exceptionsCache.find((x) => x.id === Number(btn.dataset.id));
        if (!item) return;

        if (btn.dataset.action === 'edit') {
            openExceptionModal(item);
            return;
        }
        if (btn.dataset.action === 'delete') {
            const ok = await confirmDialog({
                title: 'Remove password exception?',
                message: `"${item.term}" will be allowed in new passwords again.`,
                confirmText: 'Remove',
                danger: true,
            });
            if (!ok) return;
        }

        setButtonLoading(btn, true, '...');
        try {
            const res = btn.dataset.action === 'delete'
                ? await api('DELETE', `/api/admin/password-exceptions/${item.id}`)
                : await api('PUT', `/api/admin/password-exceptions/${item.id}`, { isActive: !item.is_active });
            showToast(res.message || 'Done.', 'success');
            await loadExceptions();
        } catch (err) {
            showToast(err.message, 'error');
            setButtonLoading(btn, false);
        }
    });

    function openExceptionModal(item) {
        const isEdit = Boolean(item);
        const body = document.createElement('form');
        body.noValidate = true;
        body.innerHTML = `
            <div class="form-group">
                <label class="form-label" for="xTerm">Word or phrase</label>
                <input class="form-input" type="text" id="xTerm" maxlength="128" autocomplete="off">
                <div class="form-error"></div>
            </div>
            <div class="form-group">
                <label class="form-label" for="xMatch">Match</label>
                <select class="form-select" id="xMatch">
                    <option value="contains">Password must not contain it</option>
                    <option value="exact">Password must not be exactly it</option>
                </select>
            </div>`;
        const termInput = body.querySelector('#xTerm');
        const matchInput = body.querySelector('#xMatch');
        termInput.value = item?.term || '';
        matchInput.value = item?.match_type || 'contains';

        openModal({
            title: isEdit ? 'Edit Password Exception' : 'Add Password Exception',
            content: body,
            confirmText: isEdit ? 'Save Changes' : 'Add Exception',
            onConfirm: async () => {
                setFieldError(termInput, '');
                const term = termInput.value.trim();
                const matchType = matchInput.value;
                if (term.length < 3) {
                    setFieldError(termInput, 'Enter at least 3 characters.');
                    return false;
                }
                try {
                    if (isEdit) {
                        await api('PUT', `/api/admin/password-exceptions/${item.id}`, { term, matchType });
                    } else {
                        await api('POST', '/api/admin/password-exceptions', { term, matchType });
                    }
                    showToast(isEdit ? 'Password exception updated.' : 'Password exception added.', 'success');
                    await loadExceptions();
                    return true;
                } catch (err) {
                    setFieldError(termInput, err.message);
                    return false;
                }
            },
        });
        termInput.focus();
    }

    // ---- Modal helpers ----

    // onConfirm returns true to close, false to keep the modal open.
    function openModal({ title, content, confirmText = 'Confirm', danger = false, onConfirm, onCancel }) {
        const backdrop = document.createElement('div');
        backdrop.className = 'modal-backdrop';
        backdrop.innerHTML = `
            <div class="modal" role="dialog" aria-modal="true">
                <h2 class="modal-title"></h2>
                <div class="modal-body"></div>
                <div class="btn-row">
                    <button type="button" class="btn btn-secondary" data-role="cancel">Cancel</button>
                    <button type="button" class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-role="confirm"></button>
                </div>
            </div>`;
        backdrop.querySelector('.modal-title').textContent = title;
        backdrop.querySelector('[data-role="confirm"]').textContent = confirmText;
        const bodyEl = backdrop.querySelector('.modal-body');
        if (typeof content === 'string') bodyEl.textContent = content;
        else bodyEl.appendChild(content);

        const confirmBtn = backdrop.querySelector('[data-role="confirm"]');
        const close = () => {
            backdrop.remove();
            document.removeEventListener('keydown', onKey);
        };
        const cancel = () => {
            close();
            onCancel?.();
        };
        const confirm = async () => {
            setButtonLoading(confirmBtn, true, 'Working...');
            const shouldClose = await onConfirm();
            if (shouldClose !== false) close();
            else setButtonLoading(confirmBtn, false);
        };
        const onKey = (e) => { if (e.key === 'Escape') cancel(); };

        backdrop.querySelector('[data-role="cancel"]').addEventListener('click', cancel);
        backdrop.addEventListener('click', (e) => { if (e.target === backdrop) cancel(); });
        confirmBtn.addEventListener('click', confirm);
        if (content instanceof HTMLFormElement) {
            content.addEventListener('submit', (e) => { e.preventDefault(); confirm(); });
        }
        document.addEventListener('keydown', onKey);
        document.body.appendChild(backdrop);
        if (typeof content === 'string') confirmBtn.focus();
    }

    function confirmDialog({ title, message, confirmText, danger }) {
        return new Promise((resolve) => {
            openModal({
                title,
                content: message,
                confirmText,
                danger,
                onConfirm: () => { resolve(true); return true; },
                onCancel: () => resolve(false),
            });
        });
    }

    // ---- Shared rendering ----

    function renderPagination(containerId, { page, totalPages, totalCount }, onChange) {
        const container = document.getElementById(containerId);
        container.innerHTML = '';
        if (totalCount === 0) return;

        const makeBtn = (label, target, { disabled = false, active = false } = {}) => {
            const b = document.createElement('button');
            b.type = 'button';
            b.className = `pagination-btn${active ? ' active' : ''}`;
            b.textContent = label;
            b.disabled = disabled;
            if (!disabled && !active) b.addEventListener('click', () => onChange(target));
            return b;
        };

        container.appendChild(makeBtn('‹ Prev', page - 1, { disabled: page <= 1 }));
        const start = Math.max(1, page - 2);
        const end = Math.min(totalPages, start + 4);
        for (let p = start; p <= end; p++) {
            container.appendChild(makeBtn(String(p), p, { active: p === page }));
        }
        container.appendChild(makeBtn('Next ›', page + 1, { disabled: page >= totalPages }));

        const info = document.createElement('span');
        info.className = 'pagination-info';
        info.textContent = `${totalCount} total`;
        container.appendChild(info);
    }

    function setTableMessage(tbody, colspan, message) {
        tbody.innerHTML = '';
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = colspan;
        td.className = 'text-center text-muted';
        td.style.padding = '2rem';
        td.textContent = message;
        tr.appendChild(td);
        tbody.appendChild(tr);
    }

    function yesNo(value) {
        return value
            ? '<span class="badge badge-success">Yes</span>'
            : '<span class="badge badge-warning">No</span>';
    }

    function humanize(value) {
        return String(value).replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
    }

    // ---- Initial load ----

    loadedTabs.add('users');
    await Promise.all([loadStats(), loadUsers()]);
})();
