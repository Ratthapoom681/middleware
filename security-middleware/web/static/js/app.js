// ── State ──────────────────────────────────────────────────────
let config = {};
const chipData = {};   // field -> string[]
const defectDojoScopeData = {
    products: [],
    engagements: [],
    tests: [],
};

// ── Navigation ─────────────────────────────────────────────────
const sectionTitles = {
    wazuh:      'Wazuh SIEM',
    defectdojo: 'DefectDojo',
    redmine:    'Redmine',
    filter:     'Filter Rules',
    dedup:      'Deduplication',
    enrichment: 'Enrichment',
    live:       'Live Events Queue',
    logging:    'Logging',
    preview:    'YAML Preview',
};

document.querySelectorAll('.nav-item[data-section]').forEach(item => {
    item.addEventListener('click', () => {
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        item.classList.add('active');
        const section = item.dataset.section;
        document.querySelectorAll('.section-page').forEach(p => p.classList.remove('active'));
        document.getElementById('page-' + section).classList.add('active');
        document.getElementById('section-title').textContent = sectionTitles[section] || section;
        if (section === 'preview') updateYamlPreview();
    });
});

// ── Chip (tag) Input ───────────────────────────────────────────
document.querySelectorAll('.chip-container').forEach(container => {
    const field = container.dataset.field;
    chipData[field] = [];

    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'chip-input';
    input.placeholder = 'Type and press Enter...';
    container.appendChild(input);

    container.addEventListener('click', () => input.focus());

    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && input.value.trim()) {
            e.preventDefault();
            addChip(container, field, input.value.trim());
            input.value = '';
        }
        if (e.key === 'Backspace' && !input.value && chipData[field].length) {
            removeChipByIndex(container, field, chipData[field].length - 1);
        }
    });
});

function addChip(container, field, value) {
    if (chipData[field].includes(value)) return;
    chipData[field].push(value);
    renderChips(container, field);
    if (field === 'defectdojo-severity_filter') resetDefectDojoFindingCountPreview();
}

function removeChipByIndex(container, field, index) {
    chipData[field].splice(index, 1);
    renderChips(container, field);
    if (field === 'defectdojo-severity_filter') resetDefectDojoFindingCountPreview();
}

function renderChips(container, field) {
    const input = container.querySelector('.chip-input');
    container.querySelectorAll('.chip').forEach(c => c.remove());
    chipData[field].forEach((val, i) => {
        const chip = document.createElement('span');
        chip.className = 'chip';
        chip.innerHTML = `${escapeHtml(val)} <span class="chip-remove" data-index="${i}">&times;</span>`;
        chip.querySelector('.chip-remove').addEventListener('click', () => {
            removeChipByIndex(container, field, i);
        });
        container.insertBefore(chip, input);
    });
}

function setChips(field, values) {
    chipData[field] = values || [];
    const container = document.querySelector(`[data-field="${field}"]`);
    if (container) renderChips(container, field);
}

function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}

function encodeAttrValue(str) {
    return encodeURIComponent(str || '');
}

function decodeAttrValue(str) {
    try {
        return decodeURIComponent(str || '');
    } catch (e) {
        return str || '';
    }
}

// ── Load Config ────────────────────────────────────────────────
async function loadConfig() {
    try {
        const res = await fetch('/api/config');
        const data = await res.json();
        if (data.status !== 'ok') throw new Error(data.message);
        config = data.config;
        populateForm(config);
        toast('Configuration loaded', 'success');
    } catch (e) {
        toast('Failed to load config: ' + e.message, 'error');
    }
}

function populateForm(c) {
    // Wazuh
    setVal('wazuh-base_url', c.wazuh?.base_url);
    setVal('wazuh-username', c.wazuh?.username);
    setVal('wazuh-password', c.wazuh?.password);
    setVal('wazuh-indexer_url', c.wazuh?.indexer_url);
    setVal('wazuh-indexer_username', c.wazuh?.indexer_username);
    setVal('wazuh-indexer_password', c.wazuh?.indexer_password);
    setVal('wazuh-min_level', c.wazuh?.min_level);
    setVal('wazuh-alerts_json_path', c.wazuh?.alerts_json_path);
    setChecked('wazuh-verify_ssl', c.wazuh?.verify_ssl);

    // DefectDojo
    setChecked('defectdojo-enabled', c.defectdojo?.enabled);
    setVal('defectdojo-base_url', c.defectdojo?.base_url);
    setVal('defectdojo-api_key', c.defectdojo?.api_key);
    setChecked('defectdojo-verify_ssl', c.defectdojo?.verify_ssl);
    setChips('defectdojo-severity_filter', c.defectdojo?.severity_filter);
    setChecked('defectdojo-active', c.defectdojo?.active);
    setChecked('defectdojo-verified', c.defectdojo?.verified);
    setVal('defectdojo-updated_since_minutes', c.defectdojo?.updated_since_minutes);
    setVal('defectdojo-fetch_limit', c.defectdojo?.fetch_limit);
    setMultiSelectValues('defectdojo-product_ids', c.defectdojo?.product_ids || [], value => `${value} (saved)`);
    setMultiSelectValues('defectdojo-engagement_ids', c.defectdojo?.engagement_ids || [], value => `${value} (saved)`);
    setMultiSelectValues('defectdojo-test_ids', c.defectdojo?.test_ids || [], value => `${value} (saved)`);
    updateDefectDojoScopeFilters();
    renderDefectDojoWarnings();
    resetDefectDojoFindingCountPreview();

    // Redmine
    setVal('redmine-base_url', c.redmine?.base_url);
    setVal('redmine-api_key', c.redmine?.api_key);
    setVal('redmine-project_id', c.redmine?.project_id);
    setVal('redmine-tracker_id', c.redmine?.tracker_id);
    setChecked('redmine-enable_parent_issues', c.redmine?.enable_parent_issues);
    setVal('redmine-parent_tracker_id', c.redmine?.parent_tracker_id);
    setVal('redmine-dedup_custom_field_id', c.redmine?.dedup_custom_field_id);
    const pm = c.redmine?.priority_map || {};
    setVal('priority-critical', pm.critical);
    setVal('priority-high', pm.high);
    setVal('priority-medium', pm.medium);
    setVal('priority-low', pm.low);
    setVal('priority-info', pm.info);
    
    // Redmine Routing Rules
    if (c.redmine?.routing_rules) {
        localRoutingRules = JSON.parse(JSON.stringify(c.redmine.routing_rules)); // Deep copy
        if (typeof renderRoutingRules === 'function') renderRoutingRules();
    }

    // Pipeline - Filter
    setVal('filter-min_severity', c.pipeline?.filter?.min_severity);
    setChips('filter-exclude_rule_ids', c.pipeline?.filter?.exclude_rule_ids);
    setChips('filter-include_hosts', c.pipeline?.filter?.include_hosts);
    setChips('filter-exclude_title_patterns', c.pipeline?.filter?.exclude_title_patterns);

    // Dedup
    setChecked('dedup-enabled', c.pipeline?.dedup?.enabled);
    setVal('dedup-db_path', c.pipeline?.dedup?.db_path);
    setVal('dedup-ttl_hours', c.pipeline?.dedup?.ttl_hours);

    // Enrichment
    setChecked('enrichment-asset_inventory_enabled', c.pipeline?.enrichment?.asset_inventory_enabled);
    setChecked('enrichment-add_remediation_links', c.pipeline?.enrichment?.add_remediation_links);
    setVal('enrichment-asset_inventory_path', c.pipeline?.enrichment?.asset_inventory_path);

    // Logging
    setVal('logging-level', c.logging?.level);
    setVal('logging-format', c.logging?.format);
    setVal('pipeline-poll_interval', c.pipeline?.poll_interval);
    setVal('pipeline-initial_lookback_minutes', c.pipeline?.initial_lookback_minutes);
}

function setVal(id, value) {
    const el = document.getElementById(id);
    if (el && value !== undefined && value !== null) el.value = value;
}

function setChecked(id, value) {
    const el = document.getElementById(id);
    if (el) el.checked = !!value;
}

// ── Collect Form → Config Object ───────────────────────────────
function collectForm() {
    return {
        wazuh: {
            base_url:         getVal('wazuh-base_url'),
            username:         getVal('wazuh-username'),
            password:         getVal('wazuh-password'),
            indexer_url:      getVal('wazuh-indexer_url'),
            indexer_username: getVal('wazuh-indexer_username'),
            indexer_password: getVal('wazuh-indexer_password'),
            alerts_json_path: getVal('wazuh-alerts_json_path'),
            verify_ssl:       getChecked('wazuh-verify_ssl'),
            min_level:        getInt('wazuh-min_level', 7),
        },
        defectdojo: {
            enabled:               getChecked('defectdojo-enabled'),
            base_url:              getVal('defectdojo-base_url'),
            api_key:               getVal('defectdojo-api_key'),
            verify_ssl:            getChecked('defectdojo-verify_ssl'),
            severity_filter:       chipData['defectdojo-severity_filter'] || [],
            product_ids:           getMultiSelectValues('defectdojo-product_ids'),
            engagement_ids:        getMultiSelectValues('defectdojo-engagement_ids'),
            test_ids:              getMultiSelectValues('defectdojo-test_ids'),
            active:                getChecked('defectdojo-active'),
            verified:              getChecked('defectdojo-verified'),
            updated_since_minutes: getInt('defectdojo-updated_since_minutes', 0),
            fetch_limit:           getInt('defectdojo-fetch_limit', 1000),
        },
        redmine: {
            base_url:              getVal('redmine-base_url'),
            api_key:               getVal('redmine-api_key'),
            project_id:            getVal('redmine-project_id'),
            tracker_id:            getInt('redmine-tracker_id', 1),
            enable_parent_issues:  getChecked('redmine-enable_parent_issues'),
            parent_tracker_id:     getIntOrNull('redmine-parent_tracker_id'),
            dedup_custom_field_id: getIntOrNull('redmine-dedup_custom_field_id'),
            priority_map: {
                critical: getInt('priority-critical', 5),
                high:     getInt('priority-high', 4),
                medium:   getInt('priority-medium', 3),
                low:      getInt('priority-low', 2),
                info:     getInt('priority-info', 1),
            },
            routing_rules: JSON.parse(JSON.stringify(localRoutingRules)) // Deep copy safety
        },
        pipeline: {
            poll_interval: getInt('pipeline-poll_interval', 300),
            initial_lookback_minutes: getInt('pipeline-initial_lookback_minutes', 1440),
            filter: {
                min_severity:           getVal('filter-min_severity'),
                exclude_rule_ids:       chipData['filter-exclude_rule_ids'] || [],
                include_hosts:          chipData['filter-include_hosts'] || [],
                exclude_title_patterns: chipData['filter-exclude_title_patterns'] || [],
            },
            dedup: {
                enabled:   getChecked('dedup-enabled'),
                db_path:   getVal('dedup-db_path'),
                ttl_hours: getInt('dedup-ttl_hours', 168),
            },
            enrichment: {
                asset_inventory_enabled: getChecked('enrichment-asset_inventory_enabled'),
                asset_inventory_path:    getVal('enrichment-asset_inventory_path'),
                add_remediation_links:   getChecked('enrichment-add_remediation_links'),
            },
        },
        logging: {
            level:  getVal('logging-level'),
            format: getVal('logging-format'),
        },
    };
}

function getVal(id)  { return document.getElementById(id)?.value || ''; }
function getChecked(id) { return document.getElementById(id)?.checked || false; }
function getInt(id, def) { const v = parseInt(document.getElementById(id)?.value); return isNaN(v) ? def : v; }
function getIntOrNull(id) { const v = parseInt(document.getElementById(id)?.value); return isNaN(v) ? null : v; }
function getMultiSelectValues(id) {
    const el = document.getElementById(id);
    if (!el) return [];
    return Array.from(el.selectedOptions)
        .map(opt => parseInt(opt.value, 10))
        .filter(value => !Number.isNaN(value));
}

function setMultiSelectValues(id, values, fallbackLabelBuilder) {
    const el = document.getElementById(id);
    if (!el) return;

    const normalizedValues = (values || [])
        .map(value => parseInt(value, 10))
        .filter(value => !Number.isNaN(value));

    normalizedValues.forEach(value => {
        const existing = Array.from(el.options).find(opt => parseInt(opt.value, 10) === value);
        if (!existing) {
            const option = document.createElement('option');
            option.value = String(value);
            option.textContent = fallbackLabelBuilder ? fallbackLabelBuilder(value) : String(value);
            el.appendChild(option);
        }
    });

    Array.from(el.options).forEach(opt => {
        opt.selected = normalizedValues.includes(parseInt(opt.value, 10));
    });
}

function renderMultiSelectOptions(id, items, selectedValues, labelBuilder, preserveMissing = true) {
    const el = document.getElementById(id);
    if (!el) return;

    const normalizedSelected = (selectedValues || [])
        .map(value => parseInt(value, 10))
        .filter(value => !Number.isNaN(value));

    el.innerHTML = '';

    items.forEach(item => {
        const option = document.createElement('option');
        option.value = String(item.id);
        option.textContent = labelBuilder(item);
        option.selected = normalizedSelected.includes(parseInt(item.id, 10));
        if (item.product_id !== undefined && item.product_id !== null) {
            option.dataset.productId = String(item.product_id);
        }
        if (item.engagement_id !== undefined && item.engagement_id !== null) {
            option.dataset.engagementId = String(item.engagement_id);
        }
        el.appendChild(option);
    });

    if (preserveMissing) {
        normalizedSelected.forEach(value => {
            const existing = Array.from(el.options).find(opt => parseInt(opt.value, 10) === value);
            if (!existing) {
                const option = document.createElement('option');
                option.value = String(value);
                option.textContent = `${value} (saved)`;
                option.selected = true;
                el.appendChild(option);
            }
        });
    }
}

// ── Save Config ────────────────────────────────────────────────
async function saveConfig() {
    const data = collectForm();
    try {
        const res = await fetch('/api/config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data),
        });
        const result = await res.json();
        if (result.status === 'ok') {
            toast('Configuration saved successfully', 'success');
        } else {
            toast('Save failed: ' + result.message, 'error');
        }
    } catch (e) {
        toast('Save failed: ' + e.message, 'error');
    }
}

// ── Test Connection ────────────────────────────────────────────
async function testConnection(service) {
    const statusEl = document.getElementById('status-' + service);
    const badgeEl  = document.getElementById('conn-badge-' + service);

    if (statusEl) { statusEl.className = 'nav-status testing'; }
    if (badgeEl)  { badgeEl.innerHTML = '<span class="conn-status pending">Testing...</span>'; }

    const data = collectForm();
    try {
        const res = await fetch('/api/config/test/' + service, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data),
        });
        const result = await res.json();

        if (result.connected) {
            if (statusEl) statusEl.className = 'nav-status connected';
            if (badgeEl)  badgeEl.innerHTML = '<span class="conn-status ok">&#10003; Connected</span>';
            toast(service + ' connection successful', 'success');
        } else {
            if (statusEl) statusEl.className = 'nav-status error';
            if (badgeEl)  badgeEl.innerHTML = '<span class="conn-status fail">&#10007; Failed</span>';
            toast(service + ': ' + result.message, 'error');
        }
    } catch (e) {
        if (statusEl) statusEl.className = 'nav-status error';
        if (badgeEl)  badgeEl.innerHTML = '<span class="conn-status fail">&#10007; Error</span>';
        toast('Connection test failed: ' + e.message, 'error');
    }
}

async function syncDefectDojoScopeData() {
    const status = document.getElementById('defectdojo-scope-status');
    if (status) {
        status.style.display = 'inline-flex';
        status.className = 'conn-status pending';
        status.textContent = 'Syncing...';
    }

    try {
        const payload = collectForm();
        const res = await fetch('/api/defectdojo/scope-data', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (data.status !== 'ok') throw new Error(data.message || 'Failed to fetch scope data');

        defectDojoScopeData.products = data.products || [];
        defectDojoScopeData.engagements = data.engagements || [];
        defectDojoScopeData.tests = data.tests || [];
        renderDefectDojoScopeOptions();
        renderDefectDojoWarnings();

        if (status) {
            status.className = 'conn-status ok';
            status.textContent = `${defectDojoScopeData.products.length} Products`;
            setTimeout(() => { status.style.display = 'none'; }, 5000);
        }
        toast('DefectDojo scope data synced', 'success');
    } catch (e) {
        if (status) {
            status.className = 'conn-status fail';
            status.textContent = 'Sync Failed';
        }
        toast('Failed to sync DefectDojo scope data: ' + e.message, 'error');
    }
}

function resetDefectDojoFindingCountPreview() {
    const status = document.getElementById('defectdojo-finding-count-status');
    const summary = document.getElementById('defectdojo-finding-count-summary');

    if (status) {
        status.style.display = 'none';
        status.className = 'conn-status';
        status.textContent = '';
    }
    if (summary) {
        summary.style.display = 'none';
        summary.textContent = '';
        summary.style.color = '';
    }
}

function formatDefectDojoFindingCountSummary(data) {
    const matchingCount = Number.isFinite(data?.matching_count) ? data.matching_count : 0;
    const pendingCount = Number.isFinite(data?.pending_count) ? data.pending_count : matchingCount;
    const processingCap = Number.isFinite(data?.processing_cap) ? data.processing_cap : null;

    if (data?.checkpoint_applied && processingCap !== null && pendingCount > processingCap) {
        return `${matchingCount} findings match the current filters. ${pendingCount} are pending after the saved checkpoint, and the next sync will process up to ${processingCap}.`;
    }
    if (data?.checkpoint_applied) {
        return `${matchingCount} findings match the current filters. ${pendingCount} are pending after the saved checkpoint.`;
    }
    if (processingCap !== null && matchingCount > processingCap) {
        return `${matchingCount} findings match the current filters. The next sync will process up to ${processingCap} because Fetch Limit is set.`;
    }
    return `${matchingCount} findings match the current filters.`;
}

async function previewDefectDojoFindingCount() {
    const status = document.getElementById('defectdojo-finding-count-status');
    const summary = document.getElementById('defectdojo-finding-count-summary');

    if (status) {
        status.style.display = 'inline-flex';
        status.className = 'conn-status pending';
        status.textContent = 'Counting...';
    }
    if (summary) {
        summary.style.display = 'none';
        summary.textContent = '';
        summary.style.color = '';
    }

    try {
        const payload = collectForm();
        const res = await fetch('/api/defectdojo/finding-count', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (data.status !== 'ok') throw new Error(data.message || 'Failed to count findings');

        if (status) {
            status.className = 'conn-status ok';
            status.textContent = `${data.matching_count} Findings`;
        }
        if (summary) {
            summary.textContent = formatDefectDojoFindingCountSummary(data);
            summary.style.display = 'block';
        }
        toast(`DefectDojo count preview: ${data.matching_count} findings match current filters`, 'success');
    } catch (e) {
        if (status) {
            status.className = 'conn-status fail';
            status.textContent = 'Count Failed';
        }
        if (summary) {
            summary.textContent = e.message;
            summary.style.display = 'block';
            summary.style.color = 'var(--red)';
        }
        toast('Failed to count DefectDojo findings: ' + e.message, 'error');
    }
}

function renderDefectDojoScopeOptions() {
    const selectedProducts = getMultiSelectValues('defectdojo-product_ids');
    const selectedEngagements = getMultiSelectValues('defectdojo-engagement_ids');
    const selectedTests = getMultiSelectValues('defectdojo-test_ids');

    renderMultiSelectOptions(
        'defectdojo-product_ids',
        defectDojoScopeData.products,
        selectedProducts,
        item => `${item.id}: ${item.name}`
    );

    renderMultiSelectOptions(
        'defectdojo-engagement_ids',
        defectDojoScopeData.engagements,
        selectedEngagements,
        item => `${item.id}: ${item.name}`
    );

    renderMultiSelectOptions(
        'defectdojo-test_ids',
        defectDojoScopeData.tests,
        selectedTests,
        item => `${item.id}: ${item.name}`
    );

    updateDefectDojoScopeFilters();
}

function updateDefectDojoScopeFilters() {
    if (
        defectDojoScopeData.products.length === 0 &&
        defectDojoScopeData.engagements.length === 0 &&
        defectDojoScopeData.tests.length === 0
    ) {
        renderDefectDojoWarnings();
        return;
    }

    const selectedProductIds = new Set(getMultiSelectValues('defectdojo-product_ids'));
    const previousEngagementIds = getMultiSelectValues('defectdojo-engagement_ids');
    const previousTestIds = getMultiSelectValues('defectdojo-test_ids');

    const filteredEngagements = defectDojoScopeData.engagements.filter(item => {
        if (selectedProductIds.size === 0) return true;
        return item.product_id !== null && selectedProductIds.has(parseInt(item.product_id, 10));
    });

    renderMultiSelectOptions(
        'defectdojo-engagement_ids',
        filteredEngagements,
        previousEngagementIds,
        item => `${item.id}: ${item.name}`,
        false
    );

    const effectiveEngagementIds = new Set(getMultiSelectValues('defectdojo-engagement_ids'));
    const filteredTests = defectDojoScopeData.tests.filter(item => {
        if (effectiveEngagementIds.size > 0) {
            return item.engagement_id !== null && effectiveEngagementIds.has(parseInt(item.engagement_id, 10));
        }
        if (selectedProductIds.size > 0) {
            return item.product_id !== null && selectedProductIds.has(parseInt(item.product_id, 10));
        }
        return true;
    });

    renderMultiSelectOptions(
        'defectdojo-test_ids',
        filteredTests,
        previousTestIds,
        item => `${item.id}: ${item.name}`,
        false
    );

    renderDefectDojoWarnings();
}

function renderDefectDojoWarnings() {
    const warningsEl = document.getElementById('defectdojo-scope-warnings');
    if (!warningsEl) return;

    const warnings = [];
    const hasScopeFilters =
        getMultiSelectValues('defectdojo-product_ids').length > 0 ||
        getMultiSelectValues('defectdojo-engagement_ids').length > 0 ||
        getMultiSelectValues('defectdojo-test_ids').length > 0;
    const updatedSince = getInt('defectdojo-updated_since_minutes', 0);
    const fetchLimit = getInt('defectdojo-fetch_limit', 1000);
    const cursorPath = config?.defectdojo?.cursor_path || 'data/defectdojo_cursor.json';

    if (!hasScopeFilters && updatedSince === 0) {
        warnings.push('Dangerous DefectDojo scope: no Product/Engagement/Test filters are selected and Updated Since is 0.');
    }
    if (fetchLimit > 0 && !cursorPath) {
        warnings.push('Fetch Limit is set without checkpoint-backed incremental sync; repeated runs can skip or replay findings.');
    }

    if (warnings.length === 0) {
        warningsEl.innerHTML = '';
        return;
    }

    warningsEl.innerHTML = warnings.map(message =>
        `<div class="toast toast-warning" style="position:static; margin-bottom:5px; opacity:1;"><span>&#9888;</span> ${escapeHtml(message)}</div>`
    ).join('');
}

// ── YAML Editor ───────────────────────────────────────────────
async function loadRawYaml() {
    try {
        const res = await fetch('/api/config/raw');
        const data = await res.json();
        if (data.status === 'ok') {
            document.getElementById('yaml-output').value = data.content;
            toast('Loaded raw YAML from file', 'success');
        } else throw new Error(data.message);
    } catch (e) {
        toast('Failed to load raw YAML: ' + e.message, 'error');
    }
}

async function saveRawYaml() {
    const yamlContent = document.getElementById('yaml-output').value;
    try {
        const res = await fetch('/api/config/raw', {
            method: 'POST',
            headers: {'Content-Type': 'text/plain'},
            body: yamlContent
        });
        const result = await res.json();
        if (result.status === 'ok') {
            toast('Raw YAML saved successfully', 'success');
            // Refresh form view
            loadConfig();
        } else {
            toast('Save failed: ' + result.message, 'error');
        }
    } catch (e) {
        toast('Save failed: ' + e.message, 'error');
    }
}

function updateYamlPreview() {
    // When activating the tab, load the contents from file so it's fresh
    loadRawYaml();
}

// ── Toasts ─────────────────────────────────────────────────────
function toast(message, type) {
    type = type || 'info';
    const container = document.getElementById('toasts');
    const el = document.createElement('div');
    const icons = { success: '&#10003;', error: '&#10007;', warning: '&#9888;', info: '&#8505;' };
    el.className = 'toast toast-' + type;
    el.innerHTML = '<span>' + (icons[type] || '') + '</span> ' + escapeHtml(message);
    container.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; setTimeout(() => el.remove(), 300); }, 4000);
}

// ── Redmine Tracker Routing Logic ──────────────────────────────
let globalTrackers = [];
let localRoutingRules = [];

async function syncRedmineTrackers() {
    const status = document.getElementById("tracker-sync-status");
    status.style.display = "inline-flex";
    status.className = "conn-status pending";
    status.textContent = "Syncing...";

    try {
        const payload = collectForm();
        const res = await fetch("/api/redmine/trackers", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        
        if (data.status === 'ok') {
            globalTrackers = data.trackers || [];
            renderTrackerDropdowns();
            renderRoutingRules();
            status.className = "conn-status ok";
            status.textContent = `${globalTrackers.length} Trackers Synced`;
            
            // clear success msg after 5s
            setTimeout(() => status.style.display = 'none', 5000);
        } else {
            status.className = "conn-status fail";
            status.textContent = "Sync Failed";
            toast("Failed to sync trackers: " + data.message, "error");
        }
    } catch(e) {
        status.className = "conn-status fail";
        status.textContent = "Network Error";
        toast("Network error syncing trackers", "error");
    }
}

function buildTrackerSelectHTML(currentVal, elementClass="routing-tracker-select") {
    // Falls back to numeric inputs if fetch hasn't run or is empty
    if (globalTrackers.length === 0) {
        return `<input type="number" class="${elementClass}" value="${currentVal !== null ? currentVal : ''}" min="1" placeholder="ID">`;
    }
    
    let options = globalTrackers.map(t => `<option value="${t.id}" ${t.id == currentVal ? 'selected' : ''}>${t.id}: ${escapeHtml(t.name)}</option>`).join("");
    if (!currentVal || !globalTrackers.find(t => t.id == currentVal)) {
        options = `<option value="" disabled ${!currentVal ? 'selected' : ''}>-- Select Tracker --</option>` + options;
        if (currentVal && parseInt(currentVal)) {
            options = `<option value="${currentVal}" selected>${currentVal} (Unsynced)</option>` + options;
        }
    }
    return `<select class="${elementClass}">${options}</select>`;
}

function renderTrackerDropdowns() {
    // Core default trackers fallback update
    const tIdEl = document.getElementById("redmine-tracker_id");
    const ptIdEl = document.getElementById("redmine-parent_tracker_id");
    
    if (tIdEl && tIdEl.tagName === "INPUT" && globalTrackers.length > 0) {
        const tVal = tIdEl.value;
        tIdEl.outerHTML = buildTrackerSelectHTML(tVal, "").replace('class=""', 'id="redmine-tracker_id"');
    } else if (tIdEl && tIdEl.tagName === "SELECT") {
        const tVal = tIdEl.value;
        tIdEl.outerHTML = buildTrackerSelectHTML(tVal, "").replace('class=""', 'id="redmine-tracker_id"');
    }
    
    if (ptIdEl && ptIdEl.tagName === "INPUT" && globalTrackers.length > 0) {
        const ptVal = ptIdEl.value;
        ptIdEl.outerHTML = buildTrackerSelectHTML(ptVal, "").replace('class=""', 'id="redmine-parent_tracker_id"');
    } else if (ptIdEl && ptIdEl.tagName === "SELECT") {
        const ptVal = ptIdEl.value;
        ptIdEl.outerHTML = buildTrackerSelectHTML(ptVal, "").replace('class=""', 'id="redmine-parent_tracker_id"');
    }
}

function addRoutingRuleFromForm() {
    const source = document.getElementById("new-rule-source").value;
    const match_type = document.getElementById("new-rule-match").value;
    const match_value = document.getElementById("new-rule-value").value.trim();
    const t_id_val = document.getElementById("new-rule-tracker").value;
    const tracker_id = t_id_val ? parseInt(t_id_val) : null;
    
    localRoutingRules.push({
        enabled: true, source: source, match_type: match_type, match_value: match_value,
        tracker_id: tracker_id, use_parent: false, parent_tracker_id: null
    });
    
    document.getElementById("new-rule-value").value = "";
    document.getElementById("new-rule-tracker").value = "";
    renderRoutingRules();
}

function deleteRoutingRule(index) {
    localRoutingRules.splice(index, 1);
    renderRoutingRules();
}

function bindRoutingRuleInputs() {
    // Ensures inputs get updated locally
    const tbody = document.getElementById("routing-rules-body");
    Array.from(tbody.rows).forEach((row, idx) => {
        const rule = localRoutingRules[idx];
        const src = row.querySelector('.r-source');
        if(src) src.onchange = (e) => rule.source = e.target.value;
        const mt = row.querySelector('.r-matchtype');
        if(mt) mt.onchange = (e) => rule.match_type = e.target.value;
        const mv = row.querySelector('.r-matchval');
        if(mv) mv.onkeyup = (e) => rule.match_value = e.target.value;
        
        const t = row.querySelector('.routing-tracker-select');
        if(t) t.onchange = (e) => rule.tracker_id = parseInt(e.target.value) || null;
        
        const up = row.querySelector('.r-useparent');
        if(up) up.onchange = (e) => rule.use_parent = e.target.checked;
        
        const pts = row.querySelectorAll('.routing-tracker-select');
        if(pts.length > 1) pts[1].onchange = (e) => rule.parent_tracker_id = parseInt(e.target.value) || null;
        
        const en = row.querySelector('.r-enabled');
        if(en) en.onchange = (e) => rule.enabled = e.target.checked;
    });
}

function renderRoutingRules() {
    const tbody = document.getElementById("routing-rules-body");
    if (!tbody) return;
    
    if (localRoutingRules.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted);">No rules established. Fallback configuration will be utilized.</td></tr>';
        return;
    }

    tbody.innerHTML = localRoutingRules.map((r, i) => `
        <tr>
            <td>
                <select class="r-source" style="padding:4px; max-width:80px; font-size:11px;">
                    <option value="any" ${r.source==='any'?'selected':''}>Any</option>
                    <option value="wazuh" ${r.source==='wazuh'?'selected':''}>Wazuh</option>
                    <option value="defectdojo" ${r.source==='defectdojo'?'selected':''}>DefectDojo</option>
                </select>
            </td>
            <td>
                <select class="r-matchtype" style="padding:4px; max-width:80px; font-size:11px;">
                    <option value="exact" ${r.match_type==='exact'?'selected':''}>Exact</option>
                    <option value="prefix" ${r.match_type==='prefix'?'selected':''}>Prefix</option>
                    <option value="regex" ${r.match_type==='regex'?'selected':''}>Regex</option>
                </select>
            </td>
            <td><input type="text" class="r-matchval" value="${escapeHtml(r.match_value)}" placeholder="Pattern..." style="padding:4px; font-size:11px;"></td>
            <td>${buildTrackerSelectHTML(r.tracker_id, "routing-tracker-select")}</td>
            <td style="text-align:center;"><input type="checkbox" class="r-useparent" ${r.use_parent?'checked':''}></td>
            <td>${buildTrackerSelectHTML(r.parent_tracker_id, "routing-tracker-select")}</td>
            <td style="text-align:center;"><input type="checkbox" class="r-enabled" ${r.enabled?'checked':''}></td>
            <td><button class="btn btn-sm btn-danger" onclick="deleteRoutingRule(${i})">X</button></td>
        </tr>
    `).join('');
    bindRoutingRuleInputs();
    validateRoutingRules();
    evaluateRoutingSandbox(); // re-eval test on rules change
}

function validateRoutingRules() {
    const wDiv = document.getElementById('routing-warnings');
    if (!wDiv) return;
    
    let warnings = [];
    
    for (let i = 0; i < localRoutingRules.length; i++) {
        const r = localRoutingRules[i];
        if (!r.enabled) continue;
        
        if (r.match_type === 'exact' && !r.match_value) {
            warnings.push(`Rule #${i+1} has an empty 'exact' Match Value! This will ONLY match completely missing device names.`);
        }
        
        if ((r.match_type === 'prefix' || r.match_type === 'regex') && !r.match_value) {
            warnings.push(`Rule #${i+1} has an empty '${r.match_type}'! This makes it a Catch-All, shadowing all rules below it.`);
        }
    }
    
    if (warnings.length > 0) {
        wDiv.innerHTML = warnings.map(w => `<div class="toast toast-warning" style="position:static; margin-bottom:5px; opacity:1;"><span>&#9888;</span> ${escapeHtml(w)}</div>`).join('');
    } else {
        wDiv.innerHTML = '';
    }
}

function evaluateRoutingSandbox() {
    const srcEl = document.getElementById('sandbox-source');
    const devEl = document.getElementById('sandbox-device');
    const resEl = document.getElementById('sandbox-result-text');
    if (!srcEl || !devEl || !resEl) return;
    
    const source = srcEl.value;
    const val = devEl.value.trim();
    if (!val) {
        resEl.innerHTML = `<span style="color:var(--text-muted)">Type a device name to see routing logic...</span>`;
        return;
    }
    
    let matchedRule = null;
    let matchedIndex = -1;
    let selectedTracker = getInt('redmine-tracker_id', 1); // default
    
    for (let i = 0; i < localRoutingRules.length; i++) {
        const rule = localRoutingRules[i];
        if (!rule.enabled) continue;
        if (rule.source !== "any" && rule.source !== source) continue;
        
        let matched = false;
        if (rule.match_type === "exact") {
            matched = (val === rule.match_value);
        } else if (rule.match_type === "prefix") {
            matched = val.startsWith(rule.match_value);
        } else if (rule.match_type === "regex") {
            try {
                const regex = new RegExp(rule.match_value);
                matched = regex.test(val);
            } catch(e) {}
        }
        
        if (matched) {
            matchedRule = rule;
            matchedIndex = i;
            if (rule.tracker_id) selectedTracker = rule.tracker_id;
            break;
        }
    }
    
    let trackerName = globalTrackers.find(t => t.id == selectedTracker)?.name || "Unknown Tracker";
    
    if (matchedRule) {
        resEl.innerHTML = `✅ Matches <b>Rule #${matchedIndex + 1}</b> (${matchedRule.match_type}: <i>${escapeHtml(matchedRule.match_value || '(empty)')}</i>)<br>
        <span style="color:var(--green);margin-top:6px;display:inline-block;">&rarr; Routing to Tracker: <b>${selectedTracker}</b> (${escapeHtml(trackerName)})</span>`;
    } else {
        resEl.innerHTML = `⚠️ No rules matched.<br>
        <span style="color:var(--text-muted);margin-top:6px;display:inline-block;">&rarr; Falling back to Default Tracker: <b>${selectedTracker}</b> (${escapeHtml(trackerName)})</span>`;
    }
}

function useCurrentDeviceForRouting(source, routingKey) {
    source = decodeAttrValue(source);
    routingKey = decodeAttrValue(routingKey);

    // Switch to Redmine tab
    document.querySelector('.nav-item[data-section="redmine"]').click();
    
    // Fill form
    const srcEl = document.getElementById("new-rule-source");
    if(srcEl) srcEl.value = (source === "defectdojo") ? "defectdojo" : "wazuh";
    
    const mtEl = document.getElementById("new-rule-match");
    if(mtEl) mtEl.value = "exact";
    
    const valEl = document.getElementById("new-rule-value");
    if(valEl) valEl.value = routingKey;
    
    valEl.focus();
    toast("Populated Add Rule form with device value!", "info");
}

// ── Live Events ────────────────────────────────────────────────
async function fetchLiveEvents() {
    try {
        const res = await fetch('/api/webhook/history');
        const data = await res.json();
        let statusBadge = document.getElementById('live-refresh-status');
        if (statusBadge) {
            statusBadge.className = 'conn-status ok';
            statusBadge.innerHTML = '&#8635; Auto-refreshing';
        }

        const tbody = document.querySelector('#live-events-table tbody');
        if (!data.history || data.history.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:20px 0;">No webhook events received since last restart.<br><span style="font-size:11px;opacity:0.7">Trigger an alert to see it appear here instantly!</span></td></tr>';
            return;
        }

        let html = '';
        data.history.forEach(evt => {
            const time = evt.receive_time.replace('T', ' ').substring(0, 19);
            
            let findingsHtml = '';
            if (evt.findings && evt.findings.length) {
                const f = evt.findings[0];
                let decisionBadge = '';
                const act = f.action || '';
                if (act === 'created') {
                    decisionBadge = '<span class="badge badge-green">Created</span>';
                } else if (act === 'recreated') {
                    decisionBadge = '<span class="badge badge-green">Recreated</span>'; 
                } else if (act === 'updated') {
                    decisionBadge = '<span class="badge badge-blue">Updated</span>';
                } else if (act === 'reopened') {
                    decisionBadge = '<span class="badge badge-blue">Reopened</span>';
                } else if (act === 'failed') {
                    decisionBadge = '<span class="badge" style="background:var(--red);color:white">Failed</span>';
                } else if (f.reason === 'same_batch_duplicate') {
                    decisionBadge = '<span class="badge badge-orange">Deduped</span>';
                } else if (f.reason && f.reason.startsWith('Filtered')) {
                    decisionBadge = '<span class="badge" style="background:var(--bg-hover)">Filtered</span>';
                } else if (f.reason === 'Deduplication disabled') {
                    decisionBadge = '<span class="badge badge-purple">Passed</span>';
                } else {
                    decisionBadge = '<span class="badge badge-purple">Processed</span>';
                }

                const sourceLinkHtml = f.source_link
                    ? `<div style="font-size:11px;margin-top:6px;"><a href="${escapeHtml(f.source_link)}" target="_blank" rel="noopener noreferrer">Source finding</a></div>`
                    : '';

                findingsHtml = `<b>${escapeHtml(f.title || 'Unknown Rule')}</b><br>
                <div style="margin-top:4px;display:flex;gap:6px;align-items:center;">
                    ${decisionBadge}
                    <span class="badge" style="background:var(--bg-hover)">Sev: ${escapeHtml(f.severity)}</span>
                </div>
                <div style="font-size:11px;color:var(--text-secondary);margin-top:4px;border-left:2px solid var(--border);padding-left:6px;">
                    <div>Host: <span style="color:var(--text)">${escapeHtml(f.host || '')}</span></div>
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div>Device Name Used For Routing: <span style="font-family:'JetBrains Mono', monospace;color:var(--accent)">${escapeHtml(f.routing_key || '')}</span></div>
                        <button class="btn btn-sm" style="font-size:10px;padding:2px 6px;height:auto;" onclick="useCurrentDeviceForRouting('${encodeAttrValue(f.source || '')}', '${encodeAttrValue(f.routing_key || '')}')">Use Device for Routing</button>
                    </div>
                </div>
                <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">
                    Dedup: <i>${escapeHtml(f.dedup_reason || f.reason || 'Unknown')}</i> &bull; Tracker: ${f.selected_tracker || '?'} &bull; Rule: ${escapeHtml(f.matched_rule || 'none')} &bull; Occurrences: ${f.occurrences || 1}
                </div>
                ${sourceLinkHtml}`;

                if (evt.findings.length > 1) {
                    findingsHtml += `<div style="font-size:11px;color:var(--text-muted);margin-top:4px;">+ ${evt.findings.length - 1} more</div>`;
                }
            } else {
                findingsHtml = '<span style="color:var(--text-muted)">No parsable findings</span>';
            }

            const s = evt.stats || {};
            let statsHtml = [];
            if (s.created > 0) statsHtml.push(`<span style="color:var(--green)">Created: ${s.created}</span>`);
            if (s.recreated > 0) statsHtml.push(`<span style="color:var(--green)">Recreated: ${s.recreated}</span>`);
            if (s.updated > 0) statsHtml.push(`<span style="color:var(--accent)">Updated: ${s.updated}</span>`);
            if (s.reopened > 0) statsHtml.push(`<span style="color:var(--accent)">Reopened: ${s.reopened}</span>`);
            if (s.deduplicated > 0) statsHtml.push(`<span style="color:var(--orange)">Deduplicated: ${s.deduplicated}</span>`);
            if (s.filtered > 0) statsHtml.push(`<span style="color:var(--text-muted)">Filtered: ${s.filtered}</span>`);
            if (s.failed > 0) statsHtml.push(`<span style="color:var(--red)">Failed: ${s.failed}</span>`);

            html += `<tr>
                <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-secondary)">${time}</td>
                <td>${evt.alert_count}</td>
                <td style="font-size:13px">${findingsHtml}</td>
                <td style="font-size:12px;font-weight:600;display:flex;flex-direction:column;gap:3px">${statsHtml.join('') || '-'}</td>
            </tr>`;
        });
        
        tbody.innerHTML = html;
    } catch(e) {
        console.error("Live events fetch failed", e);
        let statusBadge = document.getElementById('live-refresh-status');
        if (statusBadge) {
            statusBadge.className = 'conn-status fail';
            statusBadge.textContent = 'Disconnected';
        }
    }
}

setInterval(fetchLiveEvents, 3000);
fetchLiveEvents();

// ── Backup UI Logic ────────────────────────────────────────────
async function openBackupViewer() {
    document.getElementById('backup-modal').style.display = 'flex';
    const listEl = document.getElementById('backup-list');
    listEl.innerHTML = '<div style="text-align:center; padding: 20px; color:var(--text-muted);">Loading backups...</div>';
    
    try {
        const res = await fetch('/api/config/backups');
        const data = await res.json();
        
        if (data.status !== 'ok') throw new Error(data.message || 'Failed to load backups');
        
        if (!data.backups || data.backups.length === 0) {
            listEl.innerHTML = '<div style="text-align:center; padding: 20px; color:var(--text-muted);">No backups found.</div>';
            return;
        }
        
        listEl.innerHTML = data.backups.map(b => {
            const date = new Date(b.timestamp);
            return `<div style="display:flex; justify-content:space-between; align-items:center; background:var(--bg-input); padding:12px 16px; border:1px solid var(--border); border-radius:var(--radius-sm);">
                <div>
                    <div style="font-weight:500; font-family:'JetBrains Mono', monospace; font-size:13px; color:var(--text-primary);">${b.filename}</div>
                    <div style="color:var(--text-muted); font-size:11px; margin-top:4px;">${date.toLocaleString()} &bull; ${(b.size/1024).toFixed(1)} KB</div>
                </div>
                <button class="btn btn-sm btn-primary" onclick="restoreBackup('${b.filename}')">Restore</button>
            </div>`;
        }).join('');
    } catch(e) {
        listEl.innerHTML = `<div style="text-align:center; padding: 20px; color:var(--red);">${e.message}</div>`;
    }
}

function closeBackupViewer() {
    document.getElementById('backup-modal').style.display = 'none';
}

async function restoreBackup(filename) {
    if (!confirm(`Are you sure you want to restore ${filename}? Existing configuration will be overwritten.`)) return;
    
    try {
        const res = await fetch(`/api/config/backups/restore/${encodeURIComponent(filename)}`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
            toast('Backup restored successfully!', 'success');
            closeBackupViewer();
            loadConfig();
        } else {
            toast('Failed to restore backup: ' + data.message, 'error');
        }
    } catch(e) {
        toast('Network error restoring backup', 'error');
    }
}

// ── Init ───────────────────────────────────────────────────────
['defectdojo-product_ids', 'defectdojo-engagement_ids'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', () => {
        updateDefectDojoScopeFilters();
        resetDefectDojoFindingCountPreview();
    });
});
['defectdojo-test_ids', 'defectdojo-updated_since_minutes', 'defectdojo-fetch_limit'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', () => {
        renderDefectDojoWarnings();
        resetDefectDojoFindingCountPreview();
    });
    if (el) el.addEventListener('input', () => {
        renderDefectDojoWarnings();
        resetDefectDojoFindingCountPreview();
    });
});
['defectdojo-base_url', 'defectdojo-api_key'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', resetDefectDojoFindingCountPreview);
    if (el) el.addEventListener('change', resetDefectDojoFindingCountPreview);
});
['defectdojo-active', 'defectdojo-verified', 'defectdojo-enabled', 'defectdojo-verify_ssl'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', resetDefectDojoFindingCountPreview);
});
loadConfig();
