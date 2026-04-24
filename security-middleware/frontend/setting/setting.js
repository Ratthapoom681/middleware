/**
 * Settings page – dynamic form generation for every config section.
 * Loads from /api/settings/{section} and saves via PUT.
 */

let currentSection = 'wazuh';
let currentConfig = {};

// Field definitions per section for auto-form generation
const FIELD_DEFS = {
    wazuh: [
        { key: 'base_url', label: 'Manager Base URL', type: 'url' },
        { key: 'username', label: 'Manager Username', type: 'text' },
        { key: 'password', label: 'Manager Password', type: 'password' },
        { key: 'indexer_url', label: 'Indexer URL', type: 'url' },
        { key: 'indexer_username', label: 'Indexer Username', type: 'text' },
        { key: 'indexer_password', label: 'Indexer Password', type: 'password' },
        { key: 'alerts_json_path', label: 'Alerts JSON Path', type: 'text' },
        { key: 'min_level', label: 'Min Alert Level (0-15)', type: 'number', min: 0, max: 15 },
        { key: 'verify_ssl', label: 'Verify SSL', type: 'toggle' },
        { key: 'webhook_api_key', label: 'Webhook API Key', type: 'password' },
        { key: 'polling_enabled', label: 'Polling Enabled', type: 'toggle' },
    ],
    defectdojo: [
        { key: 'enabled', label: 'Enabled', type: 'toggle' },
        { key: 'base_url', label: 'API Base URL', type: 'url' },
        { key: 'api_key', label: 'API Key', type: 'password' },
        { key: 'verify_ssl', label: 'Verify SSL', type: 'toggle' },
        { key: 'active', label: 'Active Findings Only', type: 'toggle' },
        { key: 'verified', label: 'Verified Findings Only', type: 'toggle' },
        { key: 'updated_since_minutes', label: 'Updated Since (minutes)', type: 'number', min: 0 },
        { key: 'fetch_limit', label: 'Fetch Limit', type: 'number', min: 0 },
        { key: 'product_ids', label: 'Product IDs (comma-separated)', type: 'chips' },
        { key: 'engagement_ids', label: 'Engagement IDs (comma-separated)', type: 'chips' },
        { key: 'test_ids', label: 'Test IDs (comma-separated)', type: 'chips' },
        { key: 'severity_filter', label: 'Severity Filter (comma-separated)', type: 'chips' },
    ],
    redmine: [
        { key: 'base_url', label: 'Redmine URL', type: 'url' },
        { key: 'api_key', label: 'API Key', type: 'password' },
        { key: 'project_id', label: 'Project ID', type: 'text' },
        { key: 'tracker_id', label: 'Default Tracker ID', type: 'number' },
        { key: 'enable_parent_issues', label: 'Enable Parent Issues', type: 'toggle' },
        { key: 'parent_tracker_id', label: 'Parent Tracker ID', type: 'number' },
        { key: 'dedup_custom_field_id', label: 'Dedup Custom Field ID', type: 'number' },
        { key: 'priority_map', label: 'Priority Map (JSON)', type: 'json' },
        { key: 'routing_rules', label: 'Routing Rules (JSON)', type: 'json' },
    ],
    pipeline: [
        { key: 'poll_interval', label: 'Poll Interval (seconds)', type: 'number', min: 10 },
        { key: 'initial_lookback_minutes', label: 'Initial Lookback (minutes)', type: 'number', min: 0 },
    ],
    filter: [
        { key: 'min_severity', label: 'Min Severity', type: 'select', options: ['info', 'low', 'medium', 'high', 'critical'] },
        { key: 'default_action', label: 'Default Action', type: 'select', options: ['keep', 'drop'] },
        { key: 'exclude_rule_ids', label: 'Exclude Rule IDs (comma-separated)', type: 'chips' },
        { key: 'exclude_title_patterns', label: 'Exclude Title Patterns (comma-separated)', type: 'chips' },
        { key: 'include_hosts', label: 'Include Hosts (comma-separated)', type: 'chips' },
        { key: 'json_rules', label: 'JSON Filter Rules', type: 'json' },
    ],
    dedup: [
        { key: 'enabled', label: 'Enabled', type: 'toggle' },
        { key: 'db_path', label: 'DB Path', type: 'text' },
        { key: 'ttl_hours', label: 'TTL (hours)', type: 'number', min: 1 },
    ],
    enrichment: [
        { key: 'asset_inventory_enabled', label: 'Asset Inventory Enabled', type: 'toggle' },
        { key: 'asset_inventory_path', label: 'Asset Inventory Path', type: 'text' },
        { key: 'add_remediation_links', label: 'Add Remediation Links', type: 'toggle' },
    ],
    severity_map: [
        { key: 'wazuh_level_map', label: 'Wazuh Level Map (JSON)', type: 'json' },
        { key: 'defectdojo_severity_map', label: 'DefectDojo Severity Map (JSON)', type: 'json' },
    ],
    storage: [
        { key: 'backend', label: 'Backend', type: 'select', options: ['local', 'postgres'] },
        { key: 'postgres_dsn', label: 'Postgres DSN', type: 'password' },
        { key: 'postgres_schema', label: 'Postgres Schema', type: 'text' },
        { key: 'dedup_table', label: 'Dedup Table', type: 'text' },
        { key: 'checkpoint_table', label: 'Checkpoint Table', type: 'text' },
        { key: 'ticket_state_table', label: 'Ticket State Table', type: 'text' },
        { key: 'outbound_queue_table', label: 'Outbound Queue Table', type: 'text' },
        { key: 'ingest_event_table', label: 'Ingest Event Table', type: 'text' },
    ],
    logging: [
        { key: 'level', label: 'Log Level', type: 'select', options: ['DEBUG', 'INFO', 'WARNING', 'ERROR'] },
        { key: 'format', label: 'Log Format', type: 'text' },
    ],
};

const SECTION_TITLES = {
    wazuh: 'Wazuh Settings',
    defectdojo: 'DefectDojo Settings',
    redmine: 'Redmine Settings',
    pipeline: 'Pipeline Settings',
    filter: 'Filter Rules',
    dedup: 'Deduplication',
    enrichment: 'Enrichment',
    severity_map: 'Severity Mapping',
    storage: 'Storage',
    logging: 'Logging',
};

document.addEventListener('DOMContentLoaded', async () => {
    COMPONENTS.initLayout('settings', 'Settings');

    // Tab click handlers
    document.querySelectorAll('.settings-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.settings-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            currentSection = tab.dataset.section;
            loadSection(currentSection);
        });
    });

    loadSection('wazuh');
    loadRetentionStatus();
    loadBackups();
});

async function loadSection(section) {
    document.getElementById('settings-section-title').textContent = SECTION_TITLES[section] || section;
    const container = document.getElementById('settings-form-container');
    container.innerHTML = '<div class="loading-placeholder">Loading…</div>';

    currentConfig = await API.getSettingsSection(section);
    renderForm(section, currentConfig);
}

function renderForm(section, config) {
    const container = document.getElementById('settings-form-container');
    const fields = FIELD_DEFS[section] || [];

    if (fields.length === 0) {
        container.innerHTML = `<textarea id="raw-json-editor" style="width:100%;min-height:300px;font-family:monospace">${JSON.stringify(config, null, 2)}</textarea>`;
        return;
    }

    let html = '<div class="settings-grid">';
    for (const field of fields) {
        const val = config[field.key];
        const fullWidth = (field.type === 'json') ? ' full-width' : '';
        html += `<div class="setting-field${fullWidth}">`;
        html += `<label>${field.label}</label>`;

        if (field.type === 'toggle') {
            html += `<label class="toggle"><input type="checkbox" id="f-${field.key}" ${val ? 'checked' : ''}><span class="toggle-track"></span></label>`;
        } else if (field.type === 'select') {
            html += `<select id="f-${field.key}">${(field.options || []).map(o => `<option value="${o}" ${val === o ? 'selected' : ''}>${o}</option>`).join('')}</select>`;
        } else if (field.type === 'chips') {
            const arr = Array.isArray(val) ? val.join(', ') : (val || '');
            html += `<input type="text" id="f-${field.key}" value="${arr}" placeholder="value1, value2, …">`;
        } else if (field.type === 'json') {
            const jsonStr = typeof val === 'object' ? JSON.stringify(val, null, 2) : (val || '{}');
            html += `<textarea id="f-${field.key}">${jsonStr}</textarea>`;
        } else if (field.type === 'number') {
            html += `<input type="number" id="f-${field.key}" value="${val ?? ''}" ${field.min !== undefined ? `min="${field.min}"` : ''} ${field.max !== undefined ? `max="${field.max}"` : ''}>`;
        } else {
            html += `<input type="${field.type || 'text'}" id="f-${field.key}" value="${val ?? ''}">`;
        }

        html += `</div>`;
    }
    html += '</div>';
    container.innerHTML = html;
}

function collectFormValues() {
    const fields = FIELD_DEFS[currentSection] || [];
    if (fields.length === 0) {
        // Raw JSON mode
        const editor = document.getElementById('raw-json-editor');
        if (editor) return JSON.parse(editor.value);
        return currentConfig;
    }

    const result = { ...currentConfig };
    for (const field of fields) {
        const el = document.getElementById(`f-${field.key}`);
        if (!el) continue;

        if (field.type === 'toggle') {
            result[field.key] = el.checked;
        } else if (field.type === 'number') {
            result[field.key] = el.value === '' ? null : Number(el.value);
        } else if (field.type === 'chips') {
            const raw = el.value.trim();
            if (raw === '') { result[field.key] = []; }
            else {
                const items = raw.split(',').map(s => s.trim()).filter(Boolean);
                result[field.key] = field.key.includes('_ids') ? items.map(Number) : items;
            }
        } else if (field.type === 'json') {
            try { result[field.key] = JSON.parse(el.value); }
            catch { result[field.key] = el.value; }
        } else {
            result[field.key] = el.value;
        }
    }
    return result;
}

async function saveCurrentSection() {
    try {
        const config = collectFormValues();
        await API.updateSettings(currentSection, config);
        COMPONENTS.toast(`${SECTION_TITLES[currentSection]} saved successfully`, 'success');
        // Reload to verify
        currentConfig = await API.getSettingsSection(currentSection);
    } catch (e) {
        COMPONENTS.toast(`Save failed: ${e.message}`, 'error');
    }
}

async function doBackup(type = 'full') {
    try {
        const res = await API.triggerBackup(type);
        if (res.status === 'ok') {
            const label = type === 'config' ? 'Config' : 'Full';
            COMPONENTS.toast(`${label} backup created: ${res.backup_path}`, 'success');
            loadBackups();
        } else {
            COMPONENTS.toast(res.message || 'Backup failed', 'error');
        }
    } catch (e) {
        COMPONENTS.toast(`Backup failed: ${e.message}`, 'error');
    }
}

async function doDeleteBackups() {
    const type = document.getElementById('cleanup-type')?.value || 'all';
    const label = type === 'all' ? 'ALL' : type === 'config' ? 'all Config' : 'all Full';
    
    if (!confirm(`Are you sure you want to delete ${label} backup files?\n\nThis action cannot be undone.`)) return;
    try {
        const res = await API.deleteBackups(type);
        if (res.status === 'ok') {
            COMPONENTS.toast(`Deleted ${res.deleted_count} backup files`, 'success');
            loadBackups();
        } else {
            COMPONENTS.toast(res.message || 'Cleanup failed', 'error');
        }
    } catch (e) {
        COMPONENTS.toast(`Cleanup failed: ${e.message}`, 'error');
    }
}

async function doCleanup() {
    if (!confirm('Delete findings older than 90 days?')) return;
    try {
        const res = await API.triggerCleanup(90);
        COMPONENTS.toast(`Cleaned up ${res.deleted_records} records`, 'success');
    } catch (e) {
        COMPONENTS.toast(`Cleanup failed: ${e.message}`, 'error');
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

async function loadRetentionStatus() {
    const el = document.getElementById('retention-status');
    if (!el) return;
    try {
        const status = await API.getRetentionStatus();
        el.innerHTML = `<i class="ph-bold ph-info"></i> Retention: <strong>${status.retention_days} days</strong> · Backup: <strong>${status.backup_enabled ? 'Enabled' : 'Disabled'}</strong>`;
    } catch {
        el.textContent = '';
    }
}

async function loadBackups() {
    const tbody = document.getElementById('backups-body');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="4" class="loading-placeholder">Loading…</td></tr>';

    const backups = await API.getBackups();
    if (backups.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="loading-placeholder">No backups available</td></tr>';
        return;
    }
    tbody.innerHTML = backups.map(b => `
        <tr>
            <td><code>${b.filename}</code></td>
            <td>${formatBytes(b.size_bytes)}</td>
            <td>${new Date(b.created_at).toLocaleString()}</td>
            <td>
                <button class="btn btn-sm btn-warning" onclick="restoreBackup('${b.filename}')">
                    <i class="ph-bold ph-arrow-counter-clockwise"></i> Restore
                </button>
            </td>
        </tr>
    `).join('');
}

async function restoreBackup(filename) {
    if (!confirm(`Restore database from backup "${filename}"?\n\nThis will replace the current database. A safety backup will be created automatically.`)) return;
    try {
        const res = await API.restoreBackup(filename);
        if (res.status === 'ok') {
            COMPONENTS.toast(`Database restored from ${filename}`, 'success');
            loadBackups();
        } else {
            COMPONENTS.toast(`Restore failed: ${res.message}`, 'error');
        }
    } catch (e) {
        COMPONENTS.toast(`Restore failed: ${e.message}`, 'error');
    }
}

window.saveCurrentSection = saveCurrentSection;
window.doBackup = doBackup;
window.doCleanup = doCleanup;
window.doDeleteBackups = doDeleteBackups;
window.loadBackups = loadBackups;
window.restoreBackup = restoreBackup;

