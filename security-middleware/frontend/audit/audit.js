document.addEventListener('DOMContentLoaded', async () => {
    COMPONENTS.initLayout('audit', 'Audit Log');
    loadAudit();
});
async function loadAudit() {
    const module = document.getElementById('audit-module-filter').value;
    const tbody = document.getElementById('audit-body');
    tbody.innerHTML = '<tr><td colspan="5" class="loading-placeholder">Loading…</td></tr>';
    const entries = await API.getAuditLog(module);
    if (entries.length === 0) { tbody.innerHTML = '<tr><td colspan="5" class="loading-placeholder">No audit entries</td></tr>'; return; }
    tbody.innerHTML = entries.map(e => `
        <tr>
            <td>${e.created_at ? new Date(e.created_at).toLocaleString() : '—'}</td>
            <td>${e.module||'—'}</td>
            <td>${e.action||'—'}</td>
            <td>${e.user||'system'}</td>
            <td class="text-truncate">${e.detail||'—'}</td>
        </tr>
    `).join('');
}
window.loadAudit = loadAudit;
