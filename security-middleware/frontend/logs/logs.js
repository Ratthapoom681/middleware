document.addEventListener('DOMContentLoaded', async () => {
    COMPONENTS.initLayout('logs', 'Unified Logs');
    loadLogs();
});
async function loadLogs() {
    const source = document.getElementById('log-source-filter').value;
    const level = document.getElementById('log-level-filter').value;
    const tbody = document.getElementById('logs-body');
    tbody.innerHTML = '<tr><td colspan="5" class="loading-placeholder">Loading…</td></tr>';
    const logs = await API.getLogs(source, level, 100);
    if (logs.length === 0) { tbody.innerHTML = '<tr><td colspan="5" class="loading-placeholder">No findings match</td></tr>'; return; }
    tbody.innerHTML = logs.map(l => `
        <tr>
            <td><span class="badge badge-${(l.severity||'info').toLowerCase()}">${l.severity||'info'}</span></td>
            <td>${l.source||'—'}</td>
            <td>${l.title||'—'}</td>
            <td>${l.status||'new'}</td>
            <td>${l.created_at ? new Date(l.created_at).toLocaleString() : '—'}</td>
        </tr>
    `).join('');
}
// Make loadLogs available globally for the onclick handler
window.loadLogs = loadLogs;
