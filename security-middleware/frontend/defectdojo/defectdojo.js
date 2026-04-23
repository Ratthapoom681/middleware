document.addEventListener('DOMContentLoaded', async () => {
    COMPONENTS.initLayout('defectdojo', 'DefectDojo');
    loadDojoStatus();
    loadDojoFindings();
});

async function loadDojoStatus() {
    const st = await API.getDefectDojoStatus();
    document.getElementById('dojo-conn-status').textContent = st.connected ? '● Connected' : '○ Disconnected';
    document.getElementById('dojo-conn-status').className = `badge ${st.connected ? 'badge-low' : 'badge-critical'}`;
    document.getElementById('dojo-status-text').textContent = st.connected ? 'Online' : 'Offline';
    document.getElementById('dojo-url-text').textContent = st.url || 'Not configured';
    document.getElementById('dojo-count-text').textContent = st.finding_count ?? '—';
}

async function loadDojoFindings() {
    const tbody = document.getElementById('dojo-findings-body');
    const items = await API.getDefectDojoFindings(50);
    if (items.length === 0) { tbody.innerHTML = '<tr><td colspan="4" class="loading-placeholder">No findings</td></tr>'; return; }
    tbody.innerHTML = items.map(f => `
        <tr>
            <td><span class="badge badge-${(f.severity||'info').toLowerCase()}">${f.severity||'info'}</span></td>
            <td>${f.title||'—'}</td>
            <td>${f.source_id||'—'}</td>
            <td>${f.created_at ? new Date(f.created_at).toLocaleString() : '—'}</td>
        </tr>
    `).join('');
}
