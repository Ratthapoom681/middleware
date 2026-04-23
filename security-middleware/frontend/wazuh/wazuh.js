document.addEventListener('DOMContentLoaded', async () => {
    COMPONENTS.initLayout('wazuh', 'Wazuh SIEM');
    loadWazuhStatus();
    loadWazuhAlerts();
});

async function loadWazuhStatus() {
    const status = await API.getWazuhStatus();
    document.getElementById('wazuh-conn-status').textContent = status.connected ? '● Connected' : '○ Disconnected';
    document.getElementById('wazuh-conn-status').className = `badge ${status.connected ? 'badge-low' : 'badge-critical'}`;
    document.getElementById('wazuh-status-text').textContent = status.connected ? 'Online' : 'Offline';
    document.getElementById('wazuh-url-text').textContent = status.url || 'Not configured';
}

async function loadWazuhAlerts() {
    const tbody = document.getElementById('wazuh-alerts-body');
    const alerts = await API.getWazuhAlerts(50);
    if (alerts.length === 0) { tbody.innerHTML = '<tr><td colspan="4" class="loading-placeholder">No alerts found</td></tr>'; return; }
    tbody.innerHTML = alerts.map(a => `
        <tr>
            <td><span class="badge badge-${(a.severity||'info').toLowerCase()}">${a.severity||'info'}</span></td>
            <td>${a.title||'—'}</td>
            <td>${a.source_id||'—'}</td>
            <td>${a.created_at ? new Date(a.created_at).toLocaleString() : '—'}</td>
        </tr>
    `).join('');
}
