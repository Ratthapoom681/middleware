document.addEventListener('DOMContentLoaded', async () => {
    COMPONENTS.initLayout('redmine', 'Redmine Tickets');
    loadRedmineStatus();
    loadRedmineTickets();
});
async function loadRedmineStatus() {
    const st = await API.getRedmineStatus();
    document.getElementById('redmine-conn-status').textContent = st.connected ? '● Connected' : '○ Disconnected';
    document.getElementById('redmine-conn-status').className = `badge ${st.connected ? 'badge-low' : 'badge-critical'}`;
    document.getElementById('redmine-status-text').textContent = st.connected ? 'Online' : 'Offline';
    document.getElementById('redmine-url-text').textContent = st.url || 'Not configured';
}
async function loadRedmineTickets() {
    const tbody = document.getElementById('redmine-tickets-body');
    const items = await API.getRedmineTickets(50);
    if (items.length === 0) { tbody.innerHTML = '<tr><td colspan="4" class="loading-placeholder">No tickets</td></tr>'; return; }
    tbody.innerHTML = items.map(t => `
        <tr>
            <td><span class="badge badge-${(t.severity||'info').toLowerCase()}">${t.severity||'info'}</span></td>
            <td>${t.title||'—'}</td>
            <td>${t.redmine_ticket_id||'—'}</td>
            <td>${t.updated_at ? new Date(t.updated_at).toLocaleString() : '—'}</td>
        </tr>
    `).join('');
}
