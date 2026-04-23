document.addEventListener('DOMContentLoaded', async () => {
    COMPONENTS.initLayout('dashboard', 'Security Overview');
    loadDashboardStats();
    loadRecentLogs();
});

async function loadDashboardStats() {
    const stats = await API.getStats();
    document.getElementById('total-alerts').textContent = stats.totalAlerts.toLocaleString();
    const dedupPct = stats.totalAlerts > 0 ? Math.round((stats.deduplicated / stats.totalAlerts) * 100) : 0;
    document.getElementById('dedup-rate').textContent = dedupPct + '%';
    document.getElementById('tickets-count').textContent = stats.ticketsCreated;
    document.getElementById('system-health').textContent = stats.systemHealth;
}

async function loadRecentLogs() {
    const logsContainer = document.getElementById('recent-logs');
    const logs = await API.getLogs('all', 'all', 10);
    logsContainer.innerHTML = '';
    if (logs.length === 0) {
        logsContainer.innerHTML = '<div class="loading-placeholder">No findings yet</div>';
        return;
    }
    logs.forEach(log => {
        const el = document.createElement('div');
        el.className = 'log-item';
        el.innerHTML = `
            <div class="log-meta">
                <span class="badge badge-${(log.severity || 'info').toLowerCase()}">${log.severity || 'info'}</span>
                <span class="log-source">${log.source || 'unknown'}</span>
            </div>
            <p class="log-msg">${log.title || 'Untitled finding'}</p>
        `;
        logsContainer.appendChild(el);
    });
}
