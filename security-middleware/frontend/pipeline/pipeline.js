document.addEventListener('DOMContentLoaded', async () => {
    COMPONENTS.initLayout('pipeline', 'Pipeline Monitor');
    loadPipelineStatus();
    loadDeadLetters();
});
async function loadPipelineStatus() {
    const data = await API.getPipelineStatus();
    document.getElementById('pipeline-status-badge').textContent = data.status === 'active' ? '● Active' : '○ Inactive';
    document.getElementById('pipeline-status-badge').className = `badge ${data.status === 'active' ? 'badge-low' : 'badge-critical'}`;
    const m = data.metrics || {};
    document.getElementById('p-processed').textContent = (m.total_processed||0).toLocaleString();
    document.getElementById('p-dedup').textContent = (m.total_deduplicated||0).toLocaleString();
    document.getElementById('p-filtered').textContent = (m.total_filtered||0).toLocaleString();
    document.getElementById('p-delivered').textContent = (m.total_delivered||0).toLocaleString();
    document.getElementById('p-failed').textContent = (m.total_failed||0).toLocaleString();
}
async function loadDeadLetters() {
    const tbody = document.getElementById('dead-letter-body');
    const items = await API.getDeadLetters();
    if (items.length === 0) { tbody.innerHTML = '<tr><td colspan="4" class="loading-placeholder">No failed items</td></tr>'; return; }
    tbody.innerHTML = items.map(d => `
        <tr>
            <td>${d.finding_id||'—'}</td>
            <td class="text-truncate">${d.error||'—'}</td>
            <td>${d.retry_count||0}</td>
            <td>${d.created_at ? new Date(d.created_at).toLocaleString() : '—'}</td>
        </tr>
    `).join('');
}
