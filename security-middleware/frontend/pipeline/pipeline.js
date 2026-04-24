/**
 * Pipeline Monitor — status, scheduled jobs, dead-letter queue.
 * Connects to WebSocket for real-time metric updates.
 */

document.addEventListener('DOMContentLoaded', async () => {
    COMPONENTS.initLayout('pipeline', 'Pipeline Monitor');
    loadPipelineStatus();
    loadDeadLetters();
    loadJobs();

    // Real-time updates via WebSocket
    API.connectWebSocket((data) => {
        if (data.type === 'pipeline_run') {
            loadPipelineStatus();
            loadDeadLetters();
            loadJobs();
            COMPONENTS.toast('Pipeline run completed', 'info');
        }
    });
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

    const lastRunEl = document.getElementById('pipeline-last-run');
    if (m.last_run) {
        lastRunEl.textContent = `Last run: ${new Date(m.last_run).toLocaleString()}`;
    } else {
        lastRunEl.textContent = 'No pipeline runs yet';
    }
}

async function loadDeadLetters() {
    const tbody = document.getElementById('dead-letter-body');
    const deadLetters = await API.getDeadLetters();
    if (deadLetters.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="loading-placeholder">No dead-letter items found</td></tr>';
        return;
    }
    tbody.innerHTML = deadLetters.map(item => `
        <tr>
            <td><strong>${item.finding_id || '—'}</strong></td>
            <td class="text-error" style="max-width: 300px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${item.error || ''}">${item.error || '—'}</td>
            <td>${item.retry_count || 0}</td>
            <td>${item.created_at ? new Date(item.created_at).toLocaleString() : '—'}</td>
        </tr>
    `).join('');
}

async function loadJobs() {
    const tbody = document.getElementById('jobs-body');
    const jobs = await API.getJobs();
    if (jobs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="loading-placeholder">No jobs configured</td></tr>';
        return;
    }
    tbody.innerHTML = jobs.map(job => `
        <tr>
            <td><strong>${job.name || '—'}</strong></td>
            <td>${job.description || '—'}</td>
            <td><span class="badge ${job.enabled ? 'badge-low' : 'badge-critical'}">${job.enabled ? 'Enabled' : 'Disabled'}</span></td>
            <td>${job.last_run ? new Date(job.last_run).toLocaleString() : 'Never'}</td>
            <td>
                <button class="btn btn-sm btn-secondary" onclick="triggerJob('${job.name}')" ${!job.enabled ? 'disabled' : ''}>
                    <i class="ph-bold ph-play"></i> Run
                </button>
            </td>
        </tr>
    `).join('');
}

async function triggerPipeline() {
    const btn = document.getElementById('btn-run-now');
    btn.disabled = true;
    btn.innerHTML = '<i class="ph-bold ph-spinner"></i> Running…';
    try {
        const result = await API.triggerJob('pipeline_poll');
        if (result.status === 'ok') {
            COMPONENTS.toast('Pipeline run completed successfully', 'success');
        } else {
            COMPONENTS.toast(`Pipeline run failed: ${result.message || 'Unknown error'}`, 'error');
        }
        loadPipelineStatus();
        loadDeadLetters();
        loadJobs();
    } catch (e) {
        COMPONENTS.toast(`Pipeline trigger failed: ${e.message}`, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="ph-bold ph-play"></i> Run Now';
    }
}

async function triggerJob(jobName) {
    try {
        const result = await API.triggerJob(jobName);
        COMPONENTS.toast(`Job '${jobName}' completed: ${result.status}`, result.status === 'ok' ? 'success' : 'warning');
        loadJobs();
        loadPipelineStatus();
    } catch (e) {
        COMPONENTS.toast(`Job trigger failed: ${e.message}`, 'error');
    }
}

window.triggerPipeline = triggerPipeline;
window.triggerJob = triggerJob;
