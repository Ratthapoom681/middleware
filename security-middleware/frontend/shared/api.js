/**
 * API Utility for Middleware Dashboard
 * Connects to the FastAPI backend at /api
 */

const API = {
    baseUrl: '/api',

    async request(endpoint, options = {}) {
        try {
            const response = await fetch(`${this.baseUrl}${endpoint}`, {
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers,
                },
            });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`[API] Request failed: ${endpoint}`, error);
            throw error;
        }
    },

    // ── Dashboard ──
    async getStats() {
        try {
            const [logStats, pipelineStatus] = await Promise.all([
                this.request('/logs/stats'),
                this.request('/pipeline/status'),
            ]);
            return {
                totalAlerts: logStats.total_findings || 0,
                deduplicated: pipelineStatus.metrics?.total_deduplicated || 0,
                ticketsCreated: pipelineStatus.metrics?.total_delivered || 0,
                filtered: pipelineStatus.metrics?.total_filtered || 0,
                failed: pipelineStatus.metrics?.total_failed || 0,
                systemHealth: pipelineStatus.status === 'active' ? 'Healthy' : 'Degraded',
            };
        } catch {
            return { totalAlerts: 0, deduplicated: 0, ticketsCreated: 0, filtered: 0, failed: 0, systemHealth: 'Offline' };
        }
    },

    // ── Logs ──
    async getLogs(source = 'all', level = 'all', limit = 100) {
        try {
            const data = await this.request(`/logs?source=${source}&level=${level}&limit=${limit}`);
            return data.logs || [];
        } catch { return []; }
    },

    // ── Wazuh ──
    async getWazuhAlerts(limit = 100) {
        try {
            const data = await this.request(`/wazuh/alerts?limit=${limit}`);
            return data.alerts || [];
        } catch { return []; }
    },
    async getWazuhStatus() {
        try { return await this.request('/wazuh/status'); }
        catch { return { connected: false }; }
    },

    // ── DefectDojo ──
    async getDefectDojoFindings(limit = 100) {
        try {
            const data = await this.request(`/defectdojo/findings?limit=${limit}`);
            return data.findings || [];
        } catch { return []; }
    },
    async getDefectDojoStatus() {
        try { return await this.request('/defectdojo/status'); }
        catch { return { connected: false }; }
    },

    // ── Redmine ──
    async getRedmineTickets(limit = 50) {
        try {
            const data = await this.request(`/redmine/tickets?limit=${limit}`);
            return data.tickets || [];
        } catch { return []; }
    },
    async getRedmineStatus() {
        try { return await this.request('/redmine/status'); }
        catch { return { connected: false }; }
    },
    async getRedmineTrackers() {
        try {
            const data = await this.request('/redmine/trackers');
            return data.trackers || [];
        } catch { return []; }
    },

    // ── Pipeline ──
    async getPipelineStatus() {
        try { return await this.request('/pipeline/status'); }
        catch { return { status: 'offline', metrics: {} }; }
    },
    async getDeadLetters(limit = 50) {
        try {
            const data = await this.request(`/pipeline/dead-letter?limit=${limit}`);
            return data.items || [];
        } catch { return []; }
    },

    // ── Audit ──
    async getAuditLog(module = 'all', action = 'all', limit = 100) {
        try {
            const data = await this.request(`/audit?module=${module}&action=${action}&limit=${limit}`);
            return data.entries || [];
        } catch { return []; }
    },

    // ── Settings ──
    async getSettings() {
        try {
            const data = await this.request('/settings');
            return data.defaults || {};
        } catch { return {}; }
    },
    async getSettingsSection(section) {
        try {
            const data = await this.request(`/settings/${section}`);
            return data.config || {};
        } catch { return {}; }
    },
    async updateSettings(section, config) {
        return await this.request(`/settings/${section}`, {
            method: 'PUT',
            body: JSON.stringify({ config }),
        });
    },

    // ── Scheduler ──
    async getJobs() {
        try {
            const data = await this.request('/scheduler/jobs');
            return data.jobs || [];
        } catch { return []; }
    },
    async triggerJob(jobName) {
        return await this.request(`/scheduler/trigger/${jobName}`, { method: 'POST' });
    },

    // ── Data Retention ──
    async triggerBackup(type = 'full') {
        return await this.request(`/data-retention/backup?type=${type}`, { method: 'POST' });
    },
    async deleteBackups(type = 'all') {
        return await this.request(`/data-retention/backups?type=${type}`, { method: 'DELETE' });
    },
    async triggerCleanup(days = 90) {
        return await this.request(`/data-retention/cleanup?retention_days=${days}`, { method: 'POST' });
    },
    async getRetentionStatus() {
        try { return await this.request('/data-retention/status'); }
        catch { return { retention_days: 90, backup_enabled: true }; }
    },
    async getBackups() {
        try {
            const data = await this.request('/data-retention/backups');
            return data.backups || [];
        } catch { return []; }
    },
    async restoreBackup(filename) {
        return await this.request(`/data-retention/backups/restore/${encodeURIComponent(filename)}`, { method: 'POST' });
    },

    // ── WebSocket ──
    connectWebSocket(onMessage) {
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${location.host}/api/logs/stream`;
        let ws = null;
        let reconnectTimer = null;

        function connect() {
            try {
                ws = new WebSocket(wsUrl);
                ws.onopen = () => console.log('[WS] Connected');
                ws.onmessage = (event) => {
                    try {
                        const data = JSON.parse(event.data);
                        if (onMessage) onMessage(data);
                    } catch (e) {
                        console.warn('[WS] Parse error:', e);
                    }
                };
                ws.onclose = () => {
                    console.log('[WS] Disconnected, reconnecting in 5s…');
                    reconnectTimer = setTimeout(connect, 5000);
                };
                ws.onerror = (err) => {
                    console.warn('[WS] Error:', err);
                    ws.close();
                };
            } catch (e) {
                console.warn('[WS] Connection failed:', e);
                reconnectTimer = setTimeout(connect, 5000);
            }
        }

        connect();
        return {
            close() {
                clearTimeout(reconnectTimer);
                if (ws) ws.close();
            }
        };
    },
};

window.API = API;
