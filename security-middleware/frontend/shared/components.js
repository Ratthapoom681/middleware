/**
 * Shared UI Components for Middleware Dashboard
 */

const COMPONENTS = {
    renderSidebar: (activePage) => {
        const sidebar = document.createElement('aside');
        sidebar.className = 'sidebar';
        
        sidebar.innerHTML = `
            <div class="sidebar-logo">
                <i class="ph-bold ph-shield-checkered"></i>
                <span>Middleware</span>
            </div>
            <nav class="sidebar-menu">
                <div class="menu-section">
                    <p class="menu-title">Main</p>
                    <a href="../main/index.html" class="menu-item ${activePage === 'dashboard' ? 'active' : ''}">
                        <i class="ph-bold ph-chart-line"></i>
                        <span>Dashboard</span>
                    </a>
                </div>

                <div class="menu-section">
                    <p class="menu-title">Sources</p>
                    <a href="../wazuh/index.html" class="menu-item ${activePage === 'wazuh' ? 'active' : ''}">
                        <i class="ph-bold ph-shield"></i>
                        <span>Wazuh</span>
                    </a>
                    <a href="../defectdojo/index.html" class="menu-item ${activePage === 'defectdojo' ? 'active' : ''}">
                        <i class="ph-bold ph-bug"></i>
                        <span>DefectDojo</span>
                    </a>
                    <a href="../redmine/index.html" class="menu-item ${activePage === 'redmine' ? 'active' : ''}">
                        <i class="ph-bold ph-ticket"></i>
                        <span>Redmine</span>
                    </a>
                </div>

                <div class="menu-section">
                    <p class="menu-title">System</p>
                    <a href="../pipeline/index.html" class="menu-item ${activePage === 'pipeline' ? 'active' : ''}">
                        <i class="ph-bold ph-git-merge"></i>
                        <span>Pipeline</span>
                    </a>
                    <a href="../logs/index.html" class="menu-item ${activePage === 'logs' ? 'active' : ''}">
                        <i class="ph-bold ph-list-bullets"></i>
                        <span>Logs</span>
                    </a>
                    <a href="../audit/index.html" class="menu-item ${activePage === 'audit' ? 'active' : ''}">
                        <i class="ph-bold ph-fingerprint"></i>
                        <span>Audit Log</span>
                    </a>
                    <a href="../setting/index.html" class="menu-item ${activePage === 'settings' ? 'active' : ''}">
                        <i class="ph-bold ph-gear-six"></i>
                        <span>Settings</span>
                    </a>
                </div>
            </nav>
        `;
        
        return sidebar;
    },

    renderHeader: (title) => {
        const header = document.createElement('header');
        header.className = 'header';
        
        header.innerHTML = `
            <div class="header-title">
                <button id="mobile-menu-toggle" class="btn-icon mobile-only" title="Menu">
                    <i class="ph-bold ph-list"></i>
                </button>
                <h1>${title}</h1>
            </div>
            <div class="header-status">
                <button id="theme-toggle" class="btn-icon" title="Toggle Theme">
                    <i class="ph-bold ph-sun"></i>
                </button>
                <div class="status-badge">
                    <span class="status-dot online"></span>
                    <span>System Online</span>
                </div>
                <div class="status-badge">
                    <i class="ph-bold ph-clock"></i>
                    <span id="header-time">00:00:00</span>
                </div>
            </div>
        `;
        
        return header;
    },

    initLayout: (pageKey, pageTitle) => {
        const container = document.querySelector('.app-container');
        if (!container) return;

        container.prepend(COMPONENTS.renderSidebar(pageKey));
        
        const mainContent = document.querySelector('.main-content');
        if (mainContent) {
            mainContent.prepend(COMPONENTS.renderHeader(pageTitle));
        }

        COMPONENTS.startClock();
        COMPONENTS.initTheme();
        COMPONENTS.initMobileMenu();
    },

    initMobileMenu: () => {
        const toggleBtn = document.getElementById('mobile-menu-toggle');
        const sidebar = document.querySelector('.sidebar');
        
        if (toggleBtn && sidebar) {
            const backdrop = document.createElement('div');
            backdrop.className = 'sidebar-backdrop';
            document.body.appendChild(backdrop);

            const toggleMenu = () => {
                sidebar.classList.toggle('open');
                backdrop.classList.toggle('active');
            };

            toggleBtn.addEventListener('click', toggleMenu);
            backdrop.addEventListener('click', toggleMenu);
        }
    },

    initTheme: () => {
        // Run immediately to prevent flash if possible, though usually this is run on DOMContentLoaded
        const currentTheme = localStorage.getItem('theme') || 'dark';
        document.documentElement.setAttribute('data-theme', currentTheme);

        const toggleBtn = document.getElementById('theme-toggle');
        if (toggleBtn) {
            const icon = toggleBtn.querySelector('i');
            
            const updateIcon = (theme) => {
                if (theme === 'light') {
                    icon.className = 'ph-bold ph-moon';
                } else {
                    icon.className = 'ph-bold ph-sun';
                }
            };
            
            updateIcon(currentTheme);

            toggleBtn.addEventListener('click', () => {
                const newTheme = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
                document.documentElement.setAttribute('data-theme', newTheme);
                localStorage.setItem('theme', newTheme);
                updateIcon(newTheme);
            });
        }
    },

    startClock: () => {
        const timeEl = document.getElementById('header-time');
        if (!timeEl) return;
        
        const updateTime = () => {
            const now = new Date();
            timeEl.textContent = now.toLocaleTimeString();
        };
        
        setInterval(updateTime, 1000);
        updateTime();
    },

    toast: (message, type = 'info') => {
        let container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        const icons = { success: '✓', error: '✗', warning: '⚠', info: 'ℹ' };
        const el = document.createElement('div');
        el.className = `toast toast-${type}`;
        el.innerHTML = `<span>${icons[type] || ''}</span> ${message}`;
        container.appendChild(el);
        setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; setTimeout(() => el.remove(), 300); }, 4000);
    }
};

window.COMPONENTS = COMPONENTS;
