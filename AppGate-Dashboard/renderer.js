const axios = require('axios');

const API_URL = 'http://localhost:8080/api';
let currentMode = '';

// Navigation
function showSection(sectionId) {
    document.querySelectorAll('.section').forEach(el => el.classList.remove('active'));
    document.getElementById(`${sectionId}-section`).classList.add('active');
    
    document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
    event.target.classList.add('active');

    if (sectionId === 'dashboard') updateDashboard();
    if (sectionId === 'rules') loadRules();
    if (sectionId === 'ports') loadGlobalPorts();
    if (sectionId === 'protocols') loadProtocols();
}

// Status Polling
async function checkStatus() {
    try {
        const response = await axios.get(`${API_URL}/status`);
        const statusEl = document.getElementById('connection-status');
        statusEl.textContent = 'Connected';
        statusEl.className = 'status-indicator connected';
        
        // Update global mode if changed
        if (currentMode !== response.data.mode) {
            currentMode = response.data.mode;
            updateModeUI();
        }
        return true;
    } catch (error) {
        const statusEl = document.getElementById('connection-status');
        statusEl.textContent = 'Disconnected';
        statusEl.className = 'status-indicator disconnected';
        return false;
    }
}

setInterval(checkStatus, 5000);
checkStatus();

// Dashboard
async function updateDashboard() {
    try {
        const response = await axios.get(`${API_URL}/dashboard`);
        const data = response.data;

        document.getElementById('stat-mode').textContent = data.mode.toUpperCase();
        document.getElementById('stat-total').textContent = data.total_rules;
        document.getElementById('stat-whitelist').textContent = data.whitelist_rules;
        document.getElementById('stat-blacklist').textContent = data.blacklist_rules;

    } catch (error) {
        console.error('Failed to fetch dashboard data', error);
    }
}

// Rules Manager
async function loadRules() {
    try {
        const response = await axios.get(`${API_URL}/rules`);
        const tbody = document.getElementById('rules-table-body');
        tbody.innerHTML = '';

        response.data.forEach(rule => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${rule.serial}</td>
                <td>${rule.ip}</td>
                <td><span style="color: ${rule.type === 'whitelist' ? '#4caf50' : '#f44336'}">${rule.type}</span></td>
                <td>${rule.all_ports ? rule.protocol : '-'}</td>
                <td>${rule.all_ports ? 'All' : rule.ports.join(', ')}</td>
                <td>
                    <button onclick="deleteRule('${rule.ip}')" class="btn danger" style="padding: 4px 8px; font-size: 0.8em;">Delete</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (error) {
        console.error('Failed to load rules', error);
    }
}

async function addRule() {
    const ip = document.getElementById('new-ip').value;
    const portsStr = document.getElementById('new-ports').value;
    const protocol = document.getElementById('new-protocol').value;
    
    if (!ip) return alert('IP Address is required');

    const payload = { ip: ip, protocol: protocol };
    if (portsStr.trim()) {
        payload.ports = portsStr.trim().split(/\s+/).map(p => parseInt(p)).filter(p => !isNaN(p));
        payload.all_ports = false;
    } else {
        payload.all_ports = true;
    }

    try {
        await axios.post(`${API_URL}/rules`, payload);
        document.getElementById('new-ip').value = '';
        document.getElementById('new-ports').value = '';
        loadRules();
        updateDashboard();
    } catch (error) {
        alert('Failed to add rule: ' + (error.response?.data?.error || error.message));
    }
}

async function deleteRule(ip) {
    if (!confirm(`Are you sure you want to delete rule for ${ip}?`)) return;
    
    try {
        await axios.delete(`${API_URL}/rules?ip=${ip}`);
        loadRules();
        updateDashboard();
    } catch (error) {
        alert('Failed to delete rule');
    }
}

async function clearRules() {
    if (!confirm('Are you sure you want to clear ALL rules?')) return;
    
    try {
        await axios.post(`${API_URL}/rules/clear`);
        loadRules();
        updateDashboard();
    } catch (error) {
        alert('Failed to clear rules');
    }
}

// Settings
function updateModeUI() {
    const checkbox = document.getElementById('mode-toggle-checkbox');
    const labelBlacklist = document.getElementById('label-blacklist');
    const labelWhitelist = document.getElementById('label-whitelist');
    const description = document.getElementById('mode-description');

    if (!checkbox || !labelBlacklist || !labelWhitelist) return;

    if (currentMode === 'whitelist') {
        checkbox.checked = true;
        labelWhitelist.classList.add('active');
        labelBlacklist.classList.remove('active');
        description.textContent = 'In Whitelist mode, ALL traffic is BLOCKED by default. Only rules in the list are allowed.';
        description.style.color = '#4caf50';
    } else {
        checkbox.checked = false;
        labelBlacklist.classList.add('active');
        labelWhitelist.classList.remove('active');
        description.textContent = 'In Blacklist mode, ALL traffic is ALLOWED by default. Only rules in the list are blocked.';
        description.style.color = '#ccc';
    }
}

async function toggleMode(checkbox) {
    const newMode = checkbox.checked ? 'whitelist' : 'blacklist';
    
    try {
        await axios.post(`${API_URL}/mode`, { mode: newMode });
        currentMode = newMode;
        updateModeUI();
        updateDashboard();
    } catch (error) {
        alert('Failed to change mode: ' + (error.response?.data?.error || error.message));
        // Revert UI on failure
        checkbox.checked = !checkbox.checked;
        updateModeUI();
    }
}

// Initial load
window.onload = () => {
    updateDashboard();
    updateModeUI();
};

// Expose functions to window for HTML onclick handlers
window.showSection = showSection;
window.addRule = addRule;
window.deleteRule = deleteRule;
window.clearRules = clearRules;
window.blockGlobalPort = blockGlobalPort;
window.unblockGlobalPort = unblockGlobalPort;
window.toggleProtocol = toggleProtocol;

// --- Global Port Blocker Functions ---

async function loadGlobalPorts() {
    try {
        const response = await axios.get(`${API_URL}/ports/block`);
        const data = response.data;
        const tbody = document.getElementById('global-ports-table-body');
        tbody.innerHTML = '';

        data.blocked_ports.forEach(item => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td style="padding: 10px;"><span class="badge badge-block" style="background: #ff4444; color: white; padding: 2px 6px; border-radius: 4px;">${item.port}</span></td>
                <td style="padding: 10px;">${item.protocol}</td>
                <td style="padding: 10px;">
                    <button class="btn-icon delete" onclick="unblockGlobalPort(${item.port}, '${item.protocol}')" style="background: none; border: none; cursor: pointer; font-size: 1.2em;">🗑️</button>
                </td>
            `;
            tbody.appendChild(row);
        });
    } catch (error) {
        console.error("Error loading ports:", error);
    }
}

async function blockGlobalPort() {
    const portInput = document.getElementById('global-port-input');
    const protocolInput = document.getElementById('global-port-protocol');
    const port = parseInt(portInput.value);
    const protocol = protocolInput.value;

    if (!port || isNaN(port)) {
        alert("Please enter a valid port number.");
        return;
    }

    try {
        const response = await axios.post(`${API_URL}/ports/block`, { port: port, protocol: protocol });

        if (response.status === 200) {
            portInput.value = '';
            loadGlobalPorts();
        } else {
            alert("Failed to block port.");
        }
    } catch (error) {
        console.error("Error blocking port:", error);
        alert("Error blocking port");
    }
}

async function unblockGlobalPort(port, protocol) {
    if (!confirm(`Are you sure you want to unblock port ${port} (${protocol})?`)) return;

    try {
        const response = await axios.delete(`${API_URL}/ports/block?port=${port}&protocol=${protocol}`);

        if (response.status === 200) {
            loadGlobalPorts();
        } else {
            alert("Failed to unblock port.");
        }
    } catch (error) {
        console.error("Error unblocking port:", error);
        alert("Error unblocking port");
    }
}

// --- Protocol Control Functions ---

async function loadProtocols() {
    try {
        const response = await axios.get(`${API_URL}/protocols`);
        const protocols = response.data.protocols;
        const grid = document.getElementById('protocols-grid');
        grid.innerHTML = '';

        protocols.forEach(p => {
            const card = document.createElement('div');
            card.className = 'protocol-card';
            card.innerHTML = `
                <div class="protocol-header">
                    <h3>${p.name}</h3>
                    <label class="switch small">
                        <input type="checkbox" ${p.blocked ? 'checked' : ''} onchange="toggleProtocol('${p.name}', this.checked)">
                        <span class="slider round"></span>
                    </label>
                </div>
                <div class="protocol-ports">
                    ${p.ports.length > 0 ? 'Ports: ' + p.ports.join(', ') : 'All Ports'}
                </div>
                <div class="protocol-status ${p.blocked ? 'blocked' : 'allowed'}">
                    ${p.blocked ? 'BLOCKED' : 'ALLOWED'}
                </div>
            `;
            grid.appendChild(card);
        });
    } catch (error) {
        console.error("Error loading protocols:", error);
    }
}

async function toggleProtocol(name, isBlocked) {
    try {
        if (isBlocked) {
            await axios.post(`${API_URL}/protocols/block`, { protocol: name });
        } else {
            await axios.delete(`${API_URL}/protocols/block?protocol=${name}`);
        }
        loadProtocols(); // Refresh UI
    } catch (error) {
        console.error("Error toggling protocol:", error);
        alert("Failed to update protocol status");
        loadProtocols(); // Revert UI
    }
}

window.toggleMode = toggleMode;
window.loadRules = loadRules;
