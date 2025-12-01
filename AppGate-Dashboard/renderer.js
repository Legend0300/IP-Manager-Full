const axios = require('axios');
const Chart = require('chart.js/auto');

const API_URL = 'http://localhost:8080/api';
let rulesChart = null;
let currentMode = '';

// Navigation
function showSection(sectionId) {
    document.querySelectorAll('.section').forEach(el => el.classList.remove('active'));
    document.getElementById(`${sectionId}-section`).classList.add('active');
    
    document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
    event.target.classList.add('active');

    if (sectionId === 'dashboard') updateDashboard();
    if (sectionId === 'rules') loadRules();
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

        updateChart(data);
    } catch (error) {
        console.error('Failed to fetch dashboard data', error);
    }
}

function updateChart(data) {
    const ctx = document.getElementById('rulesChart').getContext('2d');
    
    if (rulesChart) {
        rulesChart.destroy();
    }

    rulesChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Whitelist Rules', 'Blacklist Rules'],
            datasets: [{
                data: [data.whitelist_rules, data.blacklist_rules],
                backgroundColor: ['#4caf50', '#f44336'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#fff' }
                }
            }
        }
    });
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
    
    if (!ip) return alert('IP Address is required');

    const payload = { ip: ip };
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
window.toggleMode = toggleMode;
window.loadRules = loadRules;
