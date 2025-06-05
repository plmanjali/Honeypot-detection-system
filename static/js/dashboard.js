document.addEventListener('DOMContentLoaded', function() {
    // Chart.js global defaults for dark theme
    Chart.defaults.color = '#f8f9fa';
    Chart.defaults.borderColor = '#495057';
    
    // References to chart elements
    let attackTimelineChart = null;
    let attackSeverityChart = null;
    
    // Current time range
    let currentTimeRange = 'day';
    
    // Initialize dashboard
    loadDashboardData(currentTimeRange);
    
    // Time range selector event handlers
    document.querySelectorAll('.time-range-btn').forEach(button => {
        button.addEventListener('click', function() {
            // Update active state
            document.querySelectorAll('.time-range-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            this.classList.add('active');
            
            // Get selected time range
            const timeRange = this.getAttribute('data-range');
            currentTimeRange = timeRange;
            
            // Reload dashboard data
            loadDashboardData(timeRange);
        });
    });
    
    // Load dashboard data from API
    function loadDashboardData(timeRange) {
        fetch(`/api/dashboard/stats?range=${timeRange}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                updateDashboardStats(data.stats);
                updateRecentAlerts(data.recent_alerts);
            })
            .catch(error => {
                console.error('Error loading dashboard data:', error);
                displayErrorMessage('Failed to load dashboard data. Please try again.');
            });
    }
    
    // Update dashboard statistics
    function updateDashboardStats(stats) {
        // Update count cards
        document.getElementById('total-attacks').textContent = stats.total_attacks;
        
        const criticalHighCount = (stats.severity.critical || 0) + (stats.severity.high || 0);
        document.getElementById('critical-count').textContent = criticalHighCount;
        
        document.getElementById('alerts-count').textContent = stats.alerts_count;
        
        // Update attack types table
        updateAttackTypesTable(stats.attack_types);
        
        // Update source IPs table
        updateSourceIPsTable(stats.source_ips);
        
        // Update charts
        updateAttackTimelineChart(stats.time_series);
        updateAttackSeverityChart(stats.severity);
    }
    
    // Update attack types table
    function updateAttackTypesTable(attackTypes) {
        const tableBody = document.getElementById('attack-types-table');
        const totalAttacks = attackTypes.reduce((sum, item) => sum + item.count, 0);
        
        if (attackTypes.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="3" class="text-center">No attack data available</td></tr>';
            return;
        }
        
        let html = '';
        attackTypes.forEach(item => {
            const percentage = totalAttacks > 0 ? ((item.count / totalAttacks) * 100).toFixed(1) : 0;
            html += `
                <tr>
                    <td>${item.name || 'Unknown'}</td>
                    <td>${item.count}</td>
                    <td>${percentage}%</td>
                </tr>
            `;
        });
        
        tableBody.innerHTML = html;
    }
    
    // Update source IPs table
    function updateSourceIPsTable(sourceIPs) {
        const tableBody = document.getElementById('source-ips-table');
        const totalAttacks = sourceIPs.reduce((sum, item) => sum + item.count, 0);
        
        if (sourceIPs.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="3" class="text-center">No source IP data available</td></tr>';
            return;
        }
        
        let html = '';
        sourceIPs.forEach(item => {
            const percentage = totalAttacks > 0 ? ((item.count / totalAttacks) * 100).toFixed(1) : 0;
            html += `
                <tr>
                    <td>${item.ip}</td>
                    <td>${item.count}</td>
                    <td>${percentage}%</td>
                </tr>
            `;
        });
        
        tableBody.innerHTML = html;
    }
    
    // Update recent alerts table
    function updateRecentAlerts(alerts) {
        const tableBody = document.getElementById('recent-alerts-table');
        
        if (alerts.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="6" class="text-center">No recent alerts</td></tr>';
            return;
        }
        
        let html = '';
        alerts.forEach(alert => {
            // Determine severity class
            let severityClass = '';
            switch (alert.severity) {
                case 'critical':
                    severityClass = 'bg-danger';
                    break;
                case 'high':
                    severityClass = 'bg-warning text-dark';
                    break;
                case 'medium':
                    severityClass = 'bg-info text-dark';
                    break;
                case 'low':
                    severityClass = 'bg-secondary';
                    break;
            }
            
            html += `
                <tr>
                    <td>${alert.timestamp}</td>
                    <td><span class="badge ${severityClass}">${alert.severity}</span></td>
                    <td>${alert.source_ip || 'N/A'}</td>
                    <td>${alert.attack_type || 'N/A'}</td>
                    <td>${alert.title}</td>
                    <td>
                        <button class="btn btn-sm btn-info view-alert-btn" data-alert-id="${alert.id}">
                            <i class="fas fa-eye"></i>
                        </button>
                    </td>
                </tr>
            `;
        });
        
        tableBody.innerHTML = html;
        
        // Add event listeners to view buttons
        document.querySelectorAll('.view-alert-btn').forEach(button => {
            button.addEventListener('click', function() {
                const alertId = this.getAttribute('data-alert-id');
                window.location.href = `/alerts?alert=${alertId}`;
            });
        });
    }
    
    // Update attack timeline chart
    function updateAttackTimelineChart(timeSeriesData) {
        const ctx = document.getElementById('attack-timeline-chart').getContext('2d');
        
        // Extract labels and data
        const labels = timeSeriesData.map(item => item.time);
        const data = timeSeriesData.map(item => item.count);
        
        // Destroy existing chart if it exists
        if (attackTimelineChart) {
            attackTimelineChart.destroy();
        }
        
        // Create new chart
        attackTimelineChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Attack Count',
                    data: data,
                    borderColor: '#0d6efd',
                    backgroundColor: 'rgba(13, 110, 253, 0.2)',
                    tension: 0.2,
                    borderWidth: 2,
                    fill: true,
                    pointBackgroundColor: '#0d6efd',
                    pointRadius: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: true
                        },
                        ticks: {
                            maxRotation: 45,
                            minRotation: 45
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: {
                            display: true
                        },
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
    }
    
    // Update attack severity chart
    function updateAttackSeverityChart(severityData) {
        const ctx = document.getElementById('attack-severity-chart').getContext('2d');
        
        // Extract data
        const labels = Object.keys(severityData);
        const data = Object.values(severityData);
        
        // Define colors for severity levels
        const backgroundColors = [
            '#dc3545', // critical - danger
            '#ffc107', // high - warning
            '#0dcaf0', // medium - info
            '#6c757d'  // low - secondary
        ];
        
        // Destroy existing chart if it exists
        if (attackSeverityChart) {
            attackSeverityChart.destroy();
        }
        
        // Create new chart
        attackSeverityChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: backgroundColors,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
    }
    
    // Display error message
    function displayErrorMessage(message) {
        // You can implement a more sophisticated error display if needed
        console.error(message);
    }
    
    // Auto-refresh dashboard every 60 seconds
    setInterval(() => {
        loadDashboardData(currentTimeRange);
    }, 60000);
});
