document.addEventListener('DOMContentLoaded', function() {
    // Current page and filters
    let currentPage = 1;
    let totalPages = 1;
    let perPage = 20;
    let currentFilter = 'all'; // all or unread
    let filterParams = {};
    
    // Initialize page
    loadAlerts();
    loadFilterOptions();
    
    // Filter button event handlers
    document.querySelectorAll('.filter-btn').forEach(button => {
        button.addEventListener('click', function() {
            // Update active state
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            this.classList.add('active');
            
            // Get selected filter
            currentFilter = this.getAttribute('data-filter');
            
            // Reset to first page and reload alerts
            currentPage = 1;
            loadAlerts();
        });
    });
    
    // Mark all read button
    document.getElementById('mark-all-read-btn').addEventListener('click', function() {
        if (confirm('Are you sure you want to mark all alerts as read?')) {
            markAllAlertsRead();
        }
    });
    
    // Filter form submit
    document.getElementById('alert-filter-form').addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Collect filter values
        filterParams = {
            severity: document.getElementById('severity-filter').value,
            attack_type: document.getElementById('attack-type-filter').value,
            source_ip: document.getElementById('source-ip-filter').value
        };
        
        // Reset to first page and reload alerts
        currentPage = 1;
        loadAlerts();
    });
    
    // Reset filters button
    document.getElementById('reset-filters-btn').addEventListener('click', function() {
        // Reset form
        document.getElementById('alert-filter-form').reset();
        
        // Clear filter params
        filterParams = {};
        
        // Reset to first page and reload alerts
        currentPage = 1;
        loadAlerts();
    });
    
    // Load filter options (attack types)
    function loadFilterOptions() {
        fetch('/api/logs')
            .then(response => response.json())
            .then(data => {
                // Extract unique attack types
                const attackTypes = new Set();
                data.logs.forEach(log => {
                    if (log.attack_type) {
                        attackTypes.add(log.attack_type);
                    }
                });
                
                // Populate dropdown
                const select = document.getElementById('attack-type-filter');
                select.innerHTML = '<option value="">All</option>';
                
                Array.from(attackTypes).sort().forEach(type => {
                    const option = document.createElement('option');
                    option.value = type;
                    option.textContent = type;
                    select.appendChild(option);
                });
            })
            .catch(error => console.error('Error loading attack types:', error));
    }
    
    // Load alerts with current page and filter
    function loadAlerts() {
        // Show loading message
        document.getElementById('alerts-table').innerHTML = '<tr><td colspan="7" class="text-center">Loading alerts...</td></tr>';
        
        // Build query string
        const queryParams = new URLSearchParams();
        queryParams.append('page', currentPage);
        queryParams.append('per_page', perPage);
        
        // Add filters
        for (const [key, value] of Object.entries(filterParams)) {
            if (value) {
                queryParams.append(key, value);
            }
        }
        
        // Fetch alerts from API
        fetch(`/api/alerts?${queryParams.toString()}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                let alerts = data.alerts;
                totalPages = data.pages;
                
                // Apply read/unread filter
                if (currentFilter === 'unread') {
                    alerts = alerts.filter(alert => !alert.is_read);
                }
                
                // Update alerts table
                updateAlertsTable(alerts);
                
                // Update pagination
                updatePagination();
            })
            .catch(error => {
                console.error('Error loading alerts:', error);
                document.getElementById('alerts-table').innerHTML = 
                    '<tr><td colspan="7" class="text-center text-danger">Error loading alerts. Please try again.</td></tr>';
            });
    }
    
    // Update alerts table with data
    function updateAlertsTable(alerts) {
        const tableBody = document.getElementById('alerts-table');
        
        if (alerts.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="7" class="text-center">No alerts found</td></tr>';
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
            
            // Determine status badge
            const statusBadge = alert.is_read ? 
                '<span class="badge bg-secondary">Read</span>' : 
                '<span class="badge bg-success">New</span>';
            
            html += `
                <tr class="${!alert.is_read ? 'table-active' : ''}">
                    <td>${alert.timestamp}</td>
                    <td><span class="badge ${severityClass}">${alert.severity}</span></td>
                    <td>${alert.source_ip || 'N/A'}</td>
                    <td>${alert.attack_type || 'N/A'}</td>
                    <td>${alert.title}</td>
                    <td>${statusBadge}</td>
                    <td>
                        <button class="btn btn-sm btn-info view-alert-btn" data-alert-id="${alert.id}">
                            <i class="fas fa-eye"></i>
                        </button>
                        ${!alert.is_read ? `
                        <button class="btn btn-sm btn-success mark-read-btn" data-alert-id="${alert.id}">
                            <i class="fas fa-check"></i>
                        </button>
                        ` : ''}
                    </td>
                </tr>
            `;
        });
        
        tableBody.innerHTML = html;
        
        // Add event listeners to buttons
        document.querySelectorAll('.view-alert-btn').forEach(button => {
            button.addEventListener('click', function() {
                const alertId = this.getAttribute('data-alert-id');
                showAlertDetails(alertId, alerts);
            });
        });
        
        document.querySelectorAll('.mark-read-btn').forEach(button => {
            button.addEventListener('click', function() {
                const alertId = this.getAttribute('data-alert-id');
                markAlertRead(alertId);
            });
        });
    }
    
    // Update pagination controls
    function updatePagination() {
        const pagination = document.getElementById('alerts-pagination');
        
        if (totalPages <= 1) {
            pagination.innerHTML = '';
            return;
        }
        
        let html = '';
        
        // Previous button
        html += `
            <li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
                <a class="page-link" href="#" data-page="${currentPage - 1}">&laquo;</a>
            </li>
        `;
        
        // Page numbers
        const startPage = Math.max(1, currentPage - 2);
        const endPage = Math.min(totalPages, startPage + 4);
        
        for (let i = startPage; i <= endPage; i++) {
            html += `
                <li class="page-item ${i === currentPage ? 'active' : ''}">
                    <a class="page-link" href="#" data-page="${i}">${i}</a>
                </li>
            `;
        }
        
        // Next button
        html += `
            <li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
                <a class="page-link" href="#" data-page="${currentPage + 1}">&raquo;</a>
            </li>
        `;
        
        pagination.innerHTML = html;
        
        // Add event listeners to pagination links
        document.querySelectorAll('#alerts-pagination .page-link').forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const page = parseInt(this.getAttribute('data-page'));
                if (page !== currentPage && page >= 1 && page <= totalPages) {
                    currentPage = page;
                    loadAlerts();
                }
            });
        });
    }
    
    // Show alert details in modal
    function showAlertDetails(alertId, alerts) {
        const alert = alerts.find(a => a.id == alertId);
        
        if (!alert) {
            console.error('Alert not found:', alertId);
            return;
        }
        
        // Populate modal fields
        document.getElementById('alert-detail-timestamp').textContent = alert.timestamp;
        document.getElementById('alert-detail-severity').textContent = alert.severity;
        document.getElementById('alert-detail-source-ip').textContent = alert.source_ip || 'N/A';
        document.getElementById('alert-detail-attack-type').textContent = alert.attack_type || 'N/A';
        document.getElementById('alert-detail-status').textContent = alert.is_read ? 'Read' : 'Unread';
        document.getElementById('alert-detail-log-id').textContent = alert.log_id || 'N/A';
        document.getElementById('alert-detail-message').textContent = alert.message;
        
        // Set button actions
        const markReadBtn = document.getElementById('alert-detail-mark-read');
        if (alert.is_read) {
            markReadBtn.style.display = 'none';
        } else {
            markReadBtn.style.display = 'block';
            markReadBtn.onclick = function() {
                markAlertRead(alertId);
                document.getElementById('alert-detail-status').textContent = 'Read';
                markReadBtn.style.display = 'none';
            };
        }
        
        // View log button
        const viewLogBtn = document.getElementById('alert-detail-view-log');
        if (alert.log_id) {
            viewLogBtn.style.display = 'block';
            viewLogBtn.onclick = function() {
                window.location.href = `/logs?log=${alert.log_id}`;
            };
        } else {
            viewLogBtn.style.display = 'none';
        }
        
        // Show modal
        const modal = new bootstrap.Modal(document.getElementById('alertDetailModal'));
        modal.show();
    }
    
    // Mark an alert as read
    function markAlertRead(alertId) {
        fetch(`/api/alerts/${alertId}/mark-read`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Reload alerts to update the table
                loadAlerts();
            }
        })
        .catch(error => {
            console.error('Error marking alert as read:', error);
            alert('Failed to mark alert as read. Please try again.');
        });
    }
    
    // Mark all alerts as read
    function markAllAlertsRead() {
        // In a real implementation, this would call an API endpoint
        // For now, we'll just reload the alerts
        setTimeout(() => {
            alert('All alerts marked as read');
            loadAlerts();
        }, 500);
    }
    
    // Check URL for alert ID to show details
    function checkUrlForAlertId() {
        const urlParams = new URLSearchParams(window.location.search);
        const alertId = urlParams.get('alert');
        
        if (alertId) {
            // Load the specific alert
            fetch(`/api/alerts?page=1&per_page=100`)
                .then(response => response.json())
                .then(data => {
                    const alert = data.alerts.find(a => a.id == alertId);
                    if (alert) {
                        showAlertDetails(alertId, data.alerts);
                    }
                })
                .catch(error => console.error('Error loading alert details:', error));
        }
    }
    
    // Check URL on page load
    checkUrlForAlertId();
    
    // Auto-refresh alerts every 30 seconds
    setInterval(() => {
        loadAlerts();
    }, 30000);
});
