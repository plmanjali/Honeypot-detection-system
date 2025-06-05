document.addEventListener('DOMContentLoaded', function() {
    // Chart.js global defaults for dark theme
    Chart.defaults.color = '#f8f9fa';
    Chart.defaults.borderColor = '#495057';
    
    // References to charts
    let attackTypesChart = null;
    let sourceIpsChart = null;
    
    // Load reports on page load
    loadReports();
    
    // Generate report button
    document.getElementById('generate-report-btn').addEventListener('click', function() {
        // Show the modal
        const modal = new bootstrap.Modal(document.getElementById('generateReportModal'));
        modal.show();
    });
    
    // Report type change handler (show/hide custom date range)
    document.getElementById('report-type').addEventListener('change', function() {
        const customDateRange = document.getElementById('custom-date-range');
        if (this.value === 'custom') {
            customDateRange.style.display = 'block';
        } else {
            customDateRange.style.display = 'none';
        }
    });
    
    // Generate report form submit
    document.getElementById('generate-report-submit').addEventListener('click', function() {
        const title = document.getElementById('report-title').value;
        const reportType = document.getElementById('report-type').value;
        
        // Validate form
        if (!title) {
            alert('Please enter a report title');
            return;
        }
        
        // Build request data
        const data = {
            title: title,
            report_type: reportType
        };
        
        // Add custom date range if selected
        if (reportType === 'custom') {
            const startDate = document.getElementById('report-start-date').value;
            const endDate = document.getElementById('report-end-date').value;
            
            if (!startDate || !endDate) {
                alert('Please select start and end dates');
                return;
            }
            
            data.start_date = startDate;
            data.end_date = endDate;
        }
        
        // Show loading state
        document.getElementById('generate-report-submit').textContent = 'Generating...';
        document.getElementById('generate-report-submit').disabled = true;
        
        // Send request to generate report
        fetch('/api/reports/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Hide modal
                const modal = bootstrap.Modal.getInstance(document.getElementById('generateReportModal'));
                modal.hide();
                
                // Reset form
                document.getElementById('generate-report-form').reset();
                document.getElementById('custom-date-range').style.display = 'none';
                
                // Show success message
                alert('Report generated successfully!');
                
                // Reload reports list
                loadReports();
                
                // Show the generated report
                showReportDetails(data.report.id);
            }
        })
        .catch(error => {
            console.error('Error generating report:', error);
            alert('Failed to generate report. Please try again.');
        })
        .finally(() => {
            // Reset button state
            document.getElementById('generate-report-submit').textContent = 'Generate';
            document.getElementById('generate-report-submit').disabled = false;
        });
    });
    
    // Close report button
    document.getElementById('close-report-btn').addEventListener('click', function() {
        document.getElementById('report-detail-section').style.display = 'none';
    });
    
    // Load reports list
    function loadReports() {
        // Show loading message
        document.getElementById('reports-table').innerHTML = '<tr><td colspan="6" class="text-center">Loading reports...</td></tr>';
        
        // Fetch reports from API
        fetch('/api/reports')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                updateReportsTable(data.reports);
            })
            .catch(error => {
                console.error('Error loading reports:', error);
                document.getElementById('reports-table').innerHTML = 
                    '<tr><td colspan="6" class="text-center text-danger">Error loading reports. Please try again.</td></tr>';
            });
    }
    
    // Update reports table with data
    function updateReportsTable(reports) {
        const tableBody = document.getElementById('reports-table');
        
        if (reports.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="6" class="text-center">No reports available</td></tr>';
            return;
        }
        
        let html = '';
        reports.forEach(report => {
            // Format date range
            let dateRange = 'N/A';
            if (report.start_date && report.end_date) {
                dateRange = `${formatDate(report.start_date)} to ${formatDate(report.end_date)}`;
            }
            
            html += `
                <tr>
                    <td>${report.title}</td>
                    <td>${report.report_type}</td>
                    <td>${dateRange}</td>
                    <td>${formatDate(report.created_at)}</td>
                    <td>${report.attack_count}</td>
                    <td>
                        <button class="btn btn-sm btn-info view-report-btn" data-report-id="${report.id}">
                            <i class="fas fa-eye"></i> View
                        </button>
                    </td>
                </tr>
            `;
        });
        
        tableBody.innerHTML = html;
        
        // Add event listeners to view buttons
        document.querySelectorAll('.view-report-btn').forEach(button => {
            button.addEventListener('click', function() {
                const reportId = this.getAttribute('data-report-id');
                showReportDetails(reportId);
            });
        });
    }
    
    // Show report details
    function showReportDetails(reportId) {
        // Fetch report details
        fetch(`/api/reports/${reportId}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                const report = data.report;
                if (!report) {
                    throw new Error('Report not found');
                }
                
                // Update report title
                document.getElementById('report-detail-title').textContent = report.title;
                
                // Update summary
                document.getElementById('report-detail-summary').textContent = report.summary;
                
                // Parse JSON data
                let attackTypes = [];
                let sourceIps = [];
                
                try {
                    if (report.top_attack_types) {
                        attackTypes = JSON.parse(report.top_attack_types);
                    }
                    if (report.top_source_ips) {
                        sourceIps = JSON.parse(report.top_source_ips);
                    }
                } catch (e) {
                    console.error('Error parsing report data:', e);
                }
                
                // Update attack types table and chart
                updateAttackTypesTable(attackTypes, report.attack_count);
                updateAttackTypesChart(attackTypes);
                
                // Update source IPs table and chart
                updateSourceIpsTable(sourceIps, report.attack_count);
                updateSourceIpsChart(sourceIps);
                
                // Show the report section
                document.getElementById('report-detail-section').style.display = 'block';
                
                // Scroll to report section
                document.getElementById('report-detail-section').scrollIntoView({ behavior: 'smooth' });
            })
            .catch(error => {
                console.error('Error loading report details:', error);
                alert('Failed to load report details. Please try again.');
            });
    }
    
    // Update attack types table
    function updateAttackTypesTable(attackTypes, totalAttacks) {
        const tableBody = document.getElementById('report-attack-types-table');
        
        if (attackTypes.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="3" class="text-center">No attack type data available</td></tr>';
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
    function updateSourceIpsTable(sourceIps, totalAttacks) {
        const tableBody = document.getElementById('report-source-ips-table');
        
        if (sourceIps.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="3" class="text-center">No source IP data available</td></tr>';
            return;
        }
        
        let html = '';
        sourceIps.forEach(item => {
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
    
    // Update attack types chart
    function updateAttackTypesChart(attackTypes) {
        const ctx = document.getElementById('attack-types-chart').getContext('2d');
        
        // Extract data
        const labels = attackTypes.map(item => item.name || 'Unknown');
        const data = attackTypes.map(item => item.count);
        
        // Generate colors
        const backgroundColors = generateChartColors(attackTypes.length);
        
        // Destroy existing chart if it exists
        if (attackTypesChart) {
            attackTypesChart.destroy();
        }
        
        // Create new chart
        attackTypesChart = new Chart(ctx, {
            type: 'pie',
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
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            boxWidth: 12
                        }
                    }
                }
            }
        });
    }
    
    // Update source IPs chart
    function updateSourceIpsChart(sourceIps) {
        const ctx = document.getElementById('source-ips-chart').getContext('2d');
        
        // Extract data
        const labels = sourceIps.map(item => item.ip);
        const data = sourceIps.map(item => item.count);
        
        // Generate colors
        const backgroundColors = generateChartColors(sourceIps.length, true);
        
        // Destroy existing chart if it exists
        if (sourceIpsChart) {
            sourceIpsChart.destroy();
        }
        
        // Create new chart
        sourceIpsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Attack Count',
                    data: data,
                    backgroundColor: backgroundColors,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
    }
    
    // Generate chart colors
    function generateChartColors(count, blue = false) {
        const colors = [];
        
        if (blue) {
            // Generate shades of blue
            for (let i = 0; i < count; i++) {
                const hue = 210; // Blue
                const saturation = 100;
                const lightness = 50 - (i * 40 / count);
                colors.push(`hsl(${hue}, ${saturation}%, ${lightness}%)`);
            }
        } else {
            // Generate colorful palette
            for (let i = 0; i < count; i++) {
                const hue = (i * 360 / count) % 360;
                const saturation = 75;
                const lightness = 60;
                colors.push(`hsl(${hue}, ${saturation}%, ${lightness}%)`);
            }
        }
        
        return colors;
    }
    
    // Format date for display
    function formatDate(dateString) {
        if (!dateString) return 'N/A';
        
        const date = new Date(dateString);
        return date.toLocaleString();
    }
    
    // Set default date values for custom report
    function setDefaultDateValues() {
        const now = new Date();
        const lastMonth = new Date();
        lastMonth.setMonth(now.getMonth() - 1);
        
        document.getElementById('report-start-date').value = formatDateInput(lastMonth);
        document.getElementById('report-end-date').value = formatDateInput(now);
    }
    
    // Format date for input fields (YYYY-MM-DD)
    function formatDateInput(date) {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    }
    
    // Initialize date inputs
    setDefaultDateValues();
});
