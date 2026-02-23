// static/js/dashboard.js

$(document).ready(function() {
    // Initialize tooltips
    $('[data-toggle="tooltip"]').tooltip();

    // Start auto-refresh for live data
    startAutoRefresh();

    // Check evolution status
    checkEvolutionStatus();

    // Initialize event handlers
    initializeEventHandlers();
});

// Auto-refresh function
function startAutoRefresh(interval = 30000) {
    setInterval(function() {
        refreshDashboardData();
    }, interval);
}

// Refresh dashboard data
function refreshDashboardData() {
    showLoading();

    $.get('/api/stats/refresh', function(data) {
        updateStats(data.stats);
        updateMetrics(data.metrics);
        hideLoading();
    }).fail(function() {
        hideLoading();
        showNotification('Failed to refresh data', 'error');
    });
}

// Update statistics cards
function updateStats(stats) {
    $('#total-events').text(stats.total_events.toLocaleString());
    $('#anomaly-count').text(stats.anomalies.toLocaleString());
    $('#active-rules').text(stats.active_rules);
    $('#evolution-cycles').text(stats.evolution_cycles);
    $('#last-update').text(stats.last_update);
}

// Update performance metrics
function updateMetrics(metrics) {
    if (!metrics) return;

    $('#detection-rate').text(metrics.detection_rate + '%');
    $('#false-positive-rate').text(metrics.false_positive_rate + '%');
    $('#f1-score').text(metrics.f1_score);

    // Update progress bars
    $('#detection-progress').css('width', metrics.detection_rate + '%');
}

// Run anomaly detection
function runAnomalyDetection() {
    if (!confirm('Run anomaly detection? This may take a few minutes.')) return;

    showLoading('Running anomaly detection...');

    $.post('/api/run/anomaly', function(response) {
        hideLoading();
        if (response.success) {
            showNotification('Anomaly detection completed successfully', 'success');
            setTimeout(function() {
                location.reload();
            }, 2000);
        } else {
            showNotification('Error: ' + response.message, 'error');
        }
    }).fail(function() {
        hideLoading();
        showNotification('Failed to start anomaly detection', 'error');
    });
}

// Run rule generation
function runRuleGeneration() {
    if (!confirm('Generate new rules from anomalies?')) return;

    showLoading('Generating rules...');

    $.post('/api/run/rules', function(response) {
        hideLoading();
        if (response.success) {
            showNotification('Rules generated successfully', 'success');
            setTimeout(function() {
                location.reload();
            }, 2000);
        } else {
            showNotification('Error: ' + response.message, 'error');
        }
    }).fail(function() {
        hideLoading();
        showNotification('Failed to generate rules', 'error');
    });
}

// Run evolution cycle
function runEvolution() {
    if (!confirm('Start evolution cycle? This will run anomaly detection and rule generation.')) return;

    showLoading('Starting evolution cycle...');

    $.post('/api/run/evolve', function(response) {
        hideLoading();
        if (response.success) {
            showNotification('Evolution cycle started in background', 'success');
            checkEvolutionStatus();
        } else {
            showNotification('Error: ' + response.message, 'error');
        }
    }).fail(function() {
        hideLoading();
        showNotification('Failed to start evolution', 'error');
    });
}

// Check evolution status
function checkEvolutionStatus() {
    $.get('/api/status/evolution', function(data) {
        if (data.running) {
            $('#evolution-status').html('<span class="text-warning"><i class="fas fa-sync fa-spin"></i> Evolution Running</span>');
            setTimeout(checkEvolutionStatus, 5000);
        } else {
            $('#evolution-status').html('<span class="text-success"><i class="fas fa-check-circle"></i> Evolution Idle</span>');
        }
    });
}

// Show loading overlay
function showLoading(message = 'Loading...') {
    $('.spinner-overlay').fadeIn();
    $('.spinner-overlay .message').text(message);
}

// Hide loading overlay
function hideLoading() {
    $('.spinner-overlay').fadeOut();
}

// Show notification
function showNotification(message, type = 'info') {
    var icon = {
        'success': 'fa-check-circle',
        'error': 'fa-exclamation-circle',
        'warning': 'fa-exclamation-triangle',
        'info': 'fa-info-circle'
    }[type] || 'fa-info-circle';

    var notification = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            <i class="fas ${icon}"></i> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;

    $('#notification-area').html(notification);

    // Auto dismiss after 5 seconds
    setTimeout(function() {
        $('.alert').fadeOut();
    }, 5000);
}

// Export data
function exportData(type) {
    var filename = type + '_' + new Date().toISOString().slice(0,10) + '.csv';
    window.location.href = '/api/export/' + type + '?filename=' + filename;
}

// Filter table
function filterTable(inputId, tableId) {
    var input = document.getElementById(inputId);
    var filter = input.value.toUpperCase();
    var table = document.getElementById(tableId);
    var tr = table.getElementsByTagName('tr');

    for (var i = 0; i < tr.length; i++) {
        var td = tr[i].getElementsByTagName('td');
        var found = false;

        for (var j = 0; j < td.length; j++) {
            if (td[j] && td[j].innerHTML.toUpperCase().indexOf(filter) > -1) {
                found = true;
                break;
            }
        }

        if (found || i === 0) {
            tr[i].style.display = '';
        } else {
            tr[i].style.display = 'none';
        }
    }
}

// Sort table
function sortTable(tableId, column) {
    var table = document.getElementById(tableId);
    var switching = true;
    var direction = 'asc';

    while (switching) {
        switching = false;
        var rows = table.rows;

        for (var i = 1; i < (rows.length - 1); i++) {
            var shouldSwitch = false;
            var x = rows[i].getElementsByTagName('TD')[column];
            var y = rows[i + 1].getElementsByTagName('TD')[column];

            if (direction == 'asc') {
                if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                    shouldSwitch = true;
                    break;
                }
            } else {
                if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                    shouldSwitch = true;
                    break;
                }
            }
        }

        if (shouldSwitch) {
            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
            switching = true;
        } else {
            if (direction == 'asc') {
                direction = 'desc';
                switching = true;
            }
        }
    }
}

// Initialize event handlers
function initializeEventHandlers() {
    // Search inputs
    $('.search-input').on('keyup', function() {
        var tableId = $(this).data('table');
        filterTable(this.id, tableId);
    });

    // Sort buttons
    $('.sort-btn').on('click', function() {
        var tableId = $(this).data('table');
        var column = $(this).data('column');
        sortTable(tableId, column);
    });

    // Export buttons
    $('.export-btn').on('click', function() {
        var type = $(this).data('type');
        exportData(type);
    });
}

// Chart resize handler
$(window).on('resize', function() {
    if (typeof Plotly !== 'undefined') {
        Plotly.Plots.resize();
    }
});

// Handle errors
$(document).ajaxError(function(event, jqxhr, settings, error) {
    hideLoading();
    showNotification('AJAX Error: ' + error, 'error');
    console.error('AJAX Error:', settings.url, error);
});

// Keyboard shortcuts
$(document).on('keydown', function(e) {
    // Ctrl+R - Refresh dashboard
    if (e.ctrlKey && e.key === 'r') {
        e.preventDefault();
        refreshDashboardData();
    }

    // Ctrl+A - Run anomaly detection
    if (e.ctrlKey && e.key === 'a') {
        e.preventDefault();
        runAnomalyDetection();
    }

    // Ctrl+G - Generate rules
    if (e.ctrlKey && e.key === 'g') {
        e.preventDefault();
        runRuleGeneration();
    }
});

// Prevent accidental navigation
window.onbeforeunload = function() {
    if (evolutionRunning) {
        return 'Evolution is running. Are you sure you want to leave?';
    }
};