/**
 * Enhanced Spam Detective Frontend Script
 * 
 * File: assets/script.js
 */

jQuery(document).ready(function($) {
    let suspiciousUsers = [];
    let selectedUsers = [];
    
    // Analysis Functions
    $('#analyze-users, #quick-scan').click(function() {
        const isQuickScan = $(this).attr('id') === 'quick-scan';
        startAnalysis(isQuickScan);
    });
    
    // Clear cache
    $('#clear-cache, #clear-all-cache').click(function() {
        // Clear transients by making a simple AJAX call
        $.ajax({
            url: spamDetective.ajaxUrl,
            type: 'POST',
            data: {
                action: 'clear_spam_cache',
                nonce: spamDetective.nonce
            },
            success: function(response) {
                alert('Cache cleared successfully. Next analysis will be slower but more accurate.');
            }
        });
    });
    
    function startAnalysis(isQuickScan) {
        $('#analysis-progress').show();
        $('.progress-fill').css('width', '0%');
        $('#results-container').hide();
        
        // Simulate progress animation
        animateProgress();
        
        $.ajax({
            url: spamDetective.ajaxUrl,
            type: 'POST',
            data: {
                action: 'analyze_spam_users',
                quick_scan: isQuickScan,
                nonce: spamDetective.nonce
            },
            success: function(response) {
                $('#analysis-progress').hide();
                if (response.success) {
                    suspiciousUsers = response.data.users;
                    displayResults();
                    $('#results-container').show();
                } else {
                    alert('Error: ' + response.data);
                }
            },
            error: function() {
                $('#analysis-progress').hide();
                alert('An error occurred during analysis. Please try again.');
            }
        });
    }
    
    function animateProgress() {
        let progress = 0;
        const interval = setInterval(() => {
            progress += Math.random() * 15;
            if (progress > 90) progress = 90;
            $('.progress-fill').css('width', progress + '%');
            if (progress >= 90) {
                clearInterval(interval);
            }
        }, 200);
    }
    
    function generateRiskFactorTags(reasons) {
        if (!reasons || reasons.length === 0) {
            return '<em>No factors detected</em>';
        }
        
        // Define high priority risk factors
        const highPriorityFactors = [
            'Known spam domain',
            'No display name', 
            'Suspicious username pattern (multiple dots)',
            'Mass registration burst',
            'Bulk registration'
        ];
        
        // Define medium priority risk factors  
        const mediumPriorityFactors = [
            'Suspicious username pattern',
            'Random username',
            'Generic email pattern',
            'Suspicious domain extension',
            'Common spam username pattern',
            'Fake name used',
            'Sequential username pattern'
        ];
        
        let tags = '';
        reasons.forEach(reason => {
            let tagClass = 'risk-factor-tag';
            
            // Check if this reason matches high priority patterns
            const isHighPriority = highPriorityFactors.some(pattern => 
                reason.toLowerCase().includes(pattern.toLowerCase())
            );
            
            // Check if this reason matches medium priority patterns
            const isMediumPriority = mediumPriorityFactors.some(pattern => 
                reason.toLowerCase().includes(pattern.toLowerCase())
            );
            
            if (isHighPriority) {
                tagClass += ' high-priority';
            } else if (isMediumPriority) {
                tagClass += ' medium-priority';
            }
            
            tags += `<span class="${tagClass}" title="${escapeHtml(reason)}">${escapeHtml(reason)}</span> `;
        });
        
        return tags;
    }
    
    function displayResults() {
        const highConfidence = suspiciousUsers.filter(u => u.risk_level === 'high').length;
        const suspiciousDomains = new Set(suspiciousUsers.map(u => u.email.split('@')[1])).size;
        const protectedUsers = suspiciousUsers.filter(u => !u.can_delete).length;
        
        $('#total-suspicious').text(suspiciousUsers.length);
        $('#high-confidence').text(highConfidence);
        $('#suspicious-domains').text(suspiciousDomains);
        $('#protected-users').text(protectedUsers);
        $('#displaying-num').text(suspiciousUsers.length + ' items');
        
        let html = '';
        suspiciousUsers.forEach(user => {
            const riskClass = 'risk-' + user.risk_level;
            const emailDomain = user.email.split('@')[1];
            const statusIcon = getStatusIcon(user);
            const statusClass = getStatusClass(user);
            const riskFactorTags = generateRiskFactorTags(user.reasons);
            
            html += `
                <tr data-user-id="${user.id}" class="${statusClass}">
                    <td><input type="checkbox" class="user-checkbox" value="${user.id}" ${!user.can_delete ? 'disabled' : ''}></td>
                    <td>${statusIcon}</td>
                    <td><span class="risk-level ${riskClass}">${user.risk_level}</span></td>
                    <td><strong>${escapeHtml(user.username)}</strong></td>
                    <td>${escapeHtml(user.email)}</td>
                    <td>${user.display_name ? escapeHtml(user.display_name) : '<em>None</em>'}</td>
                    <td>${user.registered}</td>
                    <td class="risk-factors">${riskFactorTags}</td>
                    <td>
                        <button class="button button-small delete-single" data-user-id="${user.id}" ${!user.can_delete ? 'disabled' : ''}>Delete</button>
                        <button class="button button-small whitelist-domain" data-domain="${emailDomain}">Whitelist Domain</button>
                    </td>
                </tr>
            `;
        });
        $('#suspicious-users-list').html(html);
        
        // Reset selections when results change
        selectedUsers = [];
        $('#select-all-checkbox').prop('checked', false).prop('indeterminate', false);
        updateSelectedCount();
    }
    
    function getStatusIcon(user) {
        if (!user.can_delete) {
            if (user.roles.includes('administrator') || user.roles.includes('editor') || user.roles.includes('shop_manager')) {
                return '<span class="status-icon protected-role" title="Protected Role">🛡️</span>';
            }
            return '<span class="status-icon protected" title="Protected User">🔒</span>';
        }
        if (user.has_orders) {
            return '<span class="status-icon has-orders" title="Has WooCommerce Orders">🛒</span>';
        }
        return '<span class="status-icon deletable" title="Can be deleted">⚠️</span>';
    }
    
    function getStatusClass(user) {
        if (!user.can_delete) return 'protected-user';
        if (user.has_orders) return 'user-with-orders';
        return 'deletable-user';
    }
    
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    // Checkbox Handling
    $(document).on('change', '.user-checkbox', updateSelectedCount);
    
    $('#select-all-checkbox').change(function() {
        $('.user-checkbox:not(:disabled)').prop('checked', this.checked);
        updateSelectedCount();
    });
    
    $('#select-all-high').click(function() {
        $('.user-checkbox').prop('checked', false);
        suspiciousUsers.forEach(user => {
            if (user.risk_level === 'high' && user.can_delete) {
                $(`.user-checkbox[value="${user.id}"]`).prop('checked', true);
            }
        });
        updateSelectedCount();
    });
    
    $('#select-all-deletable').click(function() {
        $('.user-checkbox').prop('checked', false);
        suspiciousUsers.forEach(user => {
            if (user.can_delete && !user.has_orders) {
                $(`.user-checkbox[value="${user.id}"]`).prop('checked', true);
            }
        });
        updateSelectedCount();
    });
    
    $('#select-all-suspicious').click(function() {
        $('.user-checkbox:not(:disabled)').prop('checked', true);
        updateSelectedCount();
    });
    
    function updateSelectedCount() {
        selectedUsers = $('.user-checkbox:checked').map(function() {
            return this.value;
        }).get();
        $('#selected-count').text(selectedUsers.length + ' selected');
        
        // Update select all checkbox state
        const totalEnabledCheckboxes = $('.user-checkbox:not(:disabled)').length;
        const checkedCheckboxes = $('.user-checkbox:checked').length;
        
        if (checkedCheckboxes === 0) {
            $('#select-all-checkbox').prop('indeterminate', false).prop('checked', false);
        } else if (checkedCheckboxes === totalEnabledCheckboxes) {
            $('#select-all-checkbox').prop('indeterminate', false).prop('checked', true);
        } else {
            $('#select-all-checkbox').prop('indeterminate', true);
        }
    }
    
    // Delete Functions
    $('#delete-selected').click(function() {
        if (selectedUsers.length === 0) {
            alert('Please select users to delete.');
            return;
        }
        
        const forceDelete = $('#force-delete-checkbox').is(':checked');
        deleteUsers(selectedUsers, forceDelete);
    });
    
    $(document).on('click', '.delete-single', function() {
        const userId = $(this).data('user-id');
        deleteUsers([userId], true);
    });
    
    function deleteUsers(userIds, forceDelete = false) {
        $.ajax({
            url: spamDetective.ajaxUrl,
            type: 'POST',
            data: {
                action: 'delete_spam_users',
                user_ids: userIds,
                force_delete: forceDelete,
                nonce: spamDetective.nonce
            },
            success: function(response) {
                if (response.success) {
                    alert(response.data.message || `Successfully deleted ${response.data.deleted} users.`);
                    // Remove deleted users from display
                    userIds.forEach(id => {
                        $(`tr[data-user-id="${id}"]`).remove();
                    });
                    // Update arrays and counters
                    suspiciousUsers = suspiciousUsers.filter(u => !userIds.includes(u.id.toString()));
                    displayResults();
                } else {
                    alert('Error deleting users: ' + response.data);
                }
            },
            error: function() {
                alert('An error occurred while deleting users. Please try again.');
            }
        });
    }
    
    // Export Functions
    $('#export-selected').click(function() {
        if (selectedUsers.length === 0) {
            alert('Please select users to export.');
            return;
        }
        exportUsers(selectedUsers);
    });
    
    $('#export-all').click(function() {
        if (suspiciousUsers.length === 0) {
            alert('No users to export.');
            return;
        }
        const allUserIds = suspiciousUsers.map(u => u.id.toString());
        exportUsers(allUserIds);
    });
    
    function exportUsers(userIds) {
        $.ajax({
            url: spamDetective.ajaxUrl,
            type: 'POST',
            data: {
                action: 'export_suspicious_users',
                user_ids: userIds,
                nonce: spamDetective.nonce
            },
            success: function(response) {
                if (response.success) {
                    downloadFile(response.data.content, response.data.filename, 'text/csv');
                    alert(`Exported ${userIds.length} users successfully.`);
                } else {
                    alert('Error exporting users: ' + response.data);
                }
            },
            error: function() {
                alert('An error occurred while exporting users. Please try again.');
            }
        });
    }
    
    // Import/Export Domain Lists
    $('#export-domains').click(function() {
        $.ajax({
            url: spamDetective.ajaxUrl,
            type: 'POST',
            data: {
                action: 'export_domain_lists',
                nonce: spamDetective.nonce
            },
            success: function(response) {
                if (response.success) {
                    downloadFile(response.data.content, response.data.filename, 'application/json');
                    alert('Domain lists exported successfully.');
                } else {
                    alert('Error exporting domain lists: ' + response.data);
                }
            },
            error: function() {
                alert('An error occurred while exporting domain lists. Please try again.');
            }
        });
    });
    
    $('#import-domains').click(function() {
        const fileInput = document.getElementById('import-file');
        const file = fileInput.files[0];
        
        if (!file) {
            alert('Please select a file to import.');
            return;
        }
        
        if (file.type !== 'application/json' && !file.name.endsWith('.json')) {
            alert('Please select a valid JSON file.');
            return;
        }
        
        const formData = new FormData();
        formData.append('action', 'import_domain_lists');
        formData.append('import_file', file);
        formData.append('merge_mode', $('input[name="import_mode"]:checked').val());
        formData.append('nonce', spamDetective.nonce);
        
        $('#import-status').show().text('Importing...');
        
        $.ajax({
            url: spamDetective.ajaxUrl,
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                if (response.success) {
                    $('#import-status').text('Import successful! Reloading page...').addClass('success');
                    setTimeout(() => {
                        location.reload();
                    }, 2000);
                } else {
                    $('#import-status').text('Import failed: ' + response.data).addClass('error');
                }
            },
            error: function() {
                $('#import-status').text('An error occurred during import.').addClass('error');
            }
        });
    });
    
    // Utility function to download files
    function downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }
    
    // Domain Management
    $(document).on('click', '.whitelist-domain', function() {
        const domain = $(this).data('domain');
        manageDomain('whitelist', 'add', domain, null, null);
    });
    
    $('#add-whitelist').click(function() {
        const domain = $('#new-whitelist-domain').val().trim().toLowerCase();
        if (domain) {
            // Basic domain validation
            if (!isValidDomain(domain)) {
                alert('Please enter a valid domain name (e.g., example.com)');
                return;
            }
            
            $(this).prop('disabled', true).text('Adding...');
            
            manageDomain('whitelist', 'add', domain, null, $(this));
            $('#new-whitelist-domain').val('');
        } else {
            alert('Please enter a domain name');
        }
    });
    
    $('#add-suspicious').click(function() {
        const domain = $('#new-suspicious-domain').val().trim().toLowerCase();
        if (domain) {
            // Basic domain validation
            if (!isValidDomain(domain)) {
                alert('Please enter a valid domain name (e.g., example.com)');
                return;
            }
            
            $(this).prop('disabled', true).text('Adding...');
            
            manageDomain('suspicious', 'add', domain, null, $(this));
            $('#new-suspicious-domain').val('');
        } else {
            alert('Please enter a domain name');
        }
    });
    
    $(document).on('click', '.remove-domain', function() {
        const domain = $(this).data('domain').toLowerCase();
        const type = $(this).data('type');
        const $domainTag = $(this).closest('.domain-tag');
        
        // Show visual feedback immediately
        $domainTag.css('opacity', '0.5');
        
        manageDomain(type, 'remove', domain, $domainTag, null);
    });
    
    function manageDomain(listType, actionType, domain, $domainElement = null, $button = null) {
        const ajaxAction = listType === 'whitelist' ? 'whitelist_domain' : 'manage_suspicious_domains';
        
        console.log('Managing domain:', {
            listType: listType,
            actionType: actionType, 
            domain: domain,
            ajaxAction: ajaxAction
        });
        
        $.ajax({
            url: spamDetective.ajaxUrl,
            type: 'POST',
            data: {
                action: ajaxAction,
                action_type: actionType,
                domain: domain,
                nonce: spamDetective.nonce
            },
            success: function(response) {
                console.log('Domain management response:', response);
                
                if (response.success) {
                    if (actionType === 'remove' && $domainElement) {
                        // If we have the element reference, remove it directly
                        $domainElement.fadeOut(300, function() {
                            $(this).remove();
                        });
                    } else if (actionType === 'add') {
                        // For add operations, try UI update first, then fallback to refresh
                        updateDomainList(listType, actionType, domain);
                        
                        // Fallback: refresh the entire domain section after a delay
                        setTimeout(function() {
                            refreshDomainSection(listType);
                        }, 500);
                    }
                    
                    // Auto re-analyze if we have suspicious users displayed and cache was cleared
                    if (response.data && response.data.cache_cleared && suspiciousUsers.length > 0) {
                        console.log('Cache was cleared, triggering auto re-analysis...');
                        autoReAnalyze(domain, listType, actionType);
                    }
                } else {
                    // Restore opacity on error
                    if ($domainElement) {
                        $domainElement.css('opacity', '1');
                    }
                    alert('Error managing domain: ' + response.data);
                }
                
                // Restore button state
                if ($button && actionType === 'add') {
                    $button.prop('disabled', false).text('Add');
                }
            },
            error: function(xhr, status, error) {
                console.error('AJAX error:', {xhr: xhr, status: status, error: error});
                
                // Restore opacity on error
                if ($domainElement) {
                    $domainElement.css('opacity', '1');
                }
                
                // Restore button state
                if ($button && actionType === 'add') {
                    $button.prop('disabled', false).text('Add');
                }
                
                alert('An error occurred while managing the domain. Please try again.');
            }
        });
    }
    
    // Refresh domain section by fetching current domains from server
    function refreshDomainSection(listType) {
        const containerId = listType === 'whitelist' ? '#whitelisted-domains' : '#suspicious-domains';
        const optionName = listType === 'whitelist' ? 'spam_detective_whitelist' : 'spam_detective_suspicious_domains';
        
        console.log('Refreshing domain section for:', listType);
        
        // Get current domains from server
        $.ajax({
            url: spamDetective.ajaxUrl,
            type: 'POST',
            data: {
                action: 'get_domain_list',
                list_type: listType,
                nonce: spamDetective.nonce
            },
            success: function(response) {
                if (response.success && response.data) {
                    renderDomainList(listType, response.data);
                }
            },
            error: function() {
                console.log('Failed to refresh domain section, using DOM update');
            }
        });
    }
    
    // Render complete domain list
    function renderDomainList(listType, domains) {
        const containerId = listType === 'whitelist' ? '#whitelisted-domains' : '#suspicious-domains';
        const tagClass = listType === 'whitelist' ? 'whitelist-tag' : 'suspicious-tag';
        const $container = $(containerId);
        
        console.log('Rendering domain list:', {listType, domains, containerId});
        
        // Clear existing content
        $container.empty();
        
        // Add each domain
        domains.forEach(function(domain) {
            const tagHtml = `<span class="domain-tag ${tagClass}">${escapeHtml(domain)} <button class="remove-domain" data-domain="${escapeHtml(domain.toLowerCase())}" data-type="${listType}">×</button></span>`;
            $container.append(tagHtml);
        });
        
        console.log('Domain list rendered, container now has', domains.length, 'domains');
    }
    
    // Simple domain validation function
    function isValidDomain(domain) {
        // Basic domain regex - allows domains like example.com, sub.example.com, etc.
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.([a-zA-Z]{2,}\.)*[a-zA-Z]{2,}$/;
        return domainRegex.test(domain);
    }
    
    function updateDomainList(listType, actionType, domain) {
        const containerId = listType === 'whitelist' ? '#whitelisted-domains' : '#suspicious-domains';
        const tagClass = listType === 'whitelist' ? 'whitelist-tag' : 'suspicious-tag';
        
        console.log('Updating domain list:', {
            listType: listType,
            actionType: actionType,
            domain: domain,
            containerId: containerId,
            tagClass: tagClass,
            containerExists: $(containerId).length > 0,
            containerContent: $(containerId).html()
        });
        
        if (actionType === 'add') {
            // Check if domain already exists (case-insensitive check)
            let domainExists = false;
            $(containerId).find('.domain-tag').each(function() {
                const $tag = $(this);
                const existingDomain = $tag.text().replace('×', '').trim().toLowerCase();
                if (existingDomain === domain.toLowerCase()) {
                    domainExists = true;
                    return false; // break out of each loop
                }
            });
            
            console.log('Domain exists check:', domainExists);
            
            if (!domainExists) {
                const $container = $(containerId);
                if ($container.length === 0) {
                    console.error('Container not found:', containerId);
                    return;
                }
                
                const tagHtml = `<span class="domain-tag ${tagClass}">${escapeHtml(domain)} <button class="remove-domain" data-domain="${escapeHtml(domain.toLowerCase())}" data-type="${listType}">×</button></span>`;
                console.log('Adding tag HTML:', tagHtml);
                
                // Create element and append it
                const $newTag = $(tagHtml);
                $container.append($newTag);
                
                // Force a reflow and then show with animation
                $newTag.hide().fadeIn(300);
                
                console.log('Domain added to UI, container now contains:', $container.html());
                console.log('Number of domain tags now:', $container.find('.domain-tag').length);
            } else {
                console.log('Domain already exists, not adding');
            }
        } else if (actionType === 'remove') {
            // Find and remove domain tags that match (case-insensitive)
            $(containerId).find('.domain-tag').each(function() {
                const $tag = $(this);
                const $button = $tag.find('.remove-domain');
                const tagDomain = $button.data('domain');
                
                if (tagDomain && tagDomain.toLowerCase() === domain.toLowerCase()) {
                    $tag.fadeOut(300, function() {
                        $(this).remove();
                    });
                }
            });
        }
    }
    
    // Enter key handlers for domain inputs
    $('#new-whitelist-domain').keypress(function(e) {
        if (e.which === 13) {
            $('#add-whitelist').click();
        }
    });
    
    $('#new-suspicious-domain').keypress(function(e) {
        if (e.which === 13) {
            $('#add-suspicious').click();
        }
    });
    
    /**
     * Auto re-analyze current suspicious users after domain changes
     */
    function autoReAnalyze(changedDomain, listType, actionType) {
        if (suspiciousUsers.length === 0) {
            console.log('No suspicious users to re-analyze');
            return;
        }
        
        console.log(`Auto re-analyzing ${suspiciousUsers.length} users after ${actionType}ing ${changedDomain} to ${listType}`);
        
        // Show loading state
        showReAnalysisProgress(`Re-analyzing users after ${actionType === 'add' ? 'adding' : 'removing'} domain...`);
        
        // Get current user IDs
        const userIds = suspiciousUsers.map(user => user.id);
        
        $.ajax({
            url: spamDetective.ajaxUrl,
            type: 'POST',
            data: {
                action: 'reanalyze_users',
                user_ids: userIds,
                nonce: spamDetective.nonce
            },
            success: function(response) {
                hideReAnalysisProgress();
                
                if (response.success) {
                    const updatedUsers = response.data.users;
                    const removedCount = response.data.removed_count || 0;
                    
                    console.log(`Re-analysis complete. ${updatedUsers.length} users still suspicious, ${removedCount} users removed from list`);
                    
                    // Update the suspicious users array
                    suspiciousUsers = updatedUsers;
                    
                    // Re-display results with updated data
                    displayResults();
                    
                    // Show feedback message
                    if (removedCount > 0) {
                        showTemporaryMessage(`Re-analysis complete! ${removedCount} user(s) are no longer flagged as suspicious due to the domain change.`, 'success');
                    } else {
                        showTemporaryMessage('Re-analysis complete! All users remain flagged as suspicious.', 'info');
                    }
                } else {
                    console.error('Re-analysis failed:', response.data);
                    showTemporaryMessage('Re-analysis failed: ' + response.data, 'error');
                }
            },
            error: function(xhr, status, error) {
                hideReAnalysisProgress();
                console.error('Re-analysis AJAX error:', {xhr: xhr, status: status, error: error});
                showTemporaryMessage('Re-analysis failed. Please manually refresh the analysis.', 'error');
            }
        });
    }
    
    /**
     * Show re-analysis progress indicator
     */
    function showReAnalysisProgress(message) {
        // Create or update progress indicator
        let $indicator = $('#reanalysis-progress');
        if ($indicator.length === 0) {
            $indicator = $('<div id="reanalysis-progress" class="reanalysis-progress"><p></p><div class="progress-bar"><div class="progress-fill"></div></div></div>');
            $('#results-container h2').after($indicator);
        }
        
        $indicator.find('p').text(message);
        $indicator.show();
        
        // Animate progress bar
        $indicator.find('.progress-fill').css('width', '0%');
        let progress = 0;
        const interval = setInterval(() => {
            progress += Math.random() * 10;
            if (progress > 90) progress = 90;
            $indicator.find('.progress-fill').css('width', progress + '%');
            if (progress >= 90) {
                clearInterval(interval);
            }
        }, 100);
        
        // Store interval ID for cleanup
        $indicator.data('interval', interval);
    }
    
    /**
     * Hide re-analysis progress indicator
     */
    function hideReAnalysisProgress() {
        const $indicator = $('#reanalysis-progress');
        if ($indicator.length > 0) {
            // Clear animation interval
            const interval = $indicator.data('interval');
            if (interval) {
                clearInterval(interval);
            }
            
            // Complete the progress bar then hide
            $indicator.find('.progress-fill').css('width', '100%');
            setTimeout(() => {
                $indicator.fadeOut(300);
            }, 500);
        }
    }
    
    /**
     * Show temporary message to user
     */
    function showTemporaryMessage(message, type = 'info') {
        const $container = $('#results-container');
        if ($container.length === 0) return;
        
        const $message = $(`<div class="temporary-message ${type}"><p>${escapeHtml(message)}</p></div>`);
        $container.prepend($message);
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            $message.fadeOut(300, function() {
                $(this).remove();
            });
        }, 5000);
        
        // Allow manual dismissal
        $message.click(function() {
            $(this).fadeOut(300, function() {
                $(this).remove();
            });
        });
    }
});