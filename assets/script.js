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
            
            html += `
                <tr data-user-id="${user.id}" class="${statusClass}">
                    <td><input type="checkbox" class="user-checkbox" value="${user.id}" ${!user.can_delete ? 'disabled' : ''}></td>
                    <td>${statusIcon}</td>
                    <td><span class="risk-level ${riskClass}">${user.risk_level}</span></td>
                    <td><strong>${escapeHtml(user.username)}</strong></td>
                    <td>${escapeHtml(user.email)}</td>
                    <td>${user.display_name ? escapeHtml(user.display_name) : '<em>None</em>'}</td>
                    <td>${user.registered}</td>
                    <td class="risk-factors">${user.reasons.join(', ')}</td>
                    <td>
                        <button class="button button-small delete-single" data-user-id="${user.id}" ${!user.can_delete ? 'disabled' : ''}>Delete</button>
                        <button class="button button-small whitelist-domain" data-domain="${emailDomain}">Whitelist Domain</button>
                    </td>
                </tr>
            `;
        });
        $('#suspicious-users-list').html(html);
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
});