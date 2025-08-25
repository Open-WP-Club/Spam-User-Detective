/**
 * Spam Detective Frontend Script
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
        
        $('#total-suspicious').text(suspiciousUsers.length);
        $('#high-confidence').text(highConfidence);
        $('#suspicious-domains').text(suspiciousDomains);
        $('#displaying-num').text(suspiciousUsers.length + ' items');
        
        let html = '';
        suspiciousUsers.forEach(user => {
            const riskClass = 'risk-' + user.risk_level;
            const emailDomain = user.email.split('@')[1];
            
            html += `
                <tr data-user-id="${user.id}">
                    <td><input type="checkbox" class="user-checkbox" value="${user.id}"></td>
                    <td><span class="risk-level ${riskClass}">${user.risk_level}</span></td>
                    <td><strong>${escapeHtml(user.username)}</strong></td>
                    <td>${escapeHtml(user.email)}</td>
                    <td>${user.display_name ? escapeHtml(user.display_name) : '<em>None</em>'}</td>
                    <td>${user.registered}</td>
                    <td class="risk-factors">${user.reasons.join(', ')}</td>
                    <td>
                        <button class="button button-small delete-single" data-user-id="${user.id}">Delete</button>
                        <button class="button button-small whitelist-domain" data-domain="${emailDomain}">Whitelist Domain</button>
                    </td>
                </tr>
            `;
        });
        $('#suspicious-users-list').html(html);
        updateSelectedCount();
    }
    
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    // Checkbox Handling
    $(document).on('change', '.user-checkbox', updateSelectedCount);
    
    $('#select-all-checkbox').change(function() {
        $('.user-checkbox').prop('checked', this.checked);
        updateSelectedCount();
    });
    
    $('#select-all-high').click(function() {
        $('.user-checkbox').prop('checked', false);
        suspiciousUsers.forEach(user => {
            if (user.risk_level === 'high') {
                $(`.user-checkbox[value="${user.id}"]`).prop('checked', true);
            }
        });
        updateSelectedCount();
    });
    
    $('#select-all-suspicious').click(function() {
        $('.user-checkbox').prop('checked', true);
        updateSelectedCount();
    });
    
    function updateSelectedCount() {
        selectedUsers = $('.user-checkbox:checked').map(function() {
            return this.value;
        }).get();
        $('#selected-count').text(selectedUsers.length + ' selected');
        
        // Update select all checkbox state
        const totalCheckboxes = $('.user-checkbox').length;
        const checkedCheckboxes = $('.user-checkbox:checked').length;
        
        if (checkedCheckboxes === 0) {
            $('#select-all-checkbox').prop('indeterminate', false).prop('checked', false);
        } else if (checkedCheckboxes === totalCheckboxes) {
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
        
        if (confirm(`Are you sure you want to delete ${selectedUsers.length} users? This action cannot be undone.`)) {
            deleteUsers(selectedUsers);
        }
    });
    
    $(document).on('click', '.delete-single', function() {
        const userId = $(this).data('user-id');
        if (confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
            deleteUsers([userId]);
        }
    });
    
    function deleteUsers(userIds) {
        $.ajax({
            url: spamDetective.ajaxUrl,
            type: 'POST',
            data: {
                action: 'delete_spam_users',
                user_ids: userIds,
                nonce: spamDetective.nonce
            },
            success: function(response) {
                if (response.success) {
                    alert(`Successfully deleted ${response.data.deleted} users.`);
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
    
    // Domain Management
    $(document).on('click', '.whitelist-domain', function() {
        const domain = $(this).data('domain');
        manageDomain('whitelist', 'add', domain);
    });
    
    $('#add-whitelist').click(function() {
        const domain = $('#new-whitelist-domain').val().trim();
        if (domain) {
            manageDomain('whitelist', 'add', domain);
            $('#new-whitelist-domain').val('');
        }
    });
    
    $('#add-suspicious').click(function() {
        const domain = $('#new-suspicious-domain').val().trim();
        if (domain) {
            manageDomain('suspicious', 'add', domain);
            $('#new-suspicious-domain').val('');
        }
    });
    
    $(document).on('click', '.remove-domain', function() {
        const domain = $(this).data('domain');
        const type = $(this).data('type');
        manageDomain(type, 'remove', domain);
    });
    
    function manageDomain(listType, actionType, domain) {
        const ajaxAction = listType === 'whitelist' ? 'whitelist_domain' : 'manage_suspicious_domains';
        
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
                if (response.success) {
                    updateDomainList(listType, actionType, domain);
                } else {
                    alert('Error managing domain: ' + response.data);
                }
            },
            error: function() {
                alert('An error occurred while managing the domain. Please try again.');
            }
        });
    }
    
    function updateDomainList(listType, actionType, domain) {
        const containerId = listType === 'whitelist' ? '#whitelisted-domains' : '#suspicious-domains';
        const tagClass = listType === 'whitelist' ? 'whitelist-tag' : 'suspicious-tag';
        
        if (actionType === 'add') {
            // Check if domain already exists to prevent duplicates
            const existingDomain = $(containerId).find(`button[data-domain="${domain}"]`);
            if (existingDomain.length === 0) {
                const tagHtml = `<span class="domain-tag ${tagClass}">${escapeHtml(domain)} <button class="remove-domain" data-domain="${escapeHtml(domain)}" data-type="${listType}">×</button></span>`;
                $(containerId).append(tagHtml);
            }
        } else if (actionType === 'remove') {
            // More specific selector to ensure we remove the right domain
            $(containerId).find(`button[data-domain="${domain}"][data-type="${listType}"]`).parent().remove();
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