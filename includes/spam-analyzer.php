<?php

/**
 * Spam Detection Analyzer Class
 * 
 * File: includes/spam-analyzer.php
 */

if (!defined('ABSPATH')) {
  exit;
}

class SpamDetective_Analyzer
{

  private $common_patterns = [
    '/^[a-z]{6,12}$/',  // Random lowercase letters
    '/^[a-z]+\d+$/',    // Letters followed by numbers
    '/^\w+\-\d+$/',     // Word-number pattern like "wispaky-6855"
    '/^[bcdfghjklmnpqrstvwxyz]{4,8}[aeiou]{1,3}[bcdfghjklmnpqrstvwxyz]{2,6}$/', // Consonant-vowel-consonant patterns
    '/^[a-z]{1,3}(\.[a-z]{1,3}){3,}$/', // Multiple dots pattern like "ja.me.sw.o.o.ds.ii.ii.v"
    '/^[a-z]+(\.[a-z]+){2,}$/', // General multiple dots pattern
  ];

  // Protected roles that cannot be deleted
  private $protected_roles = ['administrator', 'editor', 'shop_manager'];

  public function __construct()
  {
    add_action('wp_ajax_analyze_spam_users', [$this, 'ajax_analyze_spam_users']);
    add_action('wp_ajax_delete_spam_users', [$this, 'ajax_delete_spam_users']);
    add_action('wp_ajax_whitelist_domain', [$this, 'ajax_whitelist_domain']);
    add_action('wp_ajax_manage_suspicious_domains', [$this, 'ajax_manage_suspicious_domains']);
    add_action('wp_ajax_export_suspicious_users', [$this, 'ajax_export_suspicious_users']);
    add_action('wp_ajax_export_domain_lists', [$this, 'ajax_export_domain_lists']);
    add_action('wp_ajax_import_domain_lists', [$this, 'ajax_import_domain_lists']);
    add_action('wp_ajax_get_domain_list', [$this, 'ajax_get_domain_list']);
  }

  public function ajax_analyze_spam_users()
  {
    check_ajax_referer('spam_detective_nonce', 'nonce');

    if (!current_user_can('manage_options')) {
      wp_die('Insufficient permissions');
    }

    $quick_scan = isset($_POST['quick_scan']) && $_POST['quick_scan'];
    $limit = $quick_scan ? 100 : -1;

    $users = get_users([
      'number' => $limit,
      'orderby' => 'registered',
      'order' => 'DESC'
    ]);

    $suspicious_users = [];
    $whitelist = get_option('spam_detective_whitelist', []);
    $suspicious_domains = get_option('spam_detective_suspicious_domains', []);

    foreach ($users as $user) {
      // Skip protected roles
      if ($this->is_protected_user($user)) {
        continue;
      }

      // Skip users with fulfilled WooCommerce orders completely
      if ($this->has_fulfilled_woocommerce_orders($user->ID)) {
        continue;
      }

      // Check if email domain is whitelisted - skip completely if it is
      $email_domain = explode('@', $user->user_email)[1] ?? '';
      if (in_array(strtolower($email_domain), array_map('strtolower', $whitelist))) {
        continue;
      }

      // Check cache first
      $cache_key = 'spam_detective_user_' . $user->ID . '_' . md5($user->user_registered . $user->user_email);
      $cached_analysis = get_transient($cache_key);

      if ($cached_analysis !== false) {
        $analysis = $cached_analysis;
      } else {
        $analysis = $this->analyze_user($user, $whitelist, $suspicious_domains);
        // Cache for 24 hours
        set_transient($cache_key, $analysis, 24 * HOUR_IN_SECONDS);
      }

      if ($analysis['is_suspicious']) {
        $suspicious_users[] = [
          'id' => $user->ID,
          'username' => $user->user_login,
          'email' => $user->user_email,
          'display_name' => $user->display_name,
          'registered' => $user->user_registered,
          'risk_level' => $analysis['risk_level'],
          'reasons' => $analysis['reasons'],
          'can_delete' => $this->can_delete_user($user),
          'has_orders' => $this->has_woocommerce_orders($user->ID),
          'roles' => $this->get_user_roles($user)
        ];
      }
    }

    wp_send_json_success([
      'users' => $suspicious_users,
      'total_analyzed' => count($users)
    ]);
  }

  public function analyze_user($user, $whitelist = [], $suspicious_domains = [])
  {
    $reasons = [];
    $risk_score = 0;

    $email_domain = strtolower(explode('@', $user->user_email)[1] ?? '');

    // Skip whitelisted domains (case-insensitive comparison)
    $whitelist_lower = array_map('strtolower', $whitelist);
    if (in_array($email_domain, $whitelist_lower)) {
      return ['is_suspicious' => false, 'risk_level' => 'low', 'reasons' => []];
    }

    // Check suspicious domains (case-insensitive comparison)
    $suspicious_domains_lower = array_map('strtolower', $suspicious_domains);
    if (in_array($email_domain, $suspicious_domains_lower)) {
      $reasons[] = 'Known spam domain';
      $risk_score += 50;
    }

    // Check username patterns
    foreach ($this->common_patterns as $pattern) {
      if (preg_match($pattern, strtolower($user->user_login))) {
        if (strpos($pattern, '\.') !== false) {
          // This is a dot pattern - high priority
          $reasons[] = 'Suspicious username pattern (multiple dots)';
          $risk_score += 60; // Higher score for dot patterns
        } else {
          $reasons[] = 'Suspicious username pattern';
          $risk_score += 30;
        }
        break;
      }
    }

    // Check for random-looking usernames
    if ($this->is_random_string($user->user_login)) {
      $reasons[] = 'Random username';
      $risk_score += 25;
    }

    // Check for missing display name
    if (empty($user->display_name) || $user->display_name === $user->user_login) {
      $reasons[] = 'No display name';
      $risk_score += 70;
    }

    // Check username vs email consistency (suspicious pattern for bots)
    $email_prefix = explode('@', $user->user_email)[0];
    $username_lower = strtolower($user->user_login);
    $email_prefix_lower = strtolower($email_prefix);

    // Remove common separators for comparison
    $username_clean = str_replace(['.', '_', '-'], '', $username_lower);
    $email_clean = str_replace(['.', '_', '-'], '', $email_prefix_lower);

    if ($username_lower === $email_prefix_lower) {
      // Exact match: username = email prefix (common bot pattern)
      $risk_score += 15;
      $reasons[] = 'Username exactly matches email prefix';
    } elseif ($username_clean === $email_clean && $username_lower !== $email_prefix_lower) {
      // Same after removing separators (john.doe vs johndoe)
      $risk_score += 13;
      $reasons[] = 'Username similar to email prefix';
    } elseif (strlen($username_lower) >= 4 && strlen($email_prefix_lower) >= 4) {
      // Check for partial matches (at least 4 characters to avoid false positives)
      if (strpos($email_prefix_lower, $username_lower) !== false) {
        // Username is contained in email prefix
        $risk_score += 12;
        $reasons[] = 'Username contained in email';
      } elseif (strpos($username_lower, $email_prefix_lower) !== false) {
        // Email prefix is contained in username  
        $risk_score += 12;
        $reasons[] = 'Email prefix contained in username';
      }
    }

    // Check for suspicious email patterns
    if (preg_match('/^[a-z]+\d+@/', strtolower($user->user_email))) {
      $reasons[] = 'Generic email pattern';
      $risk_score += 15;
    }

    // Check for bulk registrations from same domain
    $domain_count = $this->count_users_by_domain($email_domain);
    if ($domain_count > 5) {
      $reasons[] = "Bulk registration ({$domain_count} from same domain)";
      $risk_score += min(20, $domain_count);
    }

    // Check registration with no activity
    $reg_time = strtotime($user->user_registered);
    if (time() - $reg_time > (30 * 24 * 60 * 60)) {
      $post_count = count_user_posts($user->ID);
      $comment_count = get_comments(['user_id' => $user->ID, 'count' => true]);

      if ($post_count == 0 && $comment_count == 0) {
        $reasons[] = 'No activity after 30 days';
        $risk_score += 20;
      }
    }

    // Note: WooCommerce checks are now handled in the main loop to completely exclude users

    // Determine risk level
    $risk_level = 'low';
    if ($risk_score >= 70) {
      $risk_level = 'high';
    } elseif ($risk_score >= 40) {
      $risk_level = 'medium';
    }

    return [
      'is_suspicious' => $risk_score >= 25,
      'risk_level' => $risk_level,
      'reasons' => $reasons,
      'score' => $risk_score
    ];
  }

  /**
   * Check if user has fulfilled WooCommerce orders
   */
  private function has_fulfilled_woocommerce_orders($user_id)
  {
    if (!class_exists('WooCommerce')) {
      return false;
    }

    $orders = wc_get_orders([
      'customer_id' => $user_id,
      'limit' => 1,
      'status' => ['completed'] // Only check for completed/fulfilled orders
    ]);

    return !empty($orders);
  }

  /**
   * Check if user has protected role
   */
  private function is_protected_user($user)
  {
    $user_roles = $this->get_user_roles($user);
    return !empty(array_intersect($user_roles, $this->protected_roles));
  }

  /**
   * Check if user can be deleted (not protected)
   */
  private function can_delete_user($user)
  {
    return !$this->is_protected_user($user);
  }

  /**
   * Get user roles
   */
  private function get_user_roles($user)
  {
    $user_data = get_userdata($user->ID);
    return $user_data ? $user_data->roles : [];
  }

  /**
   * Check if user has WooCommerce orders (any status)
   */
  private function has_woocommerce_orders($user_id)
  {
    if (!class_exists('WooCommerce')) {
      return false;
    }

    $orders = wc_get_orders([
      'customer_id' => $user_id,
      'limit' => 1,
      'status' => ['completed', 'processing', 'on-hold']
    ]);

    return !empty($orders);
  }

  /**
   * Clear cache for deleted users
   */
  private function clear_user_cache($user_id)
  {
    $user = get_user_by('ID', $user_id);
    if ($user) {
      $cache_key = 'spam_detective_user_' . $user_id . '_' . md5($user->user_registered . $user->user_email);
      delete_transient($cache_key);
    }
  }

  private function is_random_string($string)
  {
    // Check for lack of vowels or consonants
    $vowels = preg_match_all('/[aeiou]/i', $string);
    $consonants = preg_match_all('/[bcdfghjklmnpqrstvwxyz]/i', $string);

    if ($vowels == 0 || $consonants == 0) return true;

    // Check for repetitive patterns
    if (preg_match('/(.)\1{2,}/', $string)) return true;

    // Check for keyboard patterns
    $keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '123', 'abc'];
    foreach ($keyboard_patterns as $pattern) {
      if (strpos(strtolower($string), $pattern) !== false) return true;
    }

    return false;
  }

  private function count_users_by_domain($domain)
  {
    global $wpdb;

    $count = $wpdb->get_var($wpdb->prepare(
      "SELECT COUNT(*) FROM {$wpdb->users} WHERE user_email LIKE %s",
      '%@' . $domain
    ));

    return (int) $count;
  }

  public function ajax_delete_spam_users()
  {
    check_ajax_referer('spam_detective_nonce', 'nonce');

    if (!current_user_can('delete_users')) {
      wp_die('Insufficient permissions');
    }

    $user_ids = $_POST['user_ids'] ?? [];
    $deleted = 0;
    $skipped = 0;

    foreach ($user_ids as $user_id) {
      $user = get_user_by('ID', $user_id);

      if (!$user || $this->is_protected_user($user)) {
        $skipped++;
        continue;
      }

      // Additional check for WooCommerce orders if force delete not enabled
      $force_delete = isset($_POST['force_delete']) && $_POST['force_delete'];
      if (!$force_delete && $this->has_woocommerce_orders($user_id)) {
        $skipped++;
        continue;
      }

      if (wp_delete_user($user_id)) {
        $this->clear_user_cache($user_id);
        $deleted++;
      }
    }

    wp_send_json_success([
      'deleted' => $deleted,
      'skipped' => $skipped,
      'message' => $skipped > 0 ? "Deleted {$deleted} users. Skipped {$skipped} protected users." : "Deleted {$deleted} users."
    ]);
  }

  /**
   * Export suspicious users to CSV
   */
  public function ajax_export_suspicious_users()
  {
    check_ajax_referer('spam_detective_nonce', 'nonce');

    if (!current_user_can('manage_options')) {
      wp_die('Insufficient permissions');
    }

    $user_ids = $_POST['user_ids'] ?? [];

    if (empty($user_ids)) {
      wp_send_json_error('No users selected for export');
    }

    $csv_data = [];
    $csv_data[] = ['ID', 'Username', 'Email', 'Display Name', 'Registration Date', 'Risk Level', 'Risk Factors', 'Roles', 'Has Orders', 'Can Delete'];

    foreach ($user_ids as $user_id) {
      $user = get_user_by('ID', $user_id);
      if (!$user) continue;

      // Re-analyze user for current data
      $whitelist = get_option('spam_detective_whitelist', []);
      $suspicious_domains = get_option('spam_detective_suspicious_domains', []);
      $analysis = $this->analyze_user($user, $whitelist, $suspicious_domains);

      $csv_data[] = [
        $user->ID,
        $user->user_login,
        $user->user_email,
        $user->display_name,
        $user->user_registered,
        $analysis['risk_level'],
        implode('; ', $analysis['reasons']),
        implode(', ', $this->get_user_roles($user)),
        $this->has_woocommerce_orders($user->ID) ? 'Yes' : 'No',
        $this->can_delete_user($user) ? 'Yes' : 'No'
      ];
    }

    // Create CSV content
    $csv_content = '';
    foreach ($csv_data as $row) {
      $csv_content .= implode(',', array_map(function ($field) {
        return '"' . str_replace('"', '""', $field) . '"';
      }, $row)) . "\n";
    }

    wp_send_json_success([
      'filename' => 'suspicious-users-' . date('Y-m-d-H-i-s') . '.csv',
      'content' => $csv_content
    ]);
  }

  /**
   * Export domain lists
   */
  public function ajax_export_domain_lists()
  {
    check_ajax_referer('spam_detective_nonce', 'nonce');

    if (!current_user_can('manage_options')) {
      wp_die('Insufficient permissions');
    }

    $whitelist = get_option('spam_detective_whitelist', []);
    $suspicious_domains = get_option('spam_detective_suspicious_domains', []);

    $export_data = [
      'exported_at' => current_time('mysql'),
      'whitelist' => $whitelist,
      'suspicious_domains' => $suspicious_domains
    ];

    wp_send_json_success([
      'filename' => 'spam-detective-domains-' . date('Y-m-d-H-i-s') . '.json',
      'content' => json_encode($export_data, JSON_PRETTY_PRINT)
    ]);
  }

  /**
   * Import domain lists
   */
  public function ajax_import_domain_lists()
  {
    check_ajax_referer('spam_detective_nonce', 'nonce');

    if (!current_user_can('manage_options')) {
      wp_die('Insufficient permissions');
    }

    if (!isset($_FILES['import_file']) || $_FILES['import_file']['error'] !== UPLOAD_ERR_OK) {
      wp_send_json_error('No file uploaded or upload error');
    }

    $file_content = file_get_contents($_FILES['import_file']['tmp_name']);
    $import_data = json_decode($file_content, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
      wp_send_json_error('Invalid JSON file');
    }

    $merge_mode = $_POST['merge_mode'] ?? 'replace';

    // Import whitelist
    if (isset($import_data['whitelist']) && is_array($import_data['whitelist'])) {
      if ($merge_mode === 'merge') {
        $current_whitelist = get_option('spam_detective_whitelist', []);
        $new_whitelist = array_unique(array_merge($current_whitelist, $import_data['whitelist']));
      } else {
        $new_whitelist = $import_data['whitelist'];
      }
      update_option('spam_detective_whitelist', $new_whitelist);
    }

    // Import suspicious domains
    if (isset($import_data['suspicious_domains']) && is_array($import_data['suspicious_domains'])) {
      if ($merge_mode === 'merge') {
        $current_suspicious = get_option('spam_detective_suspicious_domains', []);
        $new_suspicious = array_unique(array_merge($current_suspicious, $import_data['suspicious_domains']));
      } else {
        $new_suspicious = $import_data['suspicious_domains'];
      }
      update_option('spam_detective_suspicious_domains', $new_suspicious);
    }

    wp_send_json_success(['message' => 'Domain lists imported successfully']);
  }

  public function ajax_whitelist_domain()
  {
    check_ajax_referer('spam_detective_nonce', 'nonce');

    if (!current_user_can('manage_options')) {
      wp_die('Insufficient permissions');
    }

    $action_type = sanitize_text_field($_POST['action_type'] ?? '');
    $domain = strtolower(sanitize_text_field($_POST['domain'] ?? '')); // Convert to lowercase

    if (!$domain) {
      wp_send_json_error('Invalid domain');
    }

    $whitelist = get_option('spam_detective_whitelist', []);
    $whitelist = array_map('strtolower', $whitelist); // Convert existing to lowercase

    if ($action_type === 'add') {
      if (!in_array($domain, $whitelist)) {
        $whitelist[] = $domain;
        update_option('spam_detective_whitelist', $whitelist);

        // Clear cache when whitelist changes
        $this->clear_all_user_cache();
      }
    } elseif ($action_type === 'remove') {
      $whitelist = array_filter($whitelist, function ($d) use ($domain) {
        return $d !== $domain;
      });
      update_option('spam_detective_whitelist', array_values($whitelist));

      // Clear cache when whitelist changes
      $this->clear_all_user_cache();
    }

    wp_send_json_success();
  }

  public function ajax_manage_suspicious_domains()
  {
    check_ajax_referer('spam_detective_nonce', 'nonce');

    if (!current_user_can('manage_options')) {
      wp_die('Insufficient permissions');
    }

    $action_type = sanitize_text_field($_POST['action_type'] ?? '');
    $domain = strtolower(sanitize_text_field($_POST['domain'] ?? '')); // Convert to lowercase

    if (!$domain) {
      wp_send_json_error('Invalid domain');
    }

    $suspicious_domains = get_option('spam_detective_suspicious_domains', []);
    $suspicious_domains = array_map('strtolower', $suspicious_domains); // Convert existing to lowercase

    if ($action_type === 'add') {
      if (!in_array($domain, $suspicious_domains)) {
        $suspicious_domains[] = $domain;
        update_option('spam_detective_suspicious_domains', $suspicious_domains);

        // Clear cache when suspicious domains change
        $this->clear_all_user_cache();
      }
    } elseif ($action_type === 'remove') {
      $suspicious_domains = array_filter($suspicious_domains, function ($d) use ($domain) {
        return $d !== $domain;
      });
      update_option('spam_detective_suspicious_domains', array_values($suspicious_domains));

      // Clear cache when suspicious domains change
      $this->clear_all_user_cache();
    }

    wp_send_json_success();
  }

  /**
   * Get domain list for refreshing UI
   */
  public function ajax_get_domain_list()
  {
    check_ajax_referer('spam_detective_nonce', 'nonce');

    if (!current_user_can('manage_options')) {
      wp_die('Insufficient permissions');
    }

    $list_type = sanitize_text_field($_POST['list_type'] ?? '');

    if ($list_type === 'whitelist') {
      $domains = get_option('spam_detective_whitelist', []);
    } elseif ($list_type === 'suspicious') {
      $domains = get_option('spam_detective_suspicious_domains', []);
    } else {
      wp_send_json_error('Invalid list type');
      return;
    }

    // Ensure domains are lowercase for consistency
    $domains = array_map('strtolower', array_map('trim', $domains));

    wp_send_json_success($domains);
  }

  /**
   * Clear all user analysis cache
   */
  private function clear_all_user_cache()
  {
    global $wpdb;

    $wpdb->query(
      "DELETE FROM {$wpdb->options} 
       WHERE option_name LIKE '_transient_spam_detective_user_%' 
       OR option_name LIKE '_transient_timeout_spam_detective_user_%'"
    );
  }
}
