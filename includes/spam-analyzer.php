<?php

/**
 * Spam Detection Analyzer Class - Improved WooCommerce Integration
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
    add_action('wp_ajax_reanalyze_users', [$this, 'ajax_reanalyze_users']);
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

    $skipped_users = [
      'protected_roles' => 0,
      'has_orders' => 0,
      'whitelisted' => 0
    ];

    foreach ($users as $user) {
      // Skip protected roles
      if ($this->is_protected_user($user)) {
        $skipped_users['protected_roles']++;
        continue;
      }

      // Skip users with any meaningful WooCommerce orders completely
      if ($this->has_meaningful_woocommerce_orders($user->ID)) {
        $skipped_users['has_orders']++;
        error_log("Spam Detective: Skipping user {$user->user_login} (ID: {$user->ID}) - has meaningful WooCommerce orders");
        continue;
      }

      // Check if email domain is whitelisted - skip completely if it is
      $email_domain = explode('@', $user->user_email)[1] ?? '';
      if (in_array(strtolower($email_domain), array_map('strtolower', $whitelist))) {
        $skipped_users['whitelisted']++;
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

    // Sort users by risk level (high -> medium -> low) and then by registration date (newest first)
    usort($suspicious_users, function ($a, $b) {
      // Define risk level priority (higher number = higher priority)
      $risk_priority = [
        'high' => 3,
        'medium' => 2,
        'low' => 1
      ];

      $a_priority = $risk_priority[$a['risk_level']] ?? 0;
      $b_priority = $risk_priority[$b['risk_level']] ?? 0;

      // First sort by risk level (descending - high risk first)
      if ($a_priority !== $b_priority) {
        return $b_priority - $a_priority;
      }

      // If same risk level, sort by registration date (newest first)
      return strcmp($b['registered'], $a['registered']);
    });

    // Log analysis summary
    error_log("Spam Detective: Analysis complete - Found " . count($suspicious_users) . " suspicious users. Skipped: " .
      "{$skipped_users['protected_roles']} protected roles, " .
      "{$skipped_users['has_orders']} with orders, " .
      "{$skipped_users['whitelisted']} whitelisted domains");

    wp_send_json_success([
      'users' => $suspicious_users,
      'total_analyzed' => count($users),
      'skipped' => $skipped_users
    ]);
  }

  /**
   * Re-analyze specific users after domain changes
   */
  public function ajax_reanalyze_users()
  {
    check_ajax_referer('spam_detective_nonce', 'nonce');

    if (!current_user_can('manage_options')) {
      wp_die('Insufficient permissions');
    }

    $user_ids = $_POST['user_ids'] ?? [];

    if (empty($user_ids)) {
      wp_send_json_error('No users provided for re-analysis');
    }

    $whitelist = get_option('spam_detective_whitelist', []);
    $suspicious_domains = get_option('spam_detective_suspicious_domains', []);

    $still_suspicious = [];
    $removed_count = 0;

    foreach ($user_ids as $user_id) {
      $user = get_user_by('ID', $user_id);
      if (!$user) {
        continue;
      }

      // Skip protected users (they shouldn't be in the list anyway)
      if ($this->is_protected_user($user)) {
        continue;
      }

      // Skip users with meaningful WooCommerce orders completely
      if ($this->has_meaningful_woocommerce_orders($user->ID)) {
        $removed_count++;
        error_log("Spam Detective: Removing user {$user->user_login} (ID: {$user->ID}) from suspicious list - has meaningful WooCommerce orders");
        continue;
      }

      // Check if email domain is whitelisted - skip completely if it is
      $email_domain = explode('@', $user->user_email)[1] ?? '';
      if (in_array(strtolower($email_domain), array_map('strtolower', $whitelist))) {
        $removed_count++;
        continue;
      }

      // Re-analyze the user with current domain lists (no cache)
      $analysis = $this->analyze_user($user, $whitelist, $suspicious_domains);

      if ($analysis['is_suspicious']) {
        $still_suspicious[] = [
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

        // Update cache with new analysis
        $cache_key = 'spam_detective_user_' . $user->ID . '_' . md5($user->user_registered . $user->user_email);
        set_transient($cache_key, $analysis, 24 * HOUR_IN_SECONDS);
      } else {
        // User is no longer suspicious
        $removed_count++;

        // Clear old cache
        $this->clear_user_cache($user->ID);
      }
    }

    // Sort users by risk level (high -> medium -> low) and then by registration date (newest first)
    usort($still_suspicious, function ($a, $b) {
      // Define risk level priority (higher number = higher priority)
      $risk_priority = [
        'high' => 3,
        'medium' => 2,
        'low' => 1
      ];

      $a_priority = $risk_priority[$a['risk_level']] ?? 0;
      $b_priority = $risk_priority[$b['risk_level']] ?? 0;

      // First sort by risk level (descending - high risk first)
      if ($a_priority !== $b_priority) {
        return $b_priority - $a_priority;
      }

      // If same risk level, sort by registration date (newest first)
      return strcmp($b['registered'], $a['registered']);
    });

    error_log("Spam Detective: Re-analyzed " . count($user_ids) . " users. " . count($still_suspicious) . " still suspicious, {$removed_count} removed from list.");

    wp_send_json_success([
      'users' => $still_suspicious,
      'removed_count' => $removed_count,
      'total_reanalyzed' => count($user_ids)
    ]);
  }

  public function analyze_user($user, $whitelist = [], $suspicious_domains = [])
  {
    global $wpdb;
    $reasons = [];
    $risk_score = 0;

    $email_domain = strtolower(explode('@', $user->user_email)[1] ?? '');
    $email_prefix = explode('@', $user->user_email)[0] ?? '';

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

    // 1. Check for suspicious TLD domains (without .info)
    $suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.ws'];
    foreach ($suspicious_tlds as $tld) {
      if (str_ends_with($email_domain, $tld)) {
        $risk_score += 15;
        $reasons[] = 'Suspicious domain extension';
        break;
      }
    }

    // 2. Enhanced email pattern analysis
    if (preg_match('/^[a-z]+\d+@/', strtolower($user->user_email))) {
      $reasons[] = 'Generic email pattern';
      $risk_score += 15;
    }

    // Check for email with trailing numbers (common bot pattern)
    if (preg_match('/\d{2,}@/', $user->user_email)) {
      $risk_score += 10;
      $reasons[] = 'Email with trailing numbers';
    }

    // Check for very short email prefixes (less than 4 characters)
    if (strlen($email_prefix) < 4) {
      $risk_score += 8;
      $reasons[] = 'Very short email prefix';
    }

    // Check for email prefix that's all numbers
    if (is_numeric($email_prefix)) {
      $risk_score += 15;
      $reasons[] = 'Numeric email prefix';
    }

    // Check for bulk registrations from same domain
    $domain_count = $this->count_users_by_domain($email_domain);
    if ($domain_count > 5) {
      $reasons[] = "Bulk registration ({$domain_count} from same domain)";
      $risk_score += min(20, $domain_count);
    }

    // 4. Check for common spam username patterns
    $spam_username_patterns = [
      '/^(user|admin|test|guest|temp|spam|bot)\d*$/',
      '/^[a-z]{1,3}\d{4,}$/', // Short letters + many numbers: a1234, xy5678
      '/^[a-z]+_\d{4,}$/',    // word_1234 pattern
      '/^(first|last|full)?name\d*$/',
      '/^[a-z]+\d{8,}$/'      // Letters followed by 8+ digits
    ];

    foreach ($spam_username_patterns as $pattern) {
      if (preg_match($pattern, $username_lower)) {
        $risk_score += 20;
        $reasons[] = 'Common spam username pattern';
        break;
      }
    }

    // 5. Display name analysis (when it exists)
    if (!empty($user->display_name) && $user->display_name !== $user->user_login) {
      $display_lower = strtolower($user->display_name);

      // Display name is just numbers
      if (is_numeric(str_replace(' ', '', $user->display_name))) {
        $risk_score += 10;
        $reasons[] = 'Numeric display name';
      }

      // Display name matches common spam patterns
      $spam_display_patterns = ['user', 'test', 'admin', 'guest', 'temp'];
      foreach ($spam_display_patterns as $pattern) {
        if (strpos($display_lower, $pattern) !== false) {
          $risk_score += 8;
          $reasons[] = 'Generic display name';
          break;
        }
      }
    }

    // 6. First/Last name analysis
    $first_name = trim($user->first_name);
    $last_name = trim($user->last_name);

    if (!empty($first_name) || !empty($last_name)) {
      // Names that are obviously fake
      $fake_names = ['test', 'user', 'admin', 'guest', 'temp', 'spam', 'bot'];

      if (
        in_array(strtolower($first_name), $fake_names) ||
        in_array(strtolower($last_name), $fake_names)
      ) {
        $risk_score += 15;
        $reasons[] = 'Fake name used';
      }

      // Names that are just numbers
      if (is_numeric($first_name) || is_numeric($last_name)) {
        $risk_score += 12;
        $reasons[] = 'Numeric name fields';
      }

      // Single character names (suspicious)
      if (strlen($first_name) === 1 || strlen($last_name) === 1) {
        $risk_score += 8;
        $reasons[] = 'Single character name';
      }
    } else {
      // Having complete name info is slightly positive
      $risk_score -= 5; // Small bonus for providing names
    }

    // 7. Sequential/Numeric Username Detection
    if (preg_match('/^[a-z]+\d{1,4}$/', $username_lower)) {
      // Check if similar usernames exist (user1, user2, user3...)
      $base_username = preg_replace('/\d+$/', '', $username_lower);
      $similar_count = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM {$wpdb->users} WHERE user_login LIKE %s",
        $base_username . '%'
      ));

      if ($similar_count > 3) {
        $risk_score += 20;
        $reasons[] = "Sequential username pattern ({$similar_count} similar)";
      }
    }

    // 8. Registration Time Burst Detection
    $reg_timestamp = strtotime($user->user_registered);
    $time_window = 1800; // 30 minutes

    $burst_count = $wpdb->get_var($wpdb->prepare(
      "SELECT COUNT(*) FROM {$wpdb->users} 
       WHERE user_registered BETWEEN %s AND %s",
      date('Y-m-d H:i:s', $reg_timestamp - $time_window),
      date('Y-m-d H:i:s', $reg_timestamp + $time_window)
    ));

    if ($burst_count > 10) {
      $risk_score += 25;
      $reasons[] = "Mass registration burst ({$burst_count} users in 1 hour)";
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
   * Enhanced method to check if user has meaningful WooCommerce orders
   * This includes completed, processing, and on-hold orders (showing legitimate customer activity)
   */
  private function has_meaningful_woocommerce_orders($user_id)
  {
    if (!class_exists('WooCommerce')) {
      return false;
    }

    // Check cache first for performance
    $cache_key = 'spam_detective_orders_' . $user_id;
    $cached_result = get_transient($cache_key);
    if ($cached_result !== false) {
      return $cached_result;
    }

    // Check for orders that indicate legitimate customer activity
    $meaningful_statuses = ['completed', 'processing', 'on-hold'];

    $orders = wc_get_orders([
      'customer_id' => $user_id,
      'limit' => 1,
      'status' => $meaningful_statuses,
      'return' => 'ids' // Only return IDs for performance
    ]);

    $has_orders = !empty($orders);

    // Cache result for 1 hour
    set_transient($cache_key, $has_orders, HOUR_IN_SECONDS);

    if ($has_orders) {
      error_log("Spam Detective: User {$user_id} has meaningful WooCommerce orders, excluding from spam analysis");
    }

    return $has_orders;
  }

  /**
   * Legacy method - kept for backward compatibility but now calls the enhanced method
   * @deprecated Use has_meaningful_woocommerce_orders() instead
   */
  private function has_fulfilled_woocommerce_orders($user_id)
  {
    return $this->has_meaningful_woocommerce_orders($user_id);
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
   * Check if user has WooCommerce orders (any status) - used for display purposes
   */
  private function has_woocommerce_orders($user_id)
  {
    if (!class_exists('WooCommerce')) {
      return false;
    }

    $orders = wc_get_orders([
      'customer_id' => $user_id,
      'limit' => 1,
      'status' => ['completed', 'processing', 'on-hold'],
      'return' => 'ids'
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

      // Also clear order cache
      $order_cache_key = 'spam_detective_orders_' . $user_id;
      delete_transient($order_cache_key);
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
      if (!$force_delete && $this->has_meaningful_woocommerce_orders($user_id)) {
        $skipped++;
        error_log("Spam Detective: Skipping deletion of user {$user->user_login} (ID: {$user_id}) - has meaningful WooCommerce orders");
        continue;
      }

      if (wp_delete_user($user_id)) {
        $this->clear_user_cache($user_id);
        $deleted++;
        error_log("Spam Detective: Deleted user {$user->user_login} (ID: {$user_id})");
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
        $this->has_meaningful_woocommerce_orders($user->ID) ? 'Yes' : 'No',
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

    // Clear cache after import
    $this->clear_all_user_cache();
    error_log("Spam Detective: Domain lists imported, cache cleared");

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
    $cache_cleared = false;

    if ($action_type === 'add') {
      if (!in_array($domain, $whitelist)) {
        $whitelist[] = $domain;
        update_option('spam_detective_whitelist', $whitelist);

        // Clear cache when whitelist changes
        $cache_cleared = $this->clear_all_user_cache();
        error_log("Spam Detective: Added domain '{$domain}' to whitelist, cache cleared: " . ($cache_cleared ? 'yes' : 'no'));
      }
    } elseif ($action_type === 'remove') {
      $original_count = count($whitelist);
      $whitelist = array_filter($whitelist, function ($d) use ($domain) {
        return $d !== $domain;
      });

      // Only clear cache if domain was actually removed
      if (count($whitelist) < $original_count) {
        update_option('spam_detective_whitelist', array_values($whitelist));
        $cache_cleared = $this->clear_all_user_cache();
        error_log("Spam Detective: Removed domain '{$domain}' from whitelist, cache cleared: " . ($cache_cleared ? 'yes' : 'no'));
      } else {
        error_log("Spam Detective: Domain '{$domain}' was not in whitelist, no changes made");
      }
    }

    wp_send_json_success([
      'cache_cleared' => $cache_cleared,
      'message' => $cache_cleared ? 'Domain updated and cache cleared' : 'Domain updated'
    ]);
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
    $cache_cleared = false;

    if ($action_type === 'add') {
      if (!in_array($domain, $suspicious_domains)) {
        $suspicious_domains[] = $domain;
        update_option('spam_detective_suspicious_domains', $suspicious_domains);

        // Clear cache when suspicious domains change
        $cache_cleared = $this->clear_all_user_cache();
        error_log("Spam Detective: Added domain '{$domain}' to suspicious list, cache cleared: " . ($cache_cleared ? 'yes' : 'no'));
      }
    } elseif ($action_type === 'remove') {
      $original_count = count($suspicious_domains);
      $suspicious_domains = array_filter($suspicious_domains, function ($d) use ($domain) {
        return $d !== $domain;
      });

      // Only clear cache if domain was actually removed
      if (count($suspicious_domains) < $original_count) {
        update_option('spam_detective_suspicious_domains', array_values($suspicious_domains));
        $cache_cleared = $this->clear_all_user_cache();
        error_log("Spam Detective: Removed domain '{$domain}' from suspicious list, cache cleared: " . ($cache_cleared ? 'yes' : 'no'));
      } else {
        error_log("Spam Detective: Domain '{$domain}' was not in suspicious list, no changes made");
      }
    }

    wp_send_json_success([
      'cache_cleared' => $cache_cleared,
      'message' => $cache_cleared ? 'Domain updated and cache cleared' : 'Domain updated'
    ]);
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

    // Use the broader pattern to catch all spam detective transients
    $deleted = $wpdb->query(
      "DELETE FROM {$wpdb->options} 
       WHERE option_name LIKE '_transient_spam_detective_%' 
       OR option_name LIKE '_transient_timeout_spam_detective_%'"
    );

    // Also clear object cache if available
    if (function_exists('wp_cache_flush_group')) {
      wp_cache_flush_group('spam_detective');
    }

    // Return whether cache was actually cleared
    return $deleted > 0;
  }
}
