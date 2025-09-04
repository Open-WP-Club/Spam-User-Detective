<?php

/**
 * AJAX Handler Class
 * 
 * File: includes/ajax-handler.php
 */

if (!defined('ABSPATH')) {
  exit;
}

class SpamDetective_AjaxHandler
{
  private $user_analyzer;
  private $user_manager;
  private $domain_manager;
  private $export_import;
  private $cache_manager;
  private $woocommerce_integration;

  public function __construct(
    $user_analyzer = null,
    $user_manager = null,
    $domain_manager = null,
    $export_import = null,
    $cache_manager = null,
    $woocommerce_integration = null
  ) {
    $this->user_analyzer = $user_analyzer;
    $this->user_manager = $user_manager;
    $this->domain_manager = $domain_manager;
    $this->export_import = $export_import;
    $this->cache_manager = $cache_manager;
    $this->woocommerce_integration = $woocommerce_integration;
  }

  /**
   * Register all AJAX handlers
   */
  public function register_handlers()
  {
    add_action('wp_ajax_analyze_spam_users', [$this, 'handle_analyze_spam_users']);
    add_action('wp_ajax_reanalyze_users', [$this, 'handle_reanalyze_users']);
    add_action('wp_ajax_delete_spam_users', [$this, 'handle_delete_spam_users']);
    add_action('wp_ajax_whitelist_domain', [$this, 'handle_whitelist_domain']);
    add_action('wp_ajax_manage_suspicious_domains', [$this, 'handle_manage_suspicious_domains']);
    add_action('wp_ajax_export_suspicious_users', [$this, 'handle_export_suspicious_users']);
    add_action('wp_ajax_export_domain_lists', [$this, 'handle_export_domain_lists']);
    add_action('wp_ajax_import_domain_lists', [$this, 'handle_import_domain_lists']);
    add_action('wp_ajax_get_domain_list', [$this, 'handle_get_domain_list']);
    add_action('wp_ajax_clear_spam_cache', [$this, 'handle_clear_spam_cache']);
  }

  /**
   * Handle user analysis request
   */
  public function handle_analyze_spam_users()
  {
    $this->verify_nonce_and_capability('manage_options');

    $quick_scan = isset($_POST['quick_scan']) && $_POST['quick_scan'];

    if (!$this->user_manager || !$this->user_analyzer) {
      wp_send_json_error('Required components not available');
    }

    $users = $this->user_manager->get_users_for_analysis($quick_scan);
    $suspicious_users = [];
    $whitelist = $this->domain_manager ? $this->domain_manager->get_whitelist() : [];
    $suspicious_domains = $this->domain_manager ? $this->domain_manager->get_suspicious_domains() : [];

    $skipped_users = [
      'protected_roles' => 0,
      'has_orders' => 0,
      'whitelisted' => 0
    ];

    foreach ($users as $user) {
      // Skip protected roles
      if ($this->user_manager->is_protected_user($user)) {
        $skipped_users['protected_roles']++;
        continue;
      }

      // Skip users with meaningful WooCommerce orders completely
      if ($this->woocommerce_integration && $this->woocommerce_integration->has_meaningful_woocommerce_orders($user->ID)) {
        $skipped_users['has_orders']++;
        continue;
      }

      // Check if email domain is whitelisted - skip completely if it is
      $email_domain = explode('@', $user->user_email)[1] ?? '';
      if (in_array(strtolower($email_domain), array_map('strtolower', $whitelist))) {
        $skipped_users['whitelisted']++;
        continue;
      }

      // Check cache first
      $analysis = null;
      if ($this->cache_manager && $this->cache_manager->is_caching_enabled()) {
        $analysis = $this->cache_manager->get_user_analysis($user->ID, $user->user_registered, $user->user_email);
      }

      if ($analysis === null || $analysis === false) {
        $analysis = $this->user_analyzer->analyze_user($user, $whitelist, $suspicious_domains);

        // Cache the analysis if caching is enabled
        if ($this->cache_manager && $this->cache_manager->is_caching_enabled()) {
          $this->cache_manager->set_user_analysis($user->ID, $user->user_registered, $user->user_email, $analysis);
        }
      }

      if ($analysis['is_suspicious']) {
        $suspicious_users[] = $this->user_manager->format_user_for_display($user, $analysis);
      }
    }

    // Sort users by risk level (high -> medium -> low) and then by registration date (newest first)
    usort($suspicious_users, [$this, 'sort_users_by_risk_and_date']);

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
   * Handle user re-analysis request
   */
  public function handle_reanalyze_users()
  {
    $this->verify_nonce_and_capability('manage_options');

    $user_ids = $_POST['user_ids'] ?? [];

    if (empty($user_ids) || !$this->user_analyzer || !$this->user_manager) {
      wp_send_json_error('No users provided or required components not available');
    }

    $whitelist = $this->domain_manager ? $this->domain_manager->get_whitelist() : [];
    $suspicious_domains = $this->domain_manager ? $this->domain_manager->get_suspicious_domains() : [];

    $still_suspicious = [];
    $removed_count = 0;

    foreach ($user_ids as $user_id) {
      $user = get_user_by('ID', $user_id);
      if (!$user) {
        continue;
      }

      // Skip protected users
      if ($this->user_manager->is_protected_user($user)) {
        continue;
      }

      // Skip users with meaningful WooCommerce orders completely
      if ($this->woocommerce_integration && $this->woocommerce_integration->has_meaningful_woocommerce_orders($user->ID)) {
        $removed_count++;
        continue;
      }

      // Check if email domain is whitelisted - skip completely if it is
      $email_domain = explode('@', $user->user_email)[1] ?? '';
      if (in_array(strtolower($email_domain), array_map('strtolower', $whitelist))) {
        $removed_count++;
        continue;
      }

      // Re-analyze the user with current domain lists (no cache)
      $analysis = $this->user_analyzer->analyze_user($user, $whitelist, $suspicious_domains);

      if ($analysis['is_suspicious']) {
        $still_suspicious[] = $this->user_manager->format_user_for_display($user, $analysis);

        // Update cache with new analysis
        if ($this->cache_manager) {
          $this->cache_manager->set_user_analysis($user->ID, $user->user_registered, $user->user_email, $analysis);
        }
      } else {
        // User is no longer suspicious
        $removed_count++;

        // Clear old cache
        if ($this->cache_manager) {
          $this->cache_manager->clear_user_cache($user->ID);
        }
      }
    }

    // Sort users by risk level
    usort($still_suspicious, [$this, 'sort_users_by_risk_and_date']);

    error_log("Spam Detective: Re-analyzed " . count($user_ids) . " users. " . count($still_suspicious) . " still suspicious, {$removed_count} removed from list.");

    wp_send_json_success([
      'users' => $still_suspicious,
      'removed_count' => $removed_count,
      'total_reanalyzed' => count($user_ids)
    ]);
  }

  /**
   * Handle user deletion request
   */
  public function handle_delete_spam_users()
  {
    $this->verify_nonce_and_capability('delete_users');

    $user_ids = $_POST['user_ids'] ?? [];
    $force_delete = isset($_POST['force_delete']) && $_POST['force_delete'];

    if (empty($user_ids) || !$this->user_manager) {
      wp_send_json_error('No users provided or user manager not available');
    }

    $result = $this->user_manager->delete_users($user_ids, $force_delete);

    if ($result['success']) {
      wp_send_json_success($result);
    } else {
      wp_send_json_error($result['message']);
    }
  }

  /**
   * Handle whitelist domain management
   */
  public function handle_whitelist_domain()
  {
    $this->verify_nonce_and_capability('manage_options');

    $action_type = sanitize_text_field($_POST['action_type'] ?? '');
    $domain = sanitize_text_field($_POST['domain'] ?? '');

    if (!$domain || !$this->domain_manager) {
      wp_send_json_error('Invalid domain or domain manager not available');
    }

    $cache_cleared = false;

    if ($action_type === 'add') {
      $success = $this->domain_manager->add_to_whitelist($domain);
      $cache_cleared = $success;
    } elseif ($action_type === 'remove') {
      $success = $this->domain_manager->remove_from_whitelist($domain);
      $cache_cleared = $success;
    } else {
      wp_send_json_error('Invalid action type');
    }

    wp_send_json_success([
      'cache_cleared' => $cache_cleared,
      'message' => $cache_cleared ? 'Domain updated and cache cleared' : 'Domain updated'
    ]);
  }

  /**
   * Handle suspicious domain management
   */
  public function handle_manage_suspicious_domains()
  {
    $this->verify_nonce_and_capability('manage_options');

    $action_type = sanitize_text_field($_POST['action_type'] ?? '');
    $domain = sanitize_text_field($_POST['domain'] ?? '');

    if (!$domain || !$this->domain_manager) {
      wp_send_json_error('Invalid domain or domain manager not available');
    }

    $cache_cleared = false;

    if ($action_type === 'add') {
      $success = $this->domain_manager->add_to_suspicious($domain);
      $cache_cleared = $success;
    } elseif ($action_type === 'remove') {
      $success = $this->domain_manager->remove_from_suspicious($domain);
      $cache_cleared = $success;
    } else {
      wp_send_json_error('Invalid action type');
    }

    wp_send_json_success([
      'cache_cleared' => $cache_cleared,
      'message' => $cache_cleared ? 'Domain updated and cache cleared' : 'Domain updated'
    ]);
  }

  /**
   * Handle export suspicious users
   */
  public function handle_export_suspicious_users()
  {
    $this->verify_nonce_and_capability('manage_options');

    $user_ids = $_POST['user_ids'] ?? [];

    if (!$this->export_import) {
      wp_send_json_error('Export functionality not available');
    }

    $result = $this->export_import->export_suspicious_users($user_ids);

    if ($result['success']) {
      wp_send_json_success($result);
    } else {
      wp_send_json_error($result['message']);
    }
  }

  /**
   * Handle export domain lists
   */
  public function handle_export_domain_lists()
  {
    $this->verify_nonce_and_capability('manage_options');

    if (!$this->export_import) {
      wp_send_json_error('Export functionality not available');
    }

    $result = $this->export_import->export_domain_lists();
    wp_send_json_success($result);
  }

  /**
   * Handle import domain lists
   */
  public function handle_import_domain_lists()
  {
    $this->verify_nonce_and_capability('manage_options');

    $merge_mode = $_POST['merge_mode'] ?? 'replace';

    if (!isset($_FILES['import_file']) || !$this->export_import) {
      wp_send_json_error('No file uploaded or import functionality not available');
    }

    $result = $this->export_import->import_domain_lists($_FILES['import_file'], $merge_mode);

    if ($result['success']) {
      wp_send_json_success($result);
    } else {
      wp_send_json_error($result['message']);
    }
  }

  /**
   * Handle get domain list
   */
  public function handle_get_domain_list()
  {
    $this->verify_nonce_and_capability('manage_options');

    $list_type = sanitize_text_field($_POST['list_type'] ?? '');

    if (!$this->domain_manager) {
      wp_send_json_error('Domain manager not available');
    }

    if ($list_type === 'whitelist') {
      $domains = $this->domain_manager->get_whitelist();
    } elseif ($list_type === 'suspicious') {
      $domains = $this->domain_manager->get_suspicious_domains();
    } else {
      wp_send_json_error('Invalid list type');
      return;
    }

    wp_send_json_success($domains);
  }

  /**
   * Handle clear cache request
   */
  public function handle_clear_spam_cache()
  {
    $this->verify_nonce_and_capability('manage_options');

    if (!$this->cache_manager) {
      wp_send_json_error('Cache manager not available');
    }

    $cache_cleared = $this->cache_manager->clear_all_user_cache();
    $cache_stats = $this->cache_manager->get_cache_stats();

    wp_send_json_success([
      'message' => $cache_cleared ? 'Cache cleared successfully' : 'No cache entries to clear',
      'cache_cleared' => $cache_cleared,
      'stats' => $cache_stats,
      'timestamp' => current_time('mysql')
    ]);
  }

  /**
   * Verify nonce and user capability
   */
  private function verify_nonce_and_capability($capability = 'manage_options')
  {
    check_ajax_referer('spam_detective_nonce', 'nonce');

    if (!current_user_can($capability)) {
      wp_die('Insufficient permissions');
    }
  }

  /**
   * Sort users by risk level and registration date
   */
  private function sort_users_by_risk_and_date($a, $b)
  {
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
  }
}
