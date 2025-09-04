<?php

/**
 * Main Spam Detection Analyzer Class - Refactored
 * 
 * File: includes/spam-analyzer.php
 */

if (!defined('ABSPATH')) {
  exit;
}

class SpamDetective_Analyzer
{
  private $user_analyzer;
  private $user_manager;
  private $domain_manager;
  private $export_import;
  private $cache_manager;
  private $woocommerce_integration;
  private $ajax_handler;

  public function __construct()
  {
    $this->init_components();
    $this->ajax_handler->register_handlers();
  }

  /**
   * Initialize all component classes
   */
  private function init_components()
  {
    // Initialize cache manager first as other components may depend on it
    $this->cache_manager = new SpamDetective_CacheManager();

    // Initialize WooCommerce integration
    $this->woocommerce_integration = new SpamDetective_WooCommerceIntegration();

    // Initialize domain manager
    $this->domain_manager = new SpamDetective_DomainManager($this->cache_manager);

    // Initialize user analyzer
    $this->user_analyzer = new SpamDetective_UserAnalyzer();

    // Initialize user manager
    $this->user_manager = new SpamDetective_UserManager(
      $this->woocommerce_integration,
      $this->cache_manager
    );

    // Initialize export/import
    $this->export_import = new SpamDetective_ExportImport(
      $this->user_manager,
      $this->user_analyzer,
      $this->domain_manager
    );

    // Initialize AJAX handler with all components
    $this->ajax_handler = new SpamDetective_AjaxHandler(
      $this->user_analyzer,
      $this->user_manager,
      $this->domain_manager,
      $this->export_import,
      $this->cache_manager,
      $this->woocommerce_integration
    );
  }

  /**
   * Get user analyzer instance
   */
  public function get_user_analyzer()
  {
    return $this->user_analyzer;
  }

  /**
   * Get user manager instance
   */
  public function get_user_manager()
  {
    return $this->user_manager;
  }

  /**
   * Get domain manager instance
   */
  public function get_domain_manager()
  {
    return $this->domain_manager;
  }

  /**
   * Get export/import instance
   */
  public function get_export_import()
  {
    return $this->export_import;
  }

  /**
   * Get cache manager instance
   */
  public function get_cache_manager()
  {
    return $this->cache_manager;
  }

  /**
   * Get WooCommerce integration instance
   */
  public function get_woocommerce_integration()
  {
    return $this->woocommerce_integration;
  }

  /**
   * Get AJAX handler instance
   */
  public function get_ajax_handler()
  {
    return $this->ajax_handler;
  }

  /**
   * Legacy method for backward compatibility
   * @deprecated Use the individual component methods instead
   */
  public function analyze_user($user, $whitelist = [], $suspicious_domains = [])
  {
    error_log('SpamDetective_Analyzer::analyze_user() is deprecated. Use get_user_analyzer()->analyze_user() instead.');
    return $this->user_analyzer->analyze_user($user, $whitelist, $suspicious_domains);
  }

  /**
   * Get system information for debugging
   */
  public function get_system_info()
  {
    return [
      'components' => [
        'user_analyzer' => class_exists('SpamDetective_UserAnalyzer'),
        'user_manager' => class_exists('SpamDetective_UserManager'),
        'domain_manager' => class_exists('SpamDetective_DomainManager'),
        'export_import' => class_exists('SpamDetective_ExportImport'),
        'cache_manager' => class_exists('SpamDetective_CacheManager'),
        'woocommerce_integration' => class_exists('SpamDetective_WooCommerceIntegration'),
        'ajax_handler' => class_exists('SpamDetective_AjaxHandler')
      ],
      'cache_stats' => $this->cache_manager ? $this->cache_manager->get_cache_stats() : null,
      'woocommerce_active' => $this->woocommerce_integration ? $this->woocommerce_integration->is_woocommerce_active() : false,
      'domain_counts' => [
        'whitelist' => count($this->domain_manager ? $this->domain_manager->get_whitelist() : []),
        'suspicious' => count($this->domain_manager ? $this->domain_manager->get_suspicious_domains() : [])
      ],
      'protected_roles' => $this->user_manager ? $this->user_manager->get_protected_roles() : []
    ];
  }

  /**
   * Run system health check
   */
  public function health_check()
  {
    $issues = [];

    // Check if all required components are loaded
    $required_components = [
      'SpamDetective_UserAnalyzer',
      'SpamDetective_UserManager',
      'SpamDetective_DomainManager',
      'SpamDetective_ExportImport',
      'SpamDetective_CacheManager',
      'SpamDetective_WooCommerceIntegration',
      'SpamDetective_AjaxHandler'
    ];

    foreach ($required_components as $component) {
      if (!class_exists($component)) {
        $issues[] = "Missing required component: {$component}";
      }
    }

    // Check cache functionality
    if ($this->cache_manager && !$this->cache_manager->is_caching_enabled()) {
      $issues[] = "Caching is disabled - performance may be impacted";
    }

    // Check database connectivity
    global $wpdb;
    if ($wpdb->last_error) {
      $issues[] = "Database error detected: " . $wpdb->last_error;
    }

    // Check memory usage
    $memory_limit = wp_convert_hr_to_bytes(ini_get('memory_limit'));
    $memory_usage = memory_get_usage(true);
    if ($memory_usage > ($memory_limit * 0.8)) {
      $issues[] = "High memory usage detected: " . size_format($memory_usage) . " of " . size_format($memory_limit);
    }

    return [
      'healthy' => empty($issues),
      'issues' => $issues,
      'timestamp' => current_time('mysql')
    ];
  }

  /**
   * Clean up resources (called on plugin deactivation)
   */
  public function cleanup()
  {
    if ($this->cache_manager) {
      $this->cache_manager->clear_all_user_cache();
      error_log("Spam Detective: Cleanup completed, all caches cleared");
    }
  }
}
