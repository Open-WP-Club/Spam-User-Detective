<?php

/**
 * Cache Management Class
 * 
 * File: includes/cache-manager.php
 */

if (!defined('ABSPATH')) {
  exit;
}

class SpamDetective_CacheManager
{
  const CACHE_DURATION = 24 * HOUR_IN_SECONDS; // 24 hours
  const CACHE_PREFIX = 'spam_detective_';

  /**
   * Get user analysis from cache
   */
  public function get_user_analysis($user_id, $user_registered, $user_email)
  {
    $cache_key = $this->get_user_cache_key($user_id, $user_registered, $user_email);
    return get_transient($cache_key);
  }

  /**
   * Set user analysis in cache
   */
  public function set_user_analysis($user_id, $user_registered, $user_email, $analysis)
  {
    $cache_key = $this->get_user_cache_key($user_id, $user_registered, $user_email);
    return set_transient($cache_key, $analysis, self::CACHE_DURATION);
  }

  /**
   * Clear cache for specific user
   */
  public function clear_user_cache($user_id)
  {
    $user = get_user_by('ID', $user_id);
    if ($user) {
      $cache_key = $this->get_user_cache_key($user_id, $user->user_registered, $user->user_email);
      delete_transient($cache_key);
    }
  }

  /**
   * Clear all user analysis cache
   */
  public function clear_all_user_cache()
  {
    global $wpdb;

    // Use the broader pattern to catch all spam detective transients
    $deleted = $wpdb->query(
      "DELETE FROM {$wpdb->options} 
       WHERE option_name LIKE '_transient_" . self::CACHE_PREFIX . "%' 
       OR option_name LIKE '_transient_timeout_" . self::CACHE_PREFIX . "%'"
    );

    // Also clear object cache if available
    if (function_exists('wp_cache_flush_group')) {
      wp_cache_flush_group('spam_detective');
    }

    error_log("Spam Detective: Cleared {$deleted} cache entries");

    // Return whether cache was actually cleared
    return $deleted > 0;
  }

  /**
   * Get cache statistics
   */
  public function get_cache_stats()
  {
    global $wpdb;

    $total_transients = $wpdb->get_var(
      "SELECT COUNT(*) FROM {$wpdb->options} 
       WHERE option_name LIKE '_transient_" . self::CACHE_PREFIX . "%'"
    );

    $expired_transients = $wpdb->get_var(
      "SELECT COUNT(*) FROM {$wpdb->options} a, {$wpdb->options} b 
       WHERE a.option_name LIKE '_transient_" . self::CACHE_PREFIX . "%' 
       AND b.option_name = CONCAT('_transient_timeout_', SUBSTRING(a.option_name, 12)) 
       AND b.option_value < UNIX_TIMESTAMP()"
    );

    return [
      'total_cached' => (int) $total_transients,
      'expired' => (int) $expired_transients,
      'active' => (int) $total_transients - (int) $expired_transients
    ];
  }

  /**
   * Clean up expired transients
   */
  public function cleanup_expired_cache()
  {
    global $wpdb;

    // Remove expired transients (WordPress doesn't auto-cleanup expired transients)
    $deleted = $wpdb->query(
      "DELETE a, b FROM {$wpdb->options} a, {$wpdb->options} b 
       WHERE a.option_name LIKE '_transient_%' 
       AND a.option_name NOT LIKE '_transient_timeout_%' 
       AND b.option_name = CONCAT('_transient_timeout_', SUBSTRING(a.option_name, 12)) 
       AND b.option_value < UNIX_TIMESTAMP()
       AND a.option_name LIKE '%spam_detective%'"
    );

    if ($deleted > 0) {
      error_log("Spam Detective: Cleaned up {$deleted} expired cache entries");
    }

    return $deleted;
  }

  /**
   * Generate cache key for user analysis
   */
  private function get_user_cache_key($user_id, $user_registered, $user_email)
  {
    return self::CACHE_PREFIX . 'user_' . $user_id . '_' . md5($user_registered . $user_email);
  }

  /**
   * Check if caching is enabled
   */
  public function is_caching_enabled()
  {
    $settings = get_option('spam_detective_settings', []);
    return isset($settings['enable_caching']) ? $settings['enable_caching'] : true;
  }

  /**
   * Get cache duration from settings
   */
  public function get_cache_duration()
  {
    $settings = get_option('spam_detective_settings', []);
    $hours = isset($settings['cache_duration']) ? (int) $settings['cache_duration'] : 24;
    return $hours * HOUR_IN_SECONDS;
  }

  /**
   * Warm up cache for specific users
   */
  public function warmup_user_cache($user_ids, $analyzer, $whitelist = [], $suspicious_domains = [])
  {
    $warmed_up = 0;

    foreach ($user_ids as $user_id) {
      $user = get_user_by('ID', $user_id);
      if (!$user) {
        continue;
      }

      $cache_key = $this->get_user_cache_key($user_id, $user->user_registered, $user->user_email);

      // Only warm up if not already cached
      if (get_transient($cache_key) === false) {
        $analysis = $analyzer->analyze_user($user, $whitelist, $suspicious_domains);
        $this->set_user_analysis($user_id, $user->user_registered, $user->user_email, $analysis);
        $warmed_up++;
      }
    }

    error_log("Spam Detective: Warmed up cache for {$warmed_up} users");
    return $warmed_up;
  }
}
