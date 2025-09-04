<?php

/**
 * User Management Class
 * 
 * File: includes/user-manager.php
 */

if (!defined('ABSPATH')) {
  exit;
}

class SpamDetective_UserManager
{
  // Protected roles that cannot be deleted
  private $protected_roles = ['administrator', 'editor', 'shop_manager'];

  private $woocommerce_integration;
  private $cache_manager;

  public function __construct($woocommerce_integration = null, $cache_manager = null)
  {
    $this->woocommerce_integration = $woocommerce_integration;
    $this->cache_manager = $cache_manager;
  }

  /**
   * Check if user has protected role
   */
  public function is_protected_user($user)
  {
    $user_roles = $this->get_user_roles($user);
    return !empty(array_intersect($user_roles, $this->protected_roles));
  }

  /**
   * Check if user can be deleted (not protected)
   */
  public function can_delete_user($user)
  {
    return !$this->is_protected_user($user);
  }

  /**
   * Get user roles
   */
  public function get_user_roles($user)
  {
    $user_data = get_userdata($user->ID);
    return $user_data ? $user_data->roles : [];
  }

  /**
   * Get protected roles list
   */
  public function get_protected_roles()
  {
    return $this->protected_roles;
  }

  /**
   * Delete users with safety checks
   */
  public function delete_users($user_ids, $force_delete = false)
  {
    if (!current_user_can('delete_users')) {
      return ['success' => false, 'message' => 'Insufficient permissions'];
    }

    $deleted = 0;
    $skipped = 0;
    $protected_users = [];
    $users_with_orders = [];

    foreach ($user_ids as $user_id) {
      $user = get_user_by('ID', $user_id);

      if (!$user) {
        $skipped++;
        continue;
      }

      // Check if user is protected by role
      if ($this->is_protected_user($user)) {
        $skipped++;
        $protected_users[] = $user->user_login;
        continue;
      }

      // Additional check for WooCommerce orders if force delete not enabled
      if (
        !$force_delete && $this->woocommerce_integration &&
        $this->woocommerce_integration->has_meaningful_woocommerce_orders($user_id)
      ) {
        $skipped++;
        $users_with_orders[] = $user->user_login;
        error_log("Spam Detective: Skipping deletion of user {$user->user_login} (ID: {$user_id}) - has meaningful WooCommerce orders");
        continue;
      }

      if (wp_delete_user($user_id)) {
        $this->clear_user_cache($user_id);
        $deleted++;
        error_log("Spam Detective: Deleted user {$user->user_login} (ID: {$user_id})");
      } else {
        $skipped++;
        error_log("Spam Detective: Failed to delete user {$user->user_login} (ID: {$user_id})");
      }
    }

    // Build detailed message
    $message_parts = [];
    if ($deleted > 0) {
      $message_parts[] = "Deleted {$deleted} users";
    }

    if ($skipped > 0) {
      $reasons = [];
      if (!empty($protected_users)) {
        $reasons[] = count($protected_users) . " protected by role";
      }
      if (!empty($users_with_orders)) {
        $reasons[] = count($users_with_orders) . " with orders";
      }
      if (empty($reasons)) {
        $reasons[] = "{$skipped} for various reasons";
      }
      $message_parts[] = "Skipped " . implode(", ", $reasons);
    }

    $message = implode(". ", $message_parts) . ".";

    return [
      'success' => true,
      'deleted' => $deleted,
      'skipped' => $skipped,
      'message' => $message,
      'protected_users' => $protected_users,
      'users_with_orders' => $users_with_orders
    ];
  }

  /**
   * Clear cache for deleted users
   */
  private function clear_user_cache($user_id)
  {
    if ($this->cache_manager) {
      $this->cache_manager->clear_user_cache($user_id);
    }

    // Also clear WooCommerce order cache if available
    if ($this->woocommerce_integration) {
      $this->woocommerce_integration->clear_user_order_cache($user_id);
    }
  }

  /**
   * Get users for analysis
   */
  public function get_users_for_analysis($quick_scan = false)
  {
    $limit = $quick_scan ? 100 : -1;

    return get_users([
      'number' => $limit,
      'orderby' => 'registered',
      'order' => 'DESC'
    ]);
  }

  /**
   * Get user analysis data for export
   */
  public function get_user_export_data($user, $analysis)
  {
    return [
      $user->ID,
      $user->user_login,
      $user->user_email,
      $user->display_name,
      $user->user_registered,
      $analysis['risk_level'],
      implode('; ', $analysis['reasons']),
      implode(', ', $this->get_user_roles($user)),
      $this->woocommerce_integration && $this->woocommerce_integration->has_meaningful_woocommerce_orders($user->ID) ? 'Yes' : 'No',
      $this->can_delete_user($user) ? 'Yes' : 'No'
    ];
  }

  /**
   * Format user data for frontend display
   */
  public function format_user_for_display($user, $analysis)
  {
    return [
      'id' => $user->ID,
      'username' => $user->user_login,
      'email' => $user->user_email,
      'display_name' => $user->display_name,
      'registered' => $user->user_registered,
      'risk_level' => $analysis['risk_level'],
      'reasons' => $analysis['reasons'],
      'can_delete' => $this->can_delete_user($user),
      'has_orders' => $this->woocommerce_integration ? $this->woocommerce_integration->has_woocommerce_orders($user->ID) : false,
      'roles' => $this->get_user_roles($user)
    ];
  }
}
