<?php

/**
 * WooCommerce Integration Class
 * 
 * File: includes/class-woocommerce-integration.php
 */

if (!defined('ABSPATH')) {
  exit;
}

class SpamDetective_WooCommerceIntegration
{
  /**
   * Check if WooCommerce is active
   */
  public function is_woocommerce_active()
  {
    return class_exists('WooCommerce');
  }

  /**
   * Enhanced method to check if user has meaningful WooCommerce orders
   * This includes completed, processing, and on-hold orders (showing legitimate customer activity)
   */
  public function has_meaningful_woocommerce_orders($user_id)
  {
    if (!$this->is_woocommerce_active()) {
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
  public function has_fulfilled_woocommerce_orders($user_id)
  {
    return $this->has_meaningful_woocommerce_orders($user_id);
  }

  /**
   * Check if user has WooCommerce orders (any status) - used for display purposes
   */
  public function has_woocommerce_orders($user_id)
  {
    if (!$this->is_woocommerce_active()) {
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
   * Get order count for a user
   */
  public function get_user_order_count($user_id)
  {
    if (!$this->is_woocommerce_active()) {
      return 0;
    }

    $orders = wc_get_orders([
      'customer_id' => $user_id,
      'status' => ['completed', 'processing', 'on-hold'],
      'return' => 'ids'
    ]);

    return count($orders);
  }

  /**
   * Clear order-related cache for a user
   */
  public function clear_user_order_cache($user_id)
  {
    $order_cache_key = 'spam_detective_orders_' . $user_id;
    delete_transient($order_cache_key);
  }

  /**
   * Get user's latest order date
   */
  public function get_user_latest_order_date($user_id)
  {
    if (!$this->is_woocommerce_active()) {
      return null;
    }

    $orders = wc_get_orders([
      'customer_id' => $user_id,
      'limit' => 1,
      'orderby' => 'date',
      'order' => 'DESC',
      'status' => ['completed', 'processing', 'on-hold']
    ]);

    if (!empty($orders)) {
      return $orders[0]->get_date_created();
    }

    return null;
  }

  /**
   * Get user's total spent amount
   */
  public function get_user_total_spent($user_id)
  {
    if (!$this->is_woocommerce_active()) {
      return 0;
    }

    $customer = new WC_Customer($user_id);
    return $customer->get_total_spent();
  }
}
