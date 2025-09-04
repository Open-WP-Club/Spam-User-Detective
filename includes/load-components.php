<?php

/**
 * Modular Components Loader
 * 
 * File: includes/load-components.php
 * 
 * This file loads all the modular components in the correct order.
 * Replace the single spam-analyzer.php include with this file in the main plugin.
 */

if (!defined('ABSPATH')) {
  exit;
}

// Load components in dependency order

// 1. Load Cache Manager (no dependencies)
require_once SPAM_DETECTIVE_PLUGIN_DIR . 'includes/cache-manager.php';

// 2. Load WooCommerce Integration (no dependencies)
require_once SPAM_DETECTIVE_PLUGIN_DIR . 'includes/woocommerce-integration.php';

// 3. Load Domain Manager (depends on Cache Manager)
require_once SPAM_DETECTIVE_PLUGIN_DIR . 'includes/domain-manager.php';

// 4. Load User Analyzer (core analysis logic, no dependencies)
require_once SPAM_DETECTIVE_PLUGIN_DIR . 'includes/user-analyzer.php';

// 5. Load User Manager (depends on WooCommerce Integration and Cache Manager)
require_once SPAM_DETECTIVE_PLUGIN_DIR . 'includes/user-manager.php';

// 6. Load Export/Import (depends on User Manager, User Analyzer, and Domain Manager)
require_once SPAM_DETECTIVE_PLUGIN_DIR . 'includes/export-import.php';

// 7. Load AJAX Handler (depends on all other components)
require_once SPAM_DETECTIVE_PLUGIN_DIR . 'includes/ajax-handler.php';

// 8. Load main Analyzer class (orchestrates all components)
require_once SPAM_DETECTIVE_PLUGIN_DIR . 'includes/spam-analyzer.php';

// Log successful loading for debugging
if (defined('WP_DEBUG') && WP_DEBUG) {
  error_log('Spam Detective: All modular components loaded successfully');
}
