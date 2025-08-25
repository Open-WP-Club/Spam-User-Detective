<?php

/**
 * Plugin Name: Spam User Detective
 * Description: Advanced spam and bot user detection for WordPress/WooCommerce
 * Version: 1.0
 * Author: Your Name
 */

// Prevent direct access
if (!defined('ABSPATH')) {
  exit;
}

// Define plugin constants
define('SPAM_DETECTIVE_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('SPAM_DETECTIVE_PLUGIN_URL', plugin_dir_url(__FILE__));

// Include required files
require_once SPAM_DETECTIVE_PLUGIN_DIR . 'includes/spam-analyzer.php';
require_once SPAM_DETECTIVE_PLUGIN_DIR . 'includes/admin-interface.php';

class SpamUserDetective
{

  public function __construct()
  {
    add_action('admin_menu', [$this, 'add_admin_menu']);
    add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);

    // Initialize components
    new SpamDetective_Analyzer();
    new SpamDetective_AdminInterface();
  }

  public function add_admin_menu()
  {
    add_users_page(
      'Spam User Detective',
      'Spam Detective',
      'manage_options',
      'spam-user-detective',
      [$this, 'admin_page']
    );
  }

  public function enqueue_scripts($hook)
  {
    if ($hook !== 'users_page_spam-user-detective') return;

    wp_enqueue_script('jquery');
    wp_enqueue_style(
      'spam-detective-css',
      SPAM_DETECTIVE_PLUGIN_URL . 'assets/style.css',
      [],
      '1.0.0'
    );
    wp_enqueue_script(
      'spam-detective-js',
      SPAM_DETECTIVE_PLUGIN_URL . 'assets/script.js',
      ['jquery'],
      '1.0.0',
      true
    );

    // Localize script
    wp_localize_script('spam-detective-js', 'spamDetective', [
      'ajaxUrl' => admin_url('admin-ajax.php'),
      'nonce' => wp_create_nonce('spam_detective_nonce')
    ]);
  }

  public function admin_page()
  {
    $admin_interface = new SpamDetective_AdminInterface();
    $admin_interface->display_page();
  }
}

// Initialize the plugin
new SpamUserDetective();
