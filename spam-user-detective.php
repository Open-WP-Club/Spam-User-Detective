<?php

/**
 * Plugin Name: Spam User Detective
 * Plugin URI: https://github.com/Open-WP-Club/Spam-User-Detective
 * Description: Advanced spam and bot user detection for WordPress/WooCommerce with role protection, caching, and export features
 * Version: 1.1.0
 * Author: Open WP Club
 * Author URI: https://github.com/Open-WP-Club
 * Text Domain: spam-user-detective
 * Requires at least: 5.0
 * Tested up to: 6.4
 * Requires PHP: 7.4
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * GitHub Plugin URI: Open-WP-Club/Spam-User-Detective
 */

// Prevent direct access
if (!defined('ABSPATH')) {
  exit;
}

// Define plugin constants
define('SPAM_DETECTIVE_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('SPAM_DETECTIVE_PLUGIN_URL', plugin_dir_url(__FILE__));
define('SPAM_DETECTIVE_VERSION', '1.1.0');
define('SPAM_DETECTIVE_MIN_PHP', '7.4');
define('SPAM_DETECTIVE_MIN_WP', '5.0');

// Include required files
require_once SPAM_DETECTIVE_PLUGIN_DIR . 'includes/spam-analyzer.php';
require_once SPAM_DETECTIVE_PLUGIN_DIR . 'includes/admin-interface.php';

class SpamUserDetective
{
  private static $instance = null;

  public static function get_instance()
  {
    if (null === self::$instance) {
      self::$instance = new self();
    }
    return self::$instance;
  }

  private function __construct()
  {
    // Check system requirements
    add_action('admin_init', [$this, 'check_requirements']);

    // Initialize plugin
    add_action('init', [$this, 'init']);
    add_action('admin_menu', [$this, 'add_admin_menu']);
    add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);

    // Cache management
    add_action('wp_ajax_clear_spam_cache', [$this, 'ajax_clear_spam_cache']);

    // Plugin lifecycle
    register_activation_hook(__FILE__, [$this, 'activate']);
    register_deactivation_hook(__FILE__, [$this, 'deactivate']);

    // Initialize components
    new SpamDetective_Analyzer();
  }

  public function init()
  {
    // Load textdomain for translations (if you plan to add them later)
    load_plugin_textdomain('spam-user-detective', false, dirname(plugin_basename(__FILE__)) . '/languages');

    // Initialize default settings
    $this->init_default_settings();
  }

  public function check_requirements()
  {
    // Check PHP version
    if (version_compare(PHP_VERSION, SPAM_DETECTIVE_MIN_PHP, '<')) {
      add_action('admin_notices', function () {
        echo '<div class="notice notice-error"><p>';
        printf(
          __('Spam User Detective requires PHP version %s or higher. You are running PHP %s.', 'spam-user-detective'),
          SPAM_DETECTIVE_MIN_PHP,
          PHP_VERSION
        );
        echo '</p></div>';
      });
      return;
    }

    // Check WordPress version
    global $wp_version;
    if (version_compare($wp_version, SPAM_DETECTIVE_MIN_WP, '<')) {
      add_action('admin_notices', function () use ($wp_version) {
        echo '<div class="notice notice-error"><p>';
        printf(
          __('Spam User Detective requires WordPress version %s or higher. You are running WordPress %s.', 'spam-user-detective'),
          SPAM_DETECTIVE_MIN_WP,
          $wp_version
        );
        echo '</p></div>';
      });
      return;
    }
  }

  public function init_default_settings()
  {
    // Initialize settings
    if (false === get_option('spam_detective_settings')) {
      $default_settings = [
        'cache_duration' => 24, // hours
        'batch_size' => 100,
        'risk_threshold_high' => 70,
        'risk_threshold_medium' => 40,
        'risk_threshold_low' => 25,
        'protect_users_with_orders' => true,
        'enable_caching' => true
      ];
      add_option('spam_detective_settings', $default_settings);
    }
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

    // Enqueue WordPress media scripts for file handling
    wp_enqueue_media();

    wp_enqueue_script('jquery');
    wp_enqueue_style(
      'spam-detective-css',
      SPAM_DETECTIVE_PLUGIN_URL . 'assets/style.css',
      [],
      SPAM_DETECTIVE_VERSION
    );
    wp_enqueue_script(
      'spam-detective-js',
      SPAM_DETECTIVE_PLUGIN_URL . 'assets/script.js',
      ['jquery'],
      SPAM_DETECTIVE_VERSION,
      true
    );

    // Localize script with enhanced data
    wp_localize_script('spam-detective-js', 'spamDetective', [
      'ajaxUrl' => admin_url('admin-ajax.php'),
      'nonce' => wp_create_nonce('spam_detective_nonce'),
      'settings' => get_option('spam_detective_settings', []),
      'isWooCommerceActive' => class_exists('WooCommerce'),
      'uploadUrl' => admin_url('admin-ajax.php'),
      'maxFileSize' => wp_max_upload_size(),
      'allowedFileTypes' => ['json'],
      'strings' => [
        'confirmDelete' => __('Are you sure you want to delete these users? This action cannot be undone.', 'spam-user-detective'),
        'confirmDeleteWithOrders' => __('Some selected users have WooCommerce orders. Are you sure you want to delete them?', 'spam-user-detective'),
        'noUsersSelected' => __('Please select users to perform this action.', 'spam-user-detective'),
        'exportSuccess' => __('Export completed successfully.', 'spam-user-detective'),
        'importSuccess' => __('Import completed successfully.', 'spam-user-detective'),
        'cacheCleared' => __('Cache cleared successfully.', 'spam-user-detective'),
        'processing' => __('Processing...', 'spam-user-detective'),
        'error' => __('An error occurred. Please try again.', 'spam-user-detective')
      ]
    ]);
  }

  public function admin_page()
  {
    // Security check
    if (!current_user_can('manage_options')) {
      wp_die(__('You do not have sufficient permissions to access this page.', 'spam-user-detective'));
    }

    $admin_interface = new SpamDetective_AdminInterface();
    $admin_interface->display_page();
  }

  /**
   * AJAX handler to clear spam detection cache
   */
  public function ajax_clear_spam_cache()
  {
    check_ajax_referer('spam_detective_nonce', 'nonce');

    if (!current_user_can('manage_options')) {
      wp_die('Insufficient permissions');
    }

    global $wpdb;

    // Clear all spam detective transients
    $deleted = $wpdb->query(
      "DELETE FROM {$wpdb->options} 
       WHERE option_name LIKE '_transient_spam_detective_%' 
       OR option_name LIKE '_transient_timeout_spam_detective_%'"
    );

    // Also clear any object cache if available
    if (function_exists('wp_cache_flush_group')) {
      wp_cache_flush_group('spam_detective');
    }

    wp_send_json_success([
      'message' => sprintf(__('Cleared %d cache entries.', 'spam-user-detective'), $deleted),
      'deleted' => $deleted
    ]);
  }

  /**
   * Plugin activation
   */
  public function activate()
  {
    // Check requirements on activation
    if (version_compare(PHP_VERSION, SPAM_DETECTIVE_MIN_PHP, '<')) {
      deactivate_plugins(plugin_basename(__FILE__));
      wp_die(sprintf(
        __('Spam User Detective requires PHP version %s or higher.', 'spam-user-detective'),
        SPAM_DETECTIVE_MIN_PHP
      ));
    }

    // Initialize settings
    $this->init_default_settings();

    // Create activation timestamp
    add_option('spam_detective_activated', current_time('timestamp'));

    // Schedule cleanup of old cache entries (optional)
    if (!wp_next_scheduled('spam_detective_cleanup_cache')) {
      wp_schedule_event(time(), 'daily', 'spam_detective_cleanup_cache');
    }
  }

  /**
   * Plugin deactivation
   */
  public function deactivate()
  {
    // Clear all caches on deactivation
    global $wpdb;
    $wpdb->query(
      "DELETE FROM {$wpdb->options} 
       WHERE option_name LIKE '_transient_spam_detective_%' 
       OR option_name LIKE '_transient_timeout_spam_detective_%'"
    );

    // Clear scheduled events
    wp_clear_scheduled_hook('spam_detective_cleanup_cache');
  }

  /**
   * Get plugin information
   */
  public static function get_plugin_info()
  {
    return [
      'version' => SPAM_DETECTIVE_VERSION,
      'php_version' => PHP_VERSION,
      'wp_version' => get_bloginfo('version'),
      'woocommerce_active' => class_exists('WooCommerce'),
      'woocommerce_version' => class_exists('WooCommerce') ? WC()->version : null,
      'cache_enabled' => true,
      'protected_roles' => ['administrator', 'editor', 'shop_manager']
    ];
  }
}

// Scheduled cache cleanup task
add_action('spam_detective_cleanup_cache', function () {
  global $wpdb;

  // Remove expired transients (WordPress doesn't auto-cleanup expired transients)
  $wpdb->query(
    "DELETE a, b FROM {$wpdb->options} a, {$wpdb->options} b 
     WHERE a.option_name LIKE '_transient_%' 
     AND a.option_name NOT LIKE '_transient_timeout_%' 
     AND b.option_name = CONCAT('_transient_timeout_', SUBSTRING(a.option_name, 12)) 
     AND b.option_value < UNIX_TIMESTAMP()
     AND a.option_name LIKE '%spam_detective%'"
  );
});

// Add settings link to plugin page
add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($links) {
  $settings_link = '<a href="' . admin_url('users.php?page=spam-user-detective') . '">' . __('Settings', 'spam-user-detective') . '</a>';
  array_unshift($links, $settings_link);
  return $links;
});

// Add plugin meta links
add_filter('plugin_row_meta', function ($links, $file) {
  if (plugin_basename(__FILE__) === $file) {
    $meta_links = [
      'github' => '<a href="https://github.com/Open-WP-Club/Spam-User-Detective" target="_blank">' . __('GitHub Repository', 'spam-user-detective') . '</a>',
      'issues' => '<a href="https://github.com/Open-WP-Club/Spam-User-Detective/issues" target="_blank">' . __('Report Issues', 'spam-user-detective') . '</a>',
      'docs' => '<a href="https://github.com/Open-WP-Club/Spam-User-Detective#readme" target="_blank">' . __('Documentation', 'spam-user-detective') . '</a>'
    ];
    return array_merge($links, $meta_links);
  }
  return $links;
}, 10, 2);

// Admin notice for new installations
add_action('admin_notices', function () {
  if (get_option('spam_detective_show_welcome', false)) {
?>
    <div class="notice notice-success is-dismissible">
      <h3><?php _e('Welcome to Spam User Detective!', 'spam-user-detective'); ?></h3>
      <p>
        <?php _e('Thank you for installing Spam User Detective. Please create a backup before using the tool.', 'spam-user-detective'); ?>
        <a href="<?php echo admin_url('users.php?page=spam-user-detective'); ?>" class="button button-primary" style="margin-left: 10px;">
          <?php _e('Get Started', 'spam-user-detective'); ?>
        </a>
      </p>
      <p>
        <small>
          <?php printf(__('Need help? Check out the <a href="%s" target="_blank">GitHub repository</a> for documentation and support.', 'spam-user-detective'), 'https://github.com/Open-WP-Club/Spam-User-Detective'); ?>
        </small>
      </p>
    </div>
    <script>
      jQuery(document).on('click', '.notice-dismiss', function() {
        jQuery.post(ajaxurl, {
          action: 'dismiss_spam_detective_welcome',
          nonce: '<?php echo wp_create_nonce('dismiss_welcome'); ?>'
        });
      });
    </script>
<?php
    delete_option('spam_detective_show_welcome');
  }
});

// Handle welcome notice dismissal
add_action('wp_ajax_dismiss_spam_detective_welcome', function () {
  check_ajax_referer('dismiss_welcome', 'nonce');
  delete_option('spam_detective_show_welcome');
  wp_die();
});

// Set welcome notice flag on activation
register_activation_hook(__FILE__, function () {
  add_option('spam_detective_show_welcome', true);
});

// Initialize the plugin
SpamUserDetective::get_instance();
