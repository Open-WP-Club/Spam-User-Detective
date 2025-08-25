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
  ];

  public function __construct()
  {
    add_action('wp_ajax_analyze_spam_users', [$this, 'ajax_analyze_spam_users']);
    add_action('wp_ajax_delete_spam_users', [$this, 'ajax_delete_spam_users']);
    add_action('wp_ajax_whitelist_domain', [$this, 'ajax_whitelist_domain']);
    add_action('wp_ajax_manage_suspicious_domains', [$this, 'ajax_manage_suspicious_domains']);
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
      $analysis = $this->analyze_user($user, $whitelist, $suspicious_domains);
      if ($analysis['is_suspicious']) {
        $suspicious_users[] = [
          'id' => $user->ID,
          'username' => $user->user_login,
          'email' => $user->user_email,
          'display_name' => $user->display_name,
          'registered' => $user->user_registered,
          'risk_level' => $analysis['risk_level'],
          'reasons' => $analysis['reasons']
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

    $email_domain = explode('@', $user->user_email)[1] ?? '';

    // Skip whitelisted domains
    if (in_array($email_domain, $whitelist)) {
      return ['is_suspicious' => false, 'risk_level' => 'low', 'reasons' => []];
    }

    // Check suspicious domains
    if (in_array($email_domain, $suspicious_domains)) {
      $reasons[] = 'Known spam domain';
      $risk_score += 50;
    }

    // Check username patterns
    foreach ($this->common_patterns as $pattern) {
      if (preg_match($pattern, $user->user_login)) {
        $reasons[] = 'Suspicious username pattern';
        $risk_score += 30;
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
      $risk_score += 10;
    }

    // Check for suspicious email patterns
    if (preg_match('/^[a-z]+\d+@/', $user->user_email)) {
      $reasons[] = 'Generic email pattern';
      $risk_score += 15;
    }

    // Check for bulk registrations from same domain
    $domain_count = $this->count_users_by_domain($email_domain);
    if ($domain_count > 5) {
      $reasons[] = "Bulk registration ({$domain_count} from same domain)";
      $risk_score += min(20, $domain_count);
    }

    // Check recent registration with no activity
    $reg_time = strtotime($user->user_registered);
    if (time() - $reg_time > 86400) { // More than 1 day old
      $post_count = count_user_posts($user->ID);
      $comment_count = get_comments(['user_id' => $user->ID, 'count' => true]);

      if ($post_count == 0 && $comment_count == 0) {
        $reasons[] = 'No activity since registration';
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

    foreach ($user_ids as $user_id) {
      if (wp_delete_user($user_id)) {
        $deleted++;
      }
    }

    wp_send_json_success(['deleted' => $deleted]);
  }

  public function ajax_whitelist_domain()
  {
    check_ajax_referer('spam_detective_nonce', 'nonce');

    if (!current_user_can('manage_options')) {
      wp_die('Insufficient permissions');
    }

    $action_type = sanitize_text_field($_POST['action_type'] ?? '');
    $domain = sanitize_text_field($_POST['domain'] ?? '');

    if (!$domain) {
      wp_send_json_error('Invalid domain');
    }

    $whitelist = get_option('spam_detective_whitelist', []);

    if ($action_type === 'add') {
      if (!in_array($domain, $whitelist)) {
        $whitelist[] = $domain;
        update_option('spam_detective_whitelist', $whitelist);
      }
    } elseif ($action_type === 'remove') {
      $whitelist = array_filter($whitelist, function ($d) use ($domain) {
        return $d !== $domain;
      });
      update_option('spam_detective_whitelist', array_values($whitelist));
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
    $domain = sanitize_text_field($_POST['domain'] ?? '');

    if (!$domain) {
      wp_send_json_error('Invalid domain');
    }

    $suspicious_domains = get_option('spam_detective_suspicious_domains', []);

    if ($action_type === 'add') {
      if (!in_array($domain, $suspicious_domains)) {
        $suspicious_domains[] = $domain;
        update_option('spam_detective_suspicious_domains', $suspicious_domains);
      }
    } elseif ($action_type === 'remove') {
      $suspicious_domains = array_filter($suspicious_domains, function ($d) use ($domain) {
        return $d !== $domain;
      });
      update_option('spam_detective_suspicious_domains', array_values($suspicious_domains));
    }

    wp_send_json_success();
  }
}
