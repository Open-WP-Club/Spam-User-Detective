<?php

/**
 * Core User Analysis Class
 * 
 * File: includes/class-user-analyzer.php
 */

if (!defined('ABSPATH')) {
  exit;
}

class SpamDetective_UserAnalyzer
{
  private $common_patterns = [
    '/^[a-z]{6,12}$/',  // Random lowercase letters
    '/^[a-z]+\d+$/',    // Letters followed by numbers
    '/^\w+\-\d+$/',     // Word-number pattern like "wispaky-6855"
    '/^[bcdfghjklmnpqrstvwxyz]{4,8}[aeiou]{1,3}[bcdfghjklmnpqrstvwxyz]{2,6}$/', // Consonant-vowel-consonant patterns
    '/^[a-z]{1,3}(\.[a-z]{1,3}){3,}$/', // Multiple dots pattern like "ja.me.sw.o.o.ds.ii.ii.v"
    '/^[a-z]+(\.[a-z]+){2,}$/', // General multiple dots pattern
  ];

  /**
   * Analyze a user for spam indicators
   */
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

    $risk_score += $this->analyze_username_patterns($user->user_login, $reasons);
    $risk_score += $this->analyze_display_name($user, $reasons);
    $risk_score += $this->analyze_email_patterns($user->user_email, $reasons);
    $risk_score += $this->analyze_user_names($user, $reasons);
    $risk_score += $this->analyze_bulk_registrations($email_domain, $reasons);
    $risk_score += $this->analyze_sequential_usernames($user->user_login, $reasons);
    $risk_score += $this->analyze_registration_burst($user->user_registered, $reasons);
    $risk_score += $this->analyze_user_activity($user, $reasons);

    // Determine risk level
    $risk_level = $this->determine_risk_level($risk_score);

    return [
      'is_suspicious' => $risk_score >= 25,
      'risk_level' => $risk_level,
      'reasons' => $reasons,
      'score' => $risk_score
    ];
  }

  /**
   * Analyze username patterns for spam indicators
   */
  private function analyze_username_patterns($username, &$reasons)
  {
    $risk_score = 0;

    // Check common spam patterns
    foreach ($this->common_patterns as $pattern) {
      if (preg_match($pattern, strtolower($username))) {
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
    if ($this->is_random_string($username)) {
      $reasons[] = 'Random username';
      $risk_score += 25;
    }

    // Check for common spam username patterns
    $spam_username_patterns = [
      '/^(user|admin|test|guest|temp|spam|bot)\d*$/',
      '/^[a-z]{1,3}\d{4,}$/', // Short letters + many numbers: a1234, xy5678
      '/^[a-z]+_\d{4,}$/',    // word_1234 pattern
      '/^(first|last|full)?name\d*$/',
      '/^[a-z]+\d{8,}$/'      // Letters followed by 8+ digits
    ];

    $username_lower = strtolower($username);
    foreach ($spam_username_patterns as $pattern) {
      if (preg_match($pattern, $username_lower)) {
        $risk_score += 20;
        $reasons[] = 'Common spam username pattern';
        break;
      }
    }

    return $risk_score;
  }

  /**
   * Analyze display name for spam indicators
   */
  private function analyze_display_name($user, &$reasons)
  {
    $risk_score = 0;

    // Check for missing display name
    if (empty($user->display_name) || $user->display_name === $user->user_login) {
      $reasons[] = 'No display name';
      $risk_score += 70;
      return $risk_score;
    }

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

    return $risk_score;
  }

  /**
   * Analyze email patterns for spam indicators
   */
  private function analyze_email_patterns($email, &$reasons)
  {
    $risk_score = 0;
    $email_domain = strtolower(explode('@', $email)[1] ?? '');
    $email_prefix = explode('@', $email)[0] ?? '';

    // Check for suspicious TLD domains
    $suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.ws'];
    foreach ($suspicious_tlds as $tld) {
      if (str_ends_with($email_domain, $tld)) {
        $risk_score += 15;
        $reasons[] = 'Suspicious domain extension';
        break;
      }
    }

    // Enhanced email pattern analysis
    if (preg_match('/^[a-z]+\d+@/', strtolower($email))) {
      $reasons[] = 'Generic email pattern';
      $risk_score += 15;
    }

    // Check for email with trailing numbers (common bot pattern)
    if (preg_match('/\d{2,}@/', $email)) {
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

    return $risk_score;
  }

  /**
   * Analyze user first/last names for spam indicators
   */
  private function analyze_user_names($user, &$reasons)
  {
    $risk_score = 0;
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

    return $risk_score;
  }

  /**
   * Analyze bulk registrations from same domain
   */
  private function analyze_bulk_registrations($email_domain, &$reasons)
  {
    $risk_score = 0;
    $domain_count = $this->count_users_by_domain($email_domain);

    if ($domain_count > 5) {
      $reasons[] = "Bulk registration ({$domain_count} from same domain)";
      $risk_score += min(20, $domain_count);
    }

    return $risk_score;
  }

  /**
   * Analyze sequential username patterns
   */
  private function analyze_sequential_usernames($username, &$reasons)
  {
    global $wpdb;
    $risk_score = 0;
    $username_lower = strtolower($username);

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

    return $risk_score;
  }

  /**
   * Analyze registration time burst patterns
   */
  private function analyze_registration_burst($user_registered, &$reasons)
  {
    global $wpdb;
    $risk_score = 0;

    $reg_timestamp = strtotime($user_registered);
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

    return $risk_score;
  }

  /**
   * Analyze user activity patterns
   */
  private function analyze_user_activity($user, &$reasons)
  {
    $risk_score = 0;

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

    return $risk_score;
  }

  /**
   * Determine risk level based on score
   */
  private function determine_risk_level($risk_score)
  {
    if ($risk_score >= 70) {
      return 'high';
    } elseif ($risk_score >= 40) {
      return 'medium';
    }
    return 'low';
  }

  /**
   * Check if string appears to be random
   */
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

  /**
   * Count users by email domain
   */
  private function count_users_by_domain($domain)
  {
    global $wpdb;

    $count = $wpdb->get_var($wpdb->prepare(
      "SELECT COUNT(*) FROM {$wpdb->users} WHERE user_email LIKE %s",
      '%@' . $domain
    ));

    return (int) $count;
  }
}
