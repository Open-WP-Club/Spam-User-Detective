<?php

/**
 * Export Import Class
 * 
 * File: includes/export-import.php
 */

if (!defined('ABSPATH')) {
  exit;
}

class SpamDetective_ExportImport
{
  private $user_manager;
  private $user_analyzer;
  private $domain_manager;

  public function __construct($user_manager = null, $user_analyzer = null, $domain_manager = null)
  {
    $this->user_manager = $user_manager;
    $this->user_analyzer = $user_analyzer;
    $this->domain_manager = $domain_manager;
  }

  /**
   * Export suspicious users to CSV
   */
  public function export_suspicious_users($user_ids)
  {
    if (empty($user_ids)) {
      return ['success' => false, 'message' => 'No users selected for export'];
    }

    $csv_data = [];
    $csv_data[] = ['ID', 'Username', 'Email', 'Display Name', 'Registration Date', 'Risk Level', 'Risk Factors', 'Roles', 'Has Orders', 'Can Delete'];

    $whitelist = $this->domain_manager ? $this->domain_manager->get_whitelist() : [];
    $suspicious_domains = $this->domain_manager ? $this->domain_manager->get_suspicious_domains() : [];

    foreach ($user_ids as $user_id) {
      $user = get_user_by('ID', $user_id);
      if (!$user) continue;

      // Re-analyze user for current data
      $analysis = $this->user_analyzer ?
        $this->user_analyzer->analyze_user($user, $whitelist, $suspicious_domains) :
        ['risk_level' => 'unknown', 'reasons' => []];

      if ($this->user_manager) {
        $csv_data[] = $this->user_manager->get_user_export_data($user, $analysis);
      } else {
        // Fallback if user_manager not available
        $csv_data[] = [
          $user->ID,
          $user->user_login,
          $user->user_email,
          $user->display_name,
          $user->user_registered,
          $analysis['risk_level'],
          implode('; ', $analysis['reasons']),
          implode(', ', $user->roles),
          'Unknown',
          'Unknown'
        ];
      }
    }

    // Create CSV content
    $csv_content = $this->array_to_csv($csv_data);

    return [
      'success' => true,
      'filename' => 'suspicious-users-' . date('Y-m-d-H-i-s') . '.csv',
      'content' => $csv_content
    ];
  }

  /**
   * Export domain lists to JSON
   */
  public function export_domain_lists()
  {
    $export_data = $this->domain_manager ?
      $this->domain_manager->export_domain_lists() :
      [
        'exported_at' => current_time('mysql'),
        'whitelist' => get_option('spam_detective_whitelist', []),
        'suspicious_domains' => get_option('spam_detective_suspicious_domains', [])
      ];

    return [
      'success' => true,
      'filename' => 'spam-detective-domains-' . date('Y-m-d-H-i-s') . '.json',
      'content' => json_encode($export_data, JSON_PRETTY_PRINT)
    ];
  }

  /**
   * Import domain lists from JSON
   */
  public function import_domain_lists($file_data, $merge_mode = 'replace')
  {
    if (!isset($file_data['tmp_name']) || !file_exists($file_data['tmp_name'])) {
      return ['success' => false, 'message' => 'No file uploaded or upload error'];
    }

    $file_content = file_get_contents($file_data['tmp_name']);
    $import_data = json_decode($file_content, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
      return ['success' => false, 'message' => 'Invalid JSON file'];
    }

    if ($this->domain_manager) {
      $result = $this->domain_manager->import_domain_lists($import_data, $merge_mode);
    } else {
      // Fallback import logic if domain manager not available
      $result = $this->fallback_import_domains($import_data, $merge_mode);
    }

    return $result;
  }

  /**
   * Export analysis results summary
   */
  public function export_analysis_summary($suspicious_users)
  {
    $summary_data = [];
    $summary_data[] = ['Analysis Summary', 'Value'];
    $summary_data[] = ['Total Suspicious Users', count($suspicious_users)];

    // Count by risk level
    $risk_levels = array_count_values(array_column($suspicious_users, 'risk_level'));
    foreach ($risk_levels as $level => $count) {
      $summary_data[] = [ucfirst($level) . ' Risk Users', $count];
    }

    // Count domains
    $domains = [];
    foreach ($suspicious_users as $user) {
      $domain = explode('@', $user['email'])[1] ?? '';
      if ($domain) {
        $domains[$domain] = ($domains[$domain] ?? 0) + 1;
      }
    }

    $summary_data[] = ['Unique Domains', count($domains)];
    $summary_data[] = ['', ''];
    $summary_data[] = ['Top Domains', 'User Count'];

    // Sort domains by count and get top 10
    arsort($domains);
    $top_domains = array_slice($domains, 0, 10, true);
    foreach ($top_domains as $domain => $count) {
      $summary_data[] = [$domain, $count];
    }

    $csv_content = $this->array_to_csv($summary_data);

    return [
      'success' => true,
      'filename' => 'spam-analysis-summary-' . date('Y-m-d-H-i-s') . '.csv',
      'content' => $csv_content
    ];
  }

  /**
   * Convert array to CSV format
   */
  private function array_to_csv($data)
  {
    $csv_content = '';
    foreach ($data as $row) {
      $csv_content .= implode(',', array_map(function ($field) {
        return '"' . str_replace('"', '""', $field) . '"';
      }, $row)) . "\n";
    }
    return $csv_content;
  }

  /**
   * Fallback import logic if domain manager not available
   */
  private function fallback_import_domains($import_data, $merge_mode)
  {
    // Import whitelist
    if (isset($import_data['whitelist']) && is_array($import_data['whitelist'])) {
      if ($merge_mode === 'merge') {
        $current_whitelist = get_option('spam_detective_whitelist', []);
        $new_whitelist = array_unique(array_merge($current_whitelist, $import_data['whitelist']));
      } else {
        $new_whitelist = $import_data['whitelist'];
      }
      update_option('spam_detective_whitelist', $new_whitelist);
    }

    // Import suspicious domains
    if (isset($import_data['suspicious_domains']) && is_array($import_data['suspicious_domains'])) {
      if ($merge_mode === 'merge') {
        $current_suspicious = get_option('spam_detective_suspicious_domains', []);
        $new_suspicious = array_unique(array_merge($current_suspicious, $import_data['suspicious_domains']));
      } else {
        $new_suspicious = $import_data['suspicious_domains'];
      }
      update_option('spam_detective_suspicious_domains', $new_suspicious);
    }

    return ['success' => true, 'message' => 'Domain lists imported successfully'];
  }

  /**
   * Validate CSV file format
   */
  public function validate_csv_file($file_data)
  {
    if (!isset($file_data['tmp_name']) || !file_exists($file_data['tmp_name'])) {
      return ['valid' => false, 'message' => 'File not found'];
    }

    if ($file_data['type'] !== 'text/csv' && !str_ends_with($file_data['name'], '.csv')) {
      return ['valid' => false, 'message' => 'File must be CSV format'];
    }

    if ($file_data['size'] > 10 * 1024 * 1024) { // 10MB limit
      return ['valid' => false, 'message' => 'File too large (maximum 10MB)'];
    }

    return ['valid' => true, 'message' => 'File is valid'];
  }

  /**
   * Validate JSON file format
   */
  public function validate_json_file($file_data)
  {
    if (!isset($file_data['tmp_name']) || !file_exists($file_data['tmp_name'])) {
      return ['valid' => false, 'message' => 'File not found'];
    }

    if ($file_data['type'] !== 'application/json' && !str_ends_with($file_data['name'], '.json')) {
      return ['valid' => false, 'message' => 'File must be JSON format'];
    }

    if ($file_data['size'] > 5 * 1024 * 1024) { // 5MB limit
      return ['valid' => false, 'message' => 'File too large (maximum 5MB)'];
    }

    // Test JSON parsing
    $content = file_get_contents($file_data['tmp_name']);
    json_decode($content);
    if (json_last_error() !== JSON_ERROR_NONE) {
      return ['valid' => false, 'message' => 'Invalid JSON format'];
    }

    return ['valid' => true, 'message' => 'File is valid'];
  }
}
