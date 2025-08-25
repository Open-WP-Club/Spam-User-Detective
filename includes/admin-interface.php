<?php

/**
 * Admin Interface Class
 * 
 * File: includes/class-admin-interface.php
 */

if (!defined('ABSPATH')) {
  exit;
}

class SpamDetective_AdminInterface
{

  public function display_page()
  {
?>
    <div class="wrap spam-detective-wrap">
      <h1 class="spam-detective-title">Spam User Detective</h1>
      <p class="spam-detective-description">Detect and manage suspicious user accounts based on patterns commonly used by bots and spammers.</p>

      <?php $this->display_backup_warning(); ?>

      <div class="spam-detective-main">
        <div class="spam-detective-content">
          <?php $this->display_analysis_controls(); ?>
          <?php $this->display_results_container(); ?>
        </div>

        <div class="spam-detective-sidebar">
          <?php $this->display_settings(); ?>
        </div>
      </div>
    </div>
  <?php
  }

  private function display_backup_warning()
  {
  ?>
    <div class="notice notice-warning backup-warning">
      <p>
        <strong>Important:</strong> Please create a full backup of your website before using this tool.
        While we use multiple checks to identify spam accounts, false positives are always possible.
        Having a backup ensures you can restore legitimate users if they are accidentally removed.
      </p>
    </div>
  <?php
  }

  private function display_analysis_controls()
  {
  ?>
    <div class="spam-detective-card">
      <h2>Analysis Controls</h2>
      <div class="analysis-buttons">
        <button id="analyze-users" class="button button-primary">Analyze All Users</button>
        <button id="quick-scan" class="button button-secondary">Quick Scan (Last 100)</button>
      </div>
      <div id="analysis-progress" class="analysis-progress" style="display:none;">
        <p>Analyzing users...</p>
        <div class="progress-bar">
          <div class="progress-fill"></div>
        </div>
      </div>
    </div>
  <?php
  }

  private function display_results_container()
  {
  ?>
    <div id="results-container" class="spam-detective-card" style="display:none;">
      <h2>Suspicious Users Found</h2>

      <div class="analysis-summary">
        <div class="summary-stat">
          <span class="stat-number" id="total-suspicious">0</span>
          <span class="stat-label">Suspicious Users</span>
        </div>
        <div class="summary-stat">
          <span class="stat-number" id="high-confidence">0</span>
          <span class="stat-label">High Confidence</span>
        </div>
        <div class="summary-stat">
          <span class="stat-number" id="suspicious-domains">0</span>
          <span class="stat-label">Bad Domains</span>
        </div>
      </div>

      <div class="bulk-actions">
        <button id="select-all-high" class="button">Select All High Confidence</button>
        <button id="select-all-suspicious" class="button">Select All Suspicious</button>
        <button id="delete-selected" class="button button-primary delete-button">Delete Selected</button>
        <span id="selected-count" class="selected-count">0 selected</span>
      </div>

      <div class="tablenav">
        <div class="tablenav-pages">
          <span class="displaying-num" id="displaying-num">0 items</span>
        </div>
      </div>

      <table class="wp-list-table widefat fixed striped users">
        <thead>
          <tr>
            <th class="manage-column column-cb check-column">
              <input type="checkbox" id="select-all-checkbox">
            </th>
            <th>Risk Level</th>
            <th>Username</th>
            <th>Email</th>
            <th>Display Name</th>
            <th>Registration Date</th>
            <th>Risk Factors</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="suspicious-users-list">
          <!-- Results will be populated here -->
        </tbody>
      </table>
    </div>
  <?php
  }

  private function display_settings()
  {
  ?>
    <div class="spam-detective-card">
      <h2>Settings</h2>

      <div class="settings-section">
        <h3>Whitelisted Domains</h3>
        <p class="description">Domains that should never be flagged as suspicious</p>
        <div id="whitelisted-domains" class="domain-list">
          <?php
          $whitelist = get_option('spam_detective_whitelist', []);
          foreach ($whitelist as $domain) {
            echo '<span class="domain-tag whitelist-tag">' . esc_html($domain) . ' <button class="remove-domain" data-domain="' . esc_attr($domain) . '" data-type="whitelist">×</button></span>';
          }
          ?>
        </div>
        <div class="domain-input">
          <input type="text" id="new-whitelist-domain" placeholder="Enter domain (e.g., gmail.com)" class="regular-text">
          <button id="add-whitelist" class="button">Add</button>
        </div>
      </div>

      <div class="settings-section">
        <h3>Suspicious Domains</h3>
        <p class="description">Domains that should be automatically flagged as suspicious</p>
        <div id="suspicious-domains" class="domain-list">
          <?php
          $suspicious = get_option('spam_detective_suspicious_domains', []);
          foreach ($suspicious as $domain) {
            echo '<span class="domain-tag suspicious-tag">' . esc_html($domain) . ' <button class="remove-domain" data-domain="' . esc_attr($domain) . '" data-type="suspicious">×</button></span>';
          }
          ?>
        </div>
        <div class="domain-input">
          <input type="text" id="new-suspicious-domain" placeholder="Enter domain (e.g., spam-domain.com)" class="regular-text">
          <button id="add-suspicious" class="button">Add</button>
        </div>
      </div>
    </div>
<?php
  }
}
