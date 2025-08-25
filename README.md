# Spam User Detective

Spam and bot user detection plugin for WordPress and WooCommerce that helps you identify, manage, and remove suspicious user accounts while protecting legitimate users.

## Features

### Smart Detection

- **Multiple Pattern Analysis**: Detects common spam username patterns and suspicious email addresses
- **Domain Reputation**: Identifies disposable email domains and suspicious registration patterns
- **Bulk Registration Detection**: Flags mass registrations from same domains or IP patterns
- **Activity Analysis**: Identifies dormant accounts with no posts, comments, or engagement

### User Protection

- **Role-Based Protection**: Automatically protects Administrators, Editors, and Shop Managers
- **WooCommerce Integration**: Special handling for customers with purchase history

### Export & Import

- **CSV Export**: Export suspicious users with detailed analysis data
- **Domain List Management**: Import/export whitelist and suspicious domain lists
- **Bulk Operations**: Efficient management of large user databases

## Installation

### Method 1: WordPress Admin (Recommended)

1. Download the latest release from [GitHub Releases](https://github.com/Open-WP-Club/Spam-User-Detective/releases)
2. Go to **Plugins > Add New > Upload Plugin**
3. Choose the downloaded ZIP file and click **Install Now**
4. Click **Activate Plugin**

### Method 2: Manual Installation

1. Download and extract the plugin files
2. Upload the `spam-user-detective` folder to `/wp-content/plugins/`
3. Go to **Plugins** in your WordPress admin
4. Find "Spam User Detective" and click **Activate**

### Method 3: Git Clone

```bash
cd /path/to/wordpress/wp-content/plugins/
git clone https://github.com/Open-WP-Club/Spam-User-Detective.git spam-user-detective
```

## Usage Guide

### Getting Started

1. **Create a Backup**: Always backup your database before using any user management tool
2. **Access the Plugin**: Go to **Users > Spam Detective** in your WordPress admin
3. **Configure Settings**: Add trusted domains to whitelist and known spam domains to blacklist
4. **Run Analysis**: Choose between Quick Scan (100 recent users) or Full Analysis

### Analysis Options

#### Quick Scan

- Analyzes the 100 most recent user registrations
- Perfect for regular maintenance and recent spam detection
- Faster execution, ideal for larger sites

#### Full Analysis

- Scans your entire user database
- Comprehensive detection for complete cleanup
- May take longer on sites with many users

### Understanding Risk Levels

| Risk Level | Score Range | Description | Recommended Action |
|------------|-------------|-------------|-------------------|
| **🔴 High** | 70+ | Multiple spam indicators | Safe to delete |
| **🟡 Medium** | 40-69 | Some suspicious patterns | Review manually |
| **🟢 Low** | 25-39 | Minor flags detected | Investigate further |

### Status Icons

| Icon | Meaning | Action |
|------|---------|--------|
| 🛡️ | Protected Role (Admin/Editor) | Cannot be deleted |
| 🔒 | Protected User | Cannot be deleted |
| 🛒 | Has WooCommerce Orders | Protected by default |
| ⚠️ | Can be deleted | Available for removal |

### Bulk Actions

- **Select All High Confidence**: Selects users with 70+ risk score
- **Select All Deletable**: Selects non-protected users without orders
- **Select All Suspicious**: Selects all flagged users (respects protection)
- **Delete Selected**: Removes selected users immediately
- **Export Selected**: Downloads CSV with user details

## Configuration

### Domain Management

### Detection Patterns

The plugin automatically detects:

- Random character usernames: `xjk8m9p2`, `aqwerty123`
- Pattern-based names: `user123`, `name-456`
- Missing display names or profiles
- Bulk registrations from same domains
- Inactive accounts with no engagement

### WooCommerce Settings

When WooCommerce is active:

- Users with completed orders are protected by default
- Shopping cart icon (🛒) indicates customers
- "Force Delete" option available for override
- Order status considered in risk scoring

## Technical Details

### Database Impact

- Uses WordPress transients for caching (24-hour expiration)
- No custom database tables created
- Minimal database footprint
- Automatic cache cleanup on deactivation

### Performance Considerations

- Caching system reduces repeated analysis overhead
- Batch processing prevents memory exhaustion
- Progressive loading for large datasets
- Optimized database queries with proper indexing

## Development

### Local Development Setup

```bash
# Clone the repository
git clone https://github.com/Open-WP-Club/Spam-User-Detective.git

# Install in WordPress plugins directory
cp -r Spam-User-Detective /path/to/wordpress/wp-content/plugins/spam-user-detective

# Activate via WordPress admin or WP-CLI
wp plugin activate spam-user-detective
```

## Contributing

We welcome contributions from the community! Here's how you can help:

### Reporting Issues

1. Check existing [issues](https://github.com/Open-WP-Club/Spam-User-Detective/issues)
2. Create a new issue with detailed information
3. Include WordPress version, PHP version, and error logs
4. Describe expected vs actual behavior

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes following our coding standards
4. Test thoroughly on different WordPress versions
5. Commit with clear messages: `git commit -m 'Add amazing feature'`
6. Push to your branch: `git push origin feature/amazing-feature`
7. Open a Pull Request with detailed description

## License

This project is licensed under the GNU General Public License v2.0 - see the [LICENSE](LICENSE) file for details.

## Support

### Free Support

- [GitHub Issues](https://github.com/Open-WP-Club/Spam-User-Detective/issues) - Bug reports and feature requests
- [Documentation](https://github.com/Open-WP-Club/Spam-User-Detective#readme) - Comprehensive usage guide
- [Community Discussions](https://github.com/Open-WP-Club/Spam-User-Detective/discussions) - Questions and community help

### Before Asking for Help

1. **Update to latest version** - Many issues are resolved in updates
2. **Check existing issues** - Your question might already be answered
3. **Test with default theme** - Rule out theme conflicts
4. **Disable other plugins** - Identify plugin conflicts
5. **Provide system info** - WordPress, PHP, and plugin versions
