# Secure Redirect and Authentication System

## 🚨 Security Vulnerabilities Found in Original System

Your original URL structure had several critical security vulnerabilities:

```
❌ INSECURE (Original):
http://webmail-auth001.academmia.store/cpsess/prompt?fromPWA=1&pwd=abc123&_x_zm_rtaid=random123&_x_zm_rhtaid=456&email=<base64encoded_email>
```

### Critical Issues Identified:

1. **Exposed Credentials**: Password (`pwd=abc123`) visible in URL
2. **Predictable Tokens**: Simple, guessable token values
3. **Weak Encoding**: Basic base64 encoding (easily reversible)
4. **No Validation**: No redirect URL validation
5. **No Rate Limiting**: Vulnerable to brute force attacks
6. **No CSRF Protection**: Vulnerable to cross-site request forgery
7. **HTTP Protocol**: Unencrypted communication
8. **No Session Security**: No proper session management

## ✅ Secure Solution Implemented

The new secure system addresses all these vulnerabilities:

```
✅ SECURE (New Implementation):
https://webmail-auth001.academmia.store/secure-auth?email=<AES_encrypted>&auth_token=<HMAC_signed>&csrf_token=<random>&redirect=<validated>
```

## 🔧 Implementation Files

### Core Security Files:
- `secure_redirect_handler.php` - Main security implementation
- `security_config.php` - Configuration and database schema
- `usage_examples.php` - Implementation examples and tests

## 🛡️ Security Features Implemented

### 1. Secure Token Generation
- **HMAC-SHA256 signatures** for token integrity
- **Timestamp validation** with configurable expiry
- **Random nonces** to prevent replay attacks
- **Cryptographic security** using PHP's `random_bytes()`

### 2. Secure Data Encoding
- **AES-256-CBC encryption** for sensitive data
- **Random initialization vectors** for each encryption
- **Proper key management** with environment variables

### 3. Redirect Validation
- **Domain whitelisting** to prevent open redirects
- **URL parsing and validation** before redirects
- **HTTPS enforcement** in production environments

### 4. Rate Limiting
- **IP-based rate limiting** (5 attempts per 5 minutes)
- **Configurable thresholds** for different scenarios
- **Temporary blocking** for abuse prevention

### 5. CSRF Protection
- **Secure random tokens** for state validation
- **Session-based token storage** and verification
- **Request method validation** for sensitive operations

### 6. Security Headers
- **X-Content-Type-Options: nosniff**
- **X-Frame-Options: DENY**
- **Strict-Transport-Security** with HSTS preloading
- **Content-Security-Policy** to prevent XSS
- **Referrer-Policy** for privacy protection

### 7. Comprehensive Logging
- **Security event logging** with severity levels
- **Database-backed audit trail** for compliance
- **IP address and user agent tracking**

## 📋 Deployment Guide

### Step 1: Environment Setup

Create a `.env` file with secure configuration:

```bash
# Security Configuration
SECRET_KEY=your-cryptographically-secure-random-key-at-least-32-chars
ENVIRONMENT=production
DB_HOST=localhost
DB_USER=secure_app_user
DB_PASS=your-secure-database-password
DB_NAME=security_database

# SSL/TLS Configuration
SSL_CERT_PATH=/path/to/ssl/cert.pem
SSL_KEY_PATH=/path/to/ssl/private.key
```

### Step 2: Database Setup

```bash
php security_config.php
```

This creates the required security tables:
- `auth_tokens` - Secure token storage
- `security_logs` - Audit trail
- `rate_limits` - Rate limiting data
- `user_sessions` - Session management

### Step 3: Web Server Configuration

#### Apache (.htaccess)
```apache
# Force HTTPS
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

# Security Headers
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Hide server information
ServerTokens Prod
Header unset Server
```

#### Nginx
```nginx
server {
    listen 443 ssl http2;
    server_name webmail-auth001.academmia.store;
    
    ssl_certificate /path/to/ssl/cert.pem;
    ssl_certificate_key /path/to/ssl/private.key;
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    
    location /secure-auth {
        try_files $uri $uri/ /secure_redirect_handler.php$is_args$args;
    }
}
```

### Step 4: File Permissions

```bash
# Set secure file permissions
chmod 644 *.php
chmod 600 .env
chown www-data:www-data *.php
```

## 🔍 Usage Examples

### Generate Secure Authentication URL

```php
<?php
require_once 'secure_redirect_handler.php';

$processor = new SecureAuthProcessor();
$secureUrl = $processor->generateSecureAuthUrl(
    'user@example.com',
    'https://webmail-auth001.academmia.store/dashboard'
);

echo $secureUrl;
// Output: https://webmail-auth001.academmia.store/secure-auth?email=<encrypted>&auth_token=<signed>&csrf_token=<random>
?>
```

### Validate Authentication Request

```php
<?php
// This is handled automatically by secure_redirect_handler.php
// Just include it and it will process incoming requests securely
require_once 'secure_redirect_handler.php';
?>
```

## 🧪 Testing the Implementation

Run the test suite:

```bash
php usage_examples.php
```

This will run comprehensive security tests including:
- Token generation and validation
- Email encryption/decryption
- Rate limiting functionality
- CSRF protection
- Complete authentication flow

## 🚨 Security Checklist

Before deploying to production:

- [ ] Generate a cryptographically secure SECRET_KEY
- [ ] Configure SSL/TLS certificates
- [ ] Set up database with proper credentials
- [ ] Configure domain whitelist for redirects
- [ ] Test rate limiting thresholds
- [ ] Verify CSRF protection is working
- [ ] Set up security monitoring and alerting
- [ ] Configure log rotation and retention
- [ ] Test backup and recovery procedures
- [ ] Perform penetration testing

## 🔧 Customization Options

### Adjust Security Parameters

In `security_config.php`, you can modify:

```php
define('SECURITY_CONFIG', [
    'SESSION_TIMEOUT' => 900,        // 15 minutes
    'RATE_LIMIT_ATTEMPTS' => 5,      // Max attempts
    'RATE_LIMIT_WINDOW' => 300,      // Time window (seconds)
    'TOKEN_EXPIRY' => 3600,          // Token validity (seconds)
    'BCRYPT_ROUNDS' => 12,           // Password hashing rounds
]);
```

### Add Additional Domains

```php
define('ALLOWED_REDIRECT_DOMAINS', [
    'webmail-auth001.academmia.store',
    'mail.academmia.store',
    'secure.academmia.store',
    // Add your additional trusted domains here
]);
```

## 📊 Monitoring and Alerts

### Security Log Analysis

Query security events:

```sql
-- Failed authentication attempts
SELECT * FROM security_logs 
WHERE event_type = 'auth_failed' 
AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR);

-- Rate limit violations
SELECT ip_address, COUNT(*) as violations
FROM security_logs 
WHERE event_type = 'rate_limit_exceeded'
GROUP BY ip_address
ORDER BY violations DESC;
```

### Set Up Monitoring

1. **Real-time alerts** for critical security events
2. **Daily security reports** via email
3. **Log rotation** to prevent disk space issues
4. **Backup verification** for security data

## 🆘 Incident Response

If you detect a security incident:

1. **Immediately block** suspicious IP addresses
2. **Invalidate all tokens** by changing SECRET_KEY
3. **Review security logs** for the attack pattern
4. **Update security measures** based on findings
5. **Notify users** if data may have been compromised

## 🔄 Regular Maintenance

### Weekly Tasks:
- Review security logs for anomalies
- Check rate limiting effectiveness
- Verify SSL certificate validity
- Test backup restoration

### Monthly Tasks:
- Rotate encryption keys
- Update security configurations
- Perform security audits
- Review and update domain whitelists

### Quarterly Tasks:
- Penetration testing
- Security policy review
- Staff security training
- Third-party security assessment

## 📞 Support and Updates

For questions or security concerns:
1. Review the security logs first
2. Check the implementation examples
3. Test with the provided test suite
4. Document any security incidents for analysis

Remember: Security is an ongoing process, not a one-time setup. Regular monitoring, testing, and updates are essential for maintaining a secure system.