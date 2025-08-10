<?php
/**
 * Security Configuration File
 * Contains security settings, environment variables, and database schema
 */

// Security Configuration Constants
define('SECURITY_CONFIG', [
    'SECRET_KEY' => $_ENV['SECRET_KEY'] ?? 'change-this-in-production-to-secure-random-key',
    'SESSION_TIMEOUT' => 900, // 15 minutes
    'RATE_LIMIT_ATTEMPTS' => 5,
    'RATE_LIMIT_WINDOW' => 300, // 5 minutes
    'TOKEN_EXPIRY' => 3600, // 1 hour
    'BCRYPT_ROUNDS' => 12,
    'AES_METHOD' => 'AES-256-CBC',
    'HASH_ALGORITHM' => 'sha256',
]);

// Allowed domains for redirects
define('ALLOWED_REDIRECT_DOMAINS', [
    'webmail-auth001.academmia.store',
    'mail.academmia.store',
    'secure.academmia.store',
    'localhost',
    '127.0.0.1'
]);

// Security Headers Configuration
define('SECURITY_HEADERS', [
    'X-Content-Type-Options' => 'nosniff',
    'X-Frame-Options' => 'DENY',
    'X-XSS-Protection' => '1; mode=block',
    'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains; preload',
    'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self'",
    'Referrer-Policy' => 'strict-origin-when-cross-origin',
    'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()',
]);

// Database Configuration for Security Logging
$DB_CONFIG = [
    'host' => $_ENV['DB_HOST'] ?? 'localhost',
    'username' => $_ENV['DB_USER'] ?? 'secure_app',
    'password' => $_ENV['DB_PASS'] ?? 'secure_password',
    'database' => $_ENV['DB_NAME'] ?? 'security_db',
    'charset' => 'utf8mb4',
    'options' => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]
];

/**
 * Database Schema for Security Tables
 */
$SECURITY_SCHEMA = [
    'auth_tokens' => "
        CREATE TABLE IF NOT EXISTS auth_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            token_hash VARCHAR(255) NOT NULL UNIQUE,
            user_id VARCHAR(255) NOT NULL,
            action VARCHAR(50) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP NULL,
            ip_address VARCHAR(45),
            user_agent TEXT,
            INDEX idx_token_hash (token_hash),
            INDEX idx_user_id (user_id),
            INDEX idx_expires_at (expires_at)
        ) ENGINE=InnoDB
    ",
    
    'security_logs' => "
        CREATE TABLE IF NOT EXISTS security_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            event_type VARCHAR(50) NOT NULL,
            user_identifier VARCHAR(255),
            ip_address VARCHAR(45),
            user_agent TEXT,
            request_data JSON,
            severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_event_type (event_type),
            INDEX idx_user_identifier (user_identifier),
            INDEX idx_ip_address (ip_address),
            INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB
    ",
    
    'rate_limits' => "
        CREATE TABLE IF NOT EXISTS rate_limits (
            id INT AUTO_INCREMENT PRIMARY KEY,
            identifier_hash VARCHAR(255) NOT NULL,
            attempt_count INT DEFAULT 1,
            first_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            blocked_until TIMESTAMP NULL,
            UNIQUE KEY unique_identifier (identifier_hash),
            INDEX idx_blocked_until (blocked_until)
        ) ENGINE=InnoDB
    ",
    
    'user_sessions' => "
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            session_id VARCHAR(255) NOT NULL UNIQUE,
            user_id VARCHAR(255) NOT NULL,
            ip_address VARCHAR(45),
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            INDEX idx_session_id (session_id),
            INDEX idx_user_id (user_id),
            INDEX idx_expires_at (expires_at)
        ) ENGINE=InnoDB
    "
];

/**
 * Environment Variables Template
 */
$ENV_TEMPLATE = "
# Security Configuration
SECRET_KEY=your-super-secure-secret-key-here-change-this
ENVIRONMENT=production
DB_HOST=localhost
DB_USER=secure_app_user
DB_PASS=secure_database_password
DB_NAME=security_database

# SSL/TLS Configuration
SSL_CERT_PATH=/path/to/ssl/cert.pem
SSL_KEY_PATH=/path/to/ssl/private.key
SSL_CA_PATH=/path/to/ssl/ca.pem

# Email Configuration (for notifications)
SMTP_HOST=smtp.academmia.store
SMTP_PORT=587
SMTP_USER=security@academmia.store
SMTP_PASS=smtp_password
SMTP_ENCRYPTION=tls

# Logging Configuration
LOG_LEVEL=warning
LOG_FILE=/var/log/security/auth.log
SYSLOG_FACILITY=auth

# Rate Limiting
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=redis_password
";

/**
 * Security Logger Class
 */
class SecurityLogger {
    private $pdo;
    
    public function __construct() {
        global $DB_CONFIG;
        try {
            $dsn = "mysql:host={$DB_CONFIG['host']};dbname={$DB_CONFIG['database']};charset={$DB_CONFIG['charset']}";
            $this->pdo = new PDO($dsn, $DB_CONFIG['username'], $DB_CONFIG['password'], $DB_CONFIG['options']);
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
        }
    }
    
    public function logSecurityEvent($eventType, $userIdentifier, $requestData = [], $severity = 'medium') {
        if (!$this->pdo) return;
        
        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO security_logs (event_type, user_identifier, ip_address, user_agent, request_data, severity) 
                 VALUES (?, ?, ?, ?, ?, ?)"
            );
            
            $stmt->execute([
                $eventType,
                $userIdentifier,
                $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                json_encode($requestData),
                $severity
            ]);
        } catch (PDOException $e) {
            error_log("Security logging failed: " . $e->getMessage());
        }
    }
}

/**
 * Database Setup Function
 */
function setupSecurityDatabase() {
    global $DB_CONFIG, $SECURITY_SCHEMA;
    
    try {
        $dsn = "mysql:host={$DB_CONFIG['host']};charset={$DB_CONFIG['charset']}";
        $pdo = new PDO($dsn, $DB_CONFIG['username'], $DB_CONFIG['password'], $DB_CONFIG['options']);
        
        // Create database if it doesn't exist
        $pdo->exec("CREATE DATABASE IF NOT EXISTS " . $DB_CONFIG['database']);
        $pdo->exec("USE " . $DB_CONFIG['database']);
        
        // Create tables
        foreach ($SECURITY_SCHEMA as $tableName => $schema) {
            $pdo->exec($schema);
            echo "Created table: $tableName\n";
        }
        
        return true;
    } catch (PDOException $e) {
        error_log("Database setup failed: " . $e->getMessage());
        return false;
    }
}

// Auto-setup if called directly
if (basename(__FILE__) === basename($_SERVER['SCRIPT_NAME'])) {
    if (setupSecurityDatabase()) {
        echo "Security database setup completed successfully.\n";
    } else {
        echo "Security database setup failed. Check error logs.\n";
    }
}
?>