<?php
/**
 * Secure Redirect Handler for Webmail Authentication
 * Implements security best practices for redirect validation and parameter handling
 */

class SecureRedirectHandler {
    private $allowedDomains = [
        'webmail-auth001.academmia.store',
        'localhost',
        '127.0.0.1'
    ];
    
    private $secretKey;
    private $sessionTimeout = 900; // 15 minutes
    
    public function __construct() {
        $this->secretKey = $_ENV['SECRET_KEY'] ?? 'your-secure-secret-key-here';
        $this->initializeSecurityHeaders();
    }
    
    /**
     * Set security headers to prevent various attacks
     */
    private function initializeSecurityHeaders() {
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('X-XSS-Protection: 1; mode=block');
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        header('Content-Security-Policy: default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'');
        header('Referrer-Policy: strict-origin-when-cross-origin');
    }
    
    /**
     * Validate and sanitize redirect URL
     */
    public function validateRedirectUrl($url) {
        if (empty($url)) {
            return false;
        }
        
        $parsedUrl = parse_url($url);
        
        if (!$parsedUrl || !isset($parsedUrl['host'])) {
            return false;
        }
        
        // Check if domain is in whitelist
        if (!in_array($parsedUrl['host'], $this->allowedDomains)) {
            error_log("Unauthorized redirect attempt to: " . $parsedUrl['host']);
            return false;
        }
        
        // Ensure HTTPS in production
        if ($parsedUrl['scheme'] !== 'https' && $_ENV['ENVIRONMENT'] === 'production') {
            return false;
        }
        
        return true;
    }
    
    /**
     * Generate secure token with timestamp and signature
     */
    public function generateSecureToken($userId, $action = 'auth') {
        $timestamp = time();
        $data = json_encode([
            'user_id' => $userId,
            'action' => $action,
            'timestamp' => $timestamp,
            'nonce' => bin2hex(random_bytes(16))
        ]);
        
        $signature = hash_hmac('sha256', $data, $this->secretKey);
        return base64_encode($data . '.' . $signature);
    }
    
    /**
     * Validate and decode secure token
     */
    public function validateSecureToken($token) {
        try {
            $decoded = base64_decode($token);
            $parts = explode('.', $decoded);
            
            if (count($parts) !== 2) {
                return false;
            }
            
            list($data, $signature) = $parts;
            
            // Verify signature
            $expectedSignature = hash_hmac('sha256', $data, $this->secretKey);
            if (!hash_equals($expectedSignature, $signature)) {
                return false;
            }
            
            $tokenData = json_decode($data, true);
            
            // Check timestamp (token expiry)
            if (time() - $tokenData['timestamp'] > $this->sessionTimeout) {
                return false;
            }
            
            return $tokenData;
        } catch (Exception $e) {
            error_log("Token validation error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Secure email encoding (not just base64)
     */
    public function encodeEmail($email) {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new InvalidArgumentException("Invalid email format");
        }
        
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($email, 'AES-256-CBC', $this->secretKey, 0, $iv);
        return base64_encode($iv . $encrypted);
    }
    
    /**
     * Decode secure email
     */
    public function decodeEmail($encodedEmail) {
        try {
            $data = base64_decode($encodedEmail);
            $iv = substr($data, 0, 16);
            $encrypted = substr($data, 16);
            
            $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $this->secretKey, 0, $iv);
            
            if (!filter_var($decrypted, FILTER_VALIDATE_EMAIL)) {
                return false;
            }
            
            return $decrypted;
        } catch (Exception $e) {
            error_log("Email decode error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Rate limiting implementation
     */
    public function checkRateLimit($identifier, $maxAttempts = 5, $timeWindow = 300) {
        $cacheKey = 'rate_limit_' . hash('sha256', $identifier);
        
        // In production, use Redis or database instead of session
        if (!isset($_SESSION[$cacheKey])) {
            $_SESSION[$cacheKey] = ['count' => 0, 'first_attempt' => time()];
        }
        
        $attempts = $_SESSION[$cacheKey];
        
        // Reset if time window has passed
        if (time() - $attempts['first_attempt'] > $timeWindow) {
            $_SESSION[$cacheKey] = ['count' => 1, 'first_attempt' => time()];
            return true;
        }
        
        // Check if limit exceeded
        if ($attempts['count'] >= $maxAttempts) {
            return false;
        }
        
        $_SESSION[$cacheKey]['count']++;
        return true;
    }
    
    /**
     * Generate CSRF token
     */
    public function generateCSRFToken() {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
    
    /**
     * Validate CSRF token
     */
    public function validateCSRFToken($token) {
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }
}

/**
 * Secure Authentication Processor
 */
class SecureAuthProcessor {
    private $redirectHandler;
    
    public function __construct() {
        session_start();
        $this->redirectHandler = new SecureRedirectHandler();
    }
    
    /**
     * Process secure authentication request
     */
    public function processAuthRequest() {
        try {
            // Rate limiting check
            $clientIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            if (!$this->redirectHandler->checkRateLimit($clientIP)) {
                http_response_code(429);
                die(json_encode(['error' => 'Rate limit exceeded']));
            }
            
            // CSRF protection for POST requests
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $csrfToken = $_POST['csrf_token'] ?? '';
                if (!$this->redirectHandler->validateCSRFToken($csrfToken)) {
                    http_response_code(403);
                    die(json_encode(['error' => 'Invalid CSRF token']));
                }
            }
            
            // Validate and process parameters
            $params = $this->validateAndSanitizeParams();
            
            if (!$params) {
                http_response_code(400);
                die(json_encode(['error' => 'Invalid parameters']));
            }
            
            // Process authentication
            $authResult = $this->authenticateUser($params);
            
            if ($authResult['success']) {
                $this->handleSuccessfulAuth($authResult['user_id'], $params);
            } else {
                $this->handleFailedAuth($params);
            }
            
        } catch (Exception $e) {
            error_log("Auth processing error: " . $e->getMessage());
            http_response_code(500);
            die(json_encode(['error' => 'Internal server error']));
        }
    }
    
    /**
     * Validate and sanitize input parameters
     */
    private function validateAndSanitizeParams() {
        $requiredParams = ['email', 'auth_token'];
        $params = [];
        
        foreach ($requiredParams as $param) {
            if (!isset($_GET[$param]) && !isset($_POST[$param])) {
                return false;
            }
            
            $value = $_GET[$param] ?? $_POST[$param];
            $params[$param] = htmlspecialchars(trim($value), ENT_QUOTES, 'UTF-8');
        }
        
        // Validate email format
        $decodedEmail = $this->redirectHandler->decodeEmail($params['email']);
        if (!$decodedEmail) {
            return false;
        }
        
        $params['decoded_email'] = $decodedEmail;
        
        // Validate auth token
        $tokenData = $this->redirectHandler->validateSecureToken($params['auth_token']);
        if (!$tokenData) {
            return false;
        }
        
        $params['token_data'] = $tokenData;
        
        return $params;
    }
    
    /**
     * Authenticate user (implement your authentication logic)
     */
    private function authenticateUser($params) {
        // Replace with your actual authentication logic
        // This is just a placeholder
        
        $email = $params['decoded_email'];
        $tokenData = $params['token_data'];
        
        // Verify token matches email
        if ($tokenData['user_id'] !== hash('sha256', $email)) {
            return ['success' => false, 'reason' => 'Token mismatch'];
        }
        
        // Add your authentication logic here
        // Check against database, validate credentials, etc.
        
        return ['success' => true, 'user_id' => $tokenData['user_id']];
    }
    
    /**
     * Handle successful authentication
     */
    private function handleSuccessfulAuth($userId, $params) {
        // Set secure session
        $_SESSION['authenticated'] = true;
        $_SESSION['user_id'] = $userId;
        $_SESSION['auth_time'] = time();
        
        // Regenerate session ID for security
        session_regenerate_id(true);
        
        // Redirect to secure location
        $redirectUrl = $this->getSecureRedirectUrl();
        
        if ($this->redirectHandler->validateRedirectUrl($redirectUrl)) {
            header("Location: " . $redirectUrl);
            exit;
        } else {
            // Fallback to default secure location
            header("Location: /dashboard");
            exit;
        }
    }
    
    /**
     * Handle failed authentication
     */
    private function handleFailedAuth($params) {
        // Log failed attempt
        error_log("Failed auth attempt for: " . $params['decoded_email']);
        
        // Redirect to login with error
        header("Location: /login?error=auth_failed");
        exit;
    }
    
    /**
     * Get secure redirect URL
     */
    private function getSecureRedirectUrl() {
        $redirectUrl = $_GET['redirect'] ?? $_POST['redirect'] ?? '/dashboard';
        
        // Remove any potentially malicious parameters
        $redirectUrl = filter_var($redirectUrl, FILTER_SANITIZE_URL);
        
        return $redirectUrl;
    }
    
    /**
     * Generate secure authentication URL
     */
    public function generateSecureAuthUrl($email, $redirectUrl = null) {
        $userId = hash('sha256', $email);
        $authToken = $this->redirectHandler->generateSecureToken($userId);
        $encodedEmail = $this->redirectHandler->encodeEmail($email);
        $csrfToken = $this->redirectHandler->generateCSRFToken();
        
        $params = [
            'email' => $encodedEmail,
            'auth_token' => $authToken,
            'csrf_token' => $csrfToken
        ];
        
        if ($redirectUrl && $this->redirectHandler->validateRedirectUrl($redirectUrl)) {
            $params['redirect'] = $redirectUrl;
        }
        
        $baseUrl = 'https://webmail-auth001.academmia.store/secure-auth';
        return $baseUrl . '?' . http_build_query($params);
    }
}

// Usage example
if ($_SERVER['REQUEST_METHOD'] === 'GET' || $_SERVER['REQUEST_METHOD'] === 'POST') {
    $processor = new SecureAuthProcessor();
    $processor->processAuthRequest();
}
?>