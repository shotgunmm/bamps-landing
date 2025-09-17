<?php
// submit-email.php - Secure email form submission handler

// Security: Disable error display in production
error_reporting(0);
ini_set('display_errors', 0);

// Security: Set secure headers
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// Security: Restrict CORS to your domain only
$allowed_origin = 'https://bampstoys.com'; // Change to your actual domain
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if ($origin === $allowed_origin) {
    header('Access-Control-Allow-Origin: ' . $allowed_origin);
    header('Access-Control-Allow-Methods: POST');
    header('Access-Control-Allow-Headers: Content-Type');
}

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Security: Rate limiting
session_start();
$ip = $_SERVER['REMOTE_ADDR'];
$rate_limit_key = 'rate_limit_' . $ip;
$max_attempts = 5; // Max 5 submissions per session
$time_window = 3600; // 1 hour

if (!isset($_SESSION[$rate_limit_key])) {
    $_SESSION[$rate_limit_key] = ['count' => 0, 'first_attempt' => time()];
}

if (time() - $_SESSION[$rate_limit_key]['first_attempt'] > $time_window) {
    $_SESSION[$rate_limit_key] = ['count' => 0, 'first_attempt' => time()];
}

if ($_SESSION[$rate_limit_key]['count'] >= $max_attempts) {
    http_response_code(429);
    echo json_encode(['success' => false, 'message' => 'Too many requests. Please try again later.']);
    exit;
}

$_SESSION[$rate_limit_key]['count']++;

// Check if request method is POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

// Get the JSON data from the request body
$input = json_decode(file_get_contents('php://input'), true);

// Validate email
if (!isset($input['email']) || empty($input['email'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Email is required']);
    exit;
}

$email = filter_var($input['email'], FILTER_SANITIZE_EMAIL);

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Invalid email format']);
    exit;
}

// Security: Additional email validation
if (strlen($email) > 254) { // RFC 5321
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Email too long']);
    exit;
}

// Security: Check for duplicate submissions (prevent spam)
$csvFile = 'email_signups.csv';
$duplicate = false;

if (file_exists($csvFile)) {
    $existing_emails = array_map('str_getcsv', file($csvFile));
    foreach ($existing_emails as $row) {
        if (isset($row[0]) && $row[0] === $email) {
            $duplicate = true;
            break;
        }
    }
}

if ($duplicate) {
    echo json_encode(['success' => true, 'message' => 'You\'re already signed up!']);
    exit;
}

// Security: Use more secure file handling
$timestamp = date('Y-m-d H:i:s');
$csv_dir = dirname(__FILE__) . '/csv_data/';

// Create directory if it doesn't exist
if (!file_exists($csv_dir)) {
    mkdir($csv_dir, 0750, true);
}

// Security: Add .htaccess to protect CSV directory
$htaccess_content = "Order Allow,Deny\nDeny from all";
file_put_contents($csv_dir . '.htaccess', $htaccess_content);

$csvFile = $csv_dir . 'email_signups.csv';

// Security: Use file locking to prevent race conditions
$fp = fopen($csvFile, 'a');
if (flock($fp, LOCK_EX)) {
    // Check if file is empty (needs headers)
    if (filesize($csvFile) == 0) {
        fputcsv($fp, ['Email', 'Timestamp', 'IP_Address']);
    }
    
    // Write data with IP for security tracking
    fputcsv($fp, [$email, $timestamp, $ip]);
    flock($fp, LOCK_UN);
}
fclose($fp);

// Security: Sanitize email for mail function
$to = 'mmckenna@shieldssgf.com';
$subject = "New Bamp's Toy Vault Website Signup";

// Security: Use proper email encoding
$message = "A new visitor has signed up for updates on the Bamp's Toy Vault website.\n\n";
$message .= "Email: " . htmlspecialchars($email, ENT_QUOTES, 'UTF-8') . "\n";
$message .= "Date/Time: " . $timestamp . "\n";
$message .= "IP Address: " . $ip . "\n";

// Security: Proper email headers to prevent injection
$headers = [
    'From: noreply@bampstoys.com',
    'Reply-To: noreply@bampstoys.com', // Don't use user input in headers
    'X-Mailer: PHP/' . phpversion(),
    'Content-Type: text/plain; charset=UTF-8'
];

// Send the email with proper headers
$mailSent = mail($to, $subject, $message, implode("\r\n", $headers));

// Return response
echo json_encode(['success' => true, 'message' => 'Thank you for signing up!']);

// Security: Log submission attempts
$log_file = $csv_dir . 'submission_log.txt';
$log_entry = date('Y-m-d H:i:s') . " - Email: $email - IP: $ip - Success: " . ($mailSent ? 'Yes' : 'No') . "\n";
file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);
?>