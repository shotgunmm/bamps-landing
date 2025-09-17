<?php
// submit-email.php - Handle email form submission

// Enable error reporting for debugging (remove in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Set headers for CORS if needed
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

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

// Save to CSV file
$csvFile = 'email_signups.csv';
$timestamp = date('Y-m-d H:i:s');

// Check if file exists, if not create it with headers
if (!file_exists($csvFile)) {
    $headers = ['Email', 'Timestamp'];
    $fp = fopen($csvFile, 'w');
    fputcsv($fp, $headers);
    fclose($fp);
}

// Append the new email
$fp = fopen($csvFile, 'a');
fputcsv($fp, [$email, $timestamp]);
fclose($fp);

// Send notification email
$to = 'mmckenna@shieldssgf.com';
$subject = "New Bamp's Toy Vault Website Signup";
$message = "A new visitor has signed up for updates on the Bamp's Toy Vault website.\n\n";
$message .= "Email: " . $email . "\n";
$message .= "Date/Time: " . $timestamp . "\n";

$headers = "From: noreply@bampstoys.com\r\n";
$headers .= "Reply-To: " . $email . "\r\n";
$headers .= "X-Mailer: PHP/" . phpversion();

// Send the email
$mailSent = mail($to, $subject, $message, $headers);

// Return response
if ($mailSent) {
    echo json_encode(['success' => true, 'message' => 'Thank you!']);
} else {
    // Still return success if CSV was saved but email failed
    echo json_encode(['success' => true, 'message' => 'Signup saved successfully']);
}
?>