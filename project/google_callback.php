<?php
include 'db.php';
session_start();

// Replace these with your actual Google OAuth credentials
$google_client_id = 'YOUR_GOOGLE_CLIENT_ID'; // e.g. 3589...apps.googleusercontent.com
$google_client_secret = 'YOUR_GOOGLE_CLIENT_SECRET'; // e.g. GOCSPX-...
$google_redirect_uri = 'http://localhost/project/google_callback.php';

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

if (isset($_GET['code'])) {
    try {
        // Get the authorization code
        $code = $_GET['code'];

        // Exchange the code for an access token
        $token_url = 'https://oauth2.googleapis.com/token';
        $token_data = [
            'code' => $code,
            'client_id' => $google_client_id,
            'client_secret' => $google_client_secret,
            'redirect_uri' => $google_redirect_uri,
            'grant_type' => 'authorization_code'
        ];

        $ch = curl_init($token_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($token_data));
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // For development only
        $token_response = curl_exec($ch);
        
        if (curl_errno($ch)) {
            throw new Exception('Curl error: ' . curl_error($ch));
        }
        
        curl_close($ch);

        $token_data = json_decode($token_response, true);

        if (isset($token_data['error'])) {
            throw new Exception('Token error: ' . $token_data['error_description']);
        }

        if (isset($token_data['access_token'])) {
            // Get user info using the access token
            $user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo';
            $ch = curl_init($user_info_url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Authorization: Bearer ' . $token_data['access_token']
            ]);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // For development only
            $user_info_response = curl_exec($ch);
            
            if (curl_errno($ch)) {
                throw new Exception('Curl error: ' . curl_error($ch));
            }
            
            curl_close($ch);

            $user_info = json_decode($user_info_response, true);

            if (isset($user_info['error'])) {
                throw new Exception('User info error: ' . $user_info['error']['message']);
            }

            if (isset($user_info['email'])) {
                // Check if user exists in database
                $stmt = $conn->prepare("SELECT id, username FROM users WHERE email = ?");
                $stmt->bind_param("s", $user_info['email']);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows === 0) {
                    // Create new user
                    $username = explode('@', $user_info['email'])[0];
                    $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
                    $password = password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT);
                    $stmt->bind_param("sss", $username, $user_info['email'], $password);
                    $stmt->execute();
                    $user_id = $conn->insert_id;
                } else {
                    $stmt->bind_result($user_id, $username);
                    $stmt->fetch();
                }

                // Set session variables
                $_SESSION['user_id'] = $user_id;
                $_SESSION['username'] = $username;
                $_SESSION['email'] = $user_info['email'];

                // Redirect to home page
                header("Location: index.php");
                exit;
            } else {
                throw new Exception('No email found in user info');
            }
        } else {
            throw new Exception('No access token received');
        }
    } catch (Exception $e) {
        // Log the error
        error_log('Google OAuth Error: ' . $e->getMessage());
        
        // Store error in session
        $_SESSION['oauth_error'] = 'Google login failed: ' . $e->getMessage();
        
        // Redirect back to login with error
        header("Location: login.php");
        exit;
    }
}

// If something went wrong, redirect back to login
header("Location: login.php");
exit;
?> 