<?php
$host = "localhost";
$user = "root"; // your DB username
$pass = "";     // your DB password
$db   = "skillup";

$conn = new mysqli($host, $user, $pass, $db);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
