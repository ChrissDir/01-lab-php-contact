<?php
require_once 'config.php';

function connectToDatabase() {
    try {
        $conn = new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME, DB_USER, DB_PASS);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $conn;
    } catch (PDOException $e) {
        error_log('Database connection failed: ' . $e->getMessage());
        die('Une erreur est survenue. Veuillez réessayer plus tard.');
    }
}
?>