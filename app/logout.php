<?php
session_start();

// Supprimer toutes les variables de session
$_SESSION = array();

// Supprimer le cookie de session pour une déconnexion complète
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Détruire la session
session_destroy();

// Ajouter un message flash
session_start(); 
$_SESSION['flash_message'] = "Vous avez été déconnecté avec succès!";
header("Location: index.php");
exit;
?>