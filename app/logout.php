<?php
// Protection contre les attaques de type "Clickjacking"
header('X-Frame-Options: DENY');

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

// Supprimer le cookie user_id pour interrompre aussi le choix du "se souvenir de moi" s'il a été coché
if (isset($_COOKIE["user_id"])) {
    setcookie("user_id", "", time() - 3600, "/");
}

// Détruire la session
session_destroy();

// Rediriger vers index.php
header("Location: index.php");
exit;
?>