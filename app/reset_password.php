<?php
require_once 'database.php';  // Inclure le fichier database.php
// ------------------------------
// Configuration des en-têtes de sécurité
// ------------------------------
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net;");
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
session_start();

// ------------------------------
// Fonctions
// ------------------------------

// ------------------------------
// Initialisation du jeton CSRF
// ------------------------------
function initializeCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

// ------------------------------
// Assainissement de l'entrée
// ------------------------------
function sanitizeInput($input) {
    return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
}

// ------------------------------
// Gestion de la réinitialisation du mot de passe
// ------------------------------
function handleResetPassword() {
    global $error_message, $success_message;

    // Vérification du jeton CSRF
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('Invalid CSRF token');
    }

    $password = sanitizeInput($_POST["password"]);
    $password_repeat = sanitizeInput($_POST["password_repeat"]);

    // Validation du mot de passe
    if (!preg_match('/[A-Z]/', $password) || !preg_match('/[a-z]/', $password) || !preg_match('/[0-9]/', $password) || strlen($password) < 8) {
        $error_message = "Le nouveau mot de passe doit comporter au moins 8 caractères, dont une majuscule, une minuscule et un chiffre.";
        return;
    }

    // Vérification de la correspondance des mots de passe
    if ($password !== $password_repeat) {
        $error_message = "Les mots de passe ne correspondent pas!";
        return;
    }

    // Connexion à la base de données
    $conn = connectToDatabase();  // Utilisation de la fonction depuis database.php

    try {
        // Vérification de l'existence du token
        $stmt = $conn->prepare("SELECT id FROM users WHERE resetToken = ? AND resetTokenExpiration > NOW()");
        $stmt->execute([$_GET['token']]);
        $user_id = $stmt->fetchColumn();

        if ($user_id) {
            // Mise à jour du mot de passe de l'utilisateur
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $conn->prepare("UPDATE users SET password = ?, resetToken = NULL, resetTokenExpiration = NULL WHERE id = ?");
            $stmt->execute([$hashed_password, $user_id]);

            $success_message = "Votre mot de passe a été réinitialisé avec succès!";
        } else {
            $error_message = "Token invalide ou expiré.";
        }
    } catch (PDOException $e) {
        error_log("Erreur lors de la réinitialisation du mot de passe : " . $e->getMessage());
        $error_message = "Une erreur est survenue. Veuillez réessayer plus tard.";
    }
}

// ------------------------------
// Initialisation du jeton CSRF
// ------------------------------
initializeCSRFToken();

// ------------------------------
// Gestion du formulaire de réinitialisation du mot de passe
// ------------------------------
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    handleResetPassword();
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Réinitialisation du mot de passe</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"
        integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous"
        defer></script>
</head>

<body class="bg-light d-flex justify-content-center align-items-center vh-100">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card p-4 shadow-sm">
                    <h2 class="mb-4">Réinitialiser votre mot de passe</h2>
                    <?php
                    if (isset($error_message)) {
                        echo "<div class='alert alert-danger alert-dismissible fade show mt-2 mb-4' role='alert'>
                                <i class='bi bi-exclamation-triangle-fill'></i> $error_message
                                <button type='button' class='btn-close' data-bs-dismiss='alert' aria-label='Close'></button>
                            </div>";
                    }
                    if (isset($success_message)) {
                        echo "<div class='alert alert-success mt-2 mb-4' role='alert' id='success-message'>" . $success_message . "</div>";
                    }
                    ?>
                    <form action="" method="POST" id="resetPasswordForm" class="needs-validation" novalidate>
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group mb-3">
                            <label for="password">Nouveau mot de passe</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                            <div class="invalid-feedback">
                                Mot de passe invalide.
                            </div>
                        </div>
                        <div class="form-group mb-4">
                            <label for="password_repeat">Répéter le mot de passe</label>
                            <input type="password" class="form-control" id="password_repeat" name="password_repeat"
                                required>
                            <div class="invalid-feedback">
                                Veuillez répéter votre mot de passe.
                            </div>
                        </div>
                        <button type="submit" class="btn btn-primary me-3">Réinitialiser le mot de passe</button>
                        <a href="index.php" class="text-decoration-underline">Je me connecte</a>
                    </form>
                </div>
            </div>
        </div>
    </div>
</body>

</html>
