<?php
require_once 'database.php';  // Inclure le fichier database.php
// ------------------------------
// Fonctions
// ------------------------------

function initializeLoginAttempts() {
    if (!isset($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = 0;
    }
    
    if (!isset($_SESSION['last_attempt_time'])) {
        $_SESSION['last_attempt_time'] = null;
    }

    $lockout_time = 600;
    if ($_SESSION['login_attempts'] >= 5 && (time() - $_SESSION['last_attempt_time']) < $lockout_time) {
        $_SESSION['lockout'] = true;
        $_SESSION['remaining_lockout_time'] = $lockout_time - (time() - $_SESSION['last_attempt_time']);
    } else {
        $_SESSION['lockout'] = false;
    }
}

function handleLoginForm($conn) {
    global $error_message;

    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        session_destroy();
        die('Invalid CSRF token');
    }

    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $password = htmlspecialchars($_POST["password"], ENT_QUOTES, 'UTF-8');

    try {
        $stmt = $conn->prepare("SELECT id, first_name, last_name, password FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user["password"])) {
            $_SESSION["user_id"] = $user["id"];
            $_SESSION["first_name"] = $user["first_name"];
            $_SESSION["last_name"] = $user["last_name"];
            
            if (isset($_POST["rememberMe"])) {
                setcookie("user_id", $user["id"], time() + (86400 * 30), "/", "", true, true);
            }
            
            header("Location: dashboard.php");
            exit;
        } else {
            $error_message = "Adresse e-mail ou mot de passe incorrect!";
            $_SESSION['login_attempts']++;
            $_SESSION['last_attempt_time'] = time();
            error_log('Tentative de connexion échouée pour l\'email: ' . $email);
        }
    } catch (PDOException $e) {
        error_log('Error while checking user: ' . $e->getMessage());
        $error_message = "Une erreur est survenue. Veuillez réessayer plus tard.";
    }
}

// ------------------------------
// En-têtes de sécurité
// ------------------------------
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL' cdn.jsdelivr.net code.jquery.com cdnjs.cloudflare.com maxcdn.bootstrapcdn.com; style-src 'self' 'sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN' cdn.jsdelivr.net maxcdn.bootstrapcdn.com; img-src 'self' data:;");
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');

// ------------------------------
// Initialisation de la session
// ------------------------------
session_start();

if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ------------------------------
// Redirection si déjà connecté
// ------------------------------
if (isset($_SESSION["user_id"])) {
    header("Location: dashboard.php");
    exit;
}

// ------------------------------
// Gestion des tentatives de connexion
// ------------------------------

initializeLoginAttempts();

// ------------------------------
// Connexion à la base de données
// ------------------------------

$conn = connectToDatabase();  // Utilisation de la fonction depuis database.php

// ------------------------------
// Gestion du formulaire de connexion
// ------------------------------

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    handleLoginForm($conn);
} elseif (isset($_COOKIE["user_id"])) {
    $_SESSION["user_id"] = $_COOKIE["user_id"];
    header("Location: dashboard.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Formulaire de Connexion</title>
    <!-- Inclure le CSS de Bootstrap -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    <!-- Inclure le JS de Bootstrap (qui inclut également Popper.js) -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous" defer></script>
    <script src="./login.js" defer></script>
</head>
<body class="bg-light d-flex flex-column vh-100">
<div id="lockout-data" data-lockout="<?php echo isset($_SESSION['lockout']) ? $_SESSION['lockout'] : false; ?>" data-remaining-time="<?php echo isset($_SESSION['remaining_lockout_time']) ? $_SESSION['remaining_lockout_time'] : 0; ?>"></div>

<nav class="navbar navbar-expand-lg navbar-dark bg-primary">
    <div class="container-fluid d-flex justify-content-between">
        <a class="navbar-brand m-0 ml-3" href="#">Mon Site</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"
            aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ms-auto">
                <li class="nav-item">
                    <a class="navbar-brand m-0 mr-3" href="signup.php">S'inscrire</a>
                </li>
            </ul>
        </div>
    </div>
</nav>

<div class="d-flex flex-column vh-100 justify-content-center mt-n5 pb-5 mb-5">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h2>Formulaire de Connexion</h2>
                    </div>
                    <div class="card-body">
                        <?php
                        // ------------------------------
                        // Afficher le message d'erreur s'il existe
                        // ------------------------------
                        if (isset($error_message)) {
                            echo "<div class='alert alert-danger mt-2' role='alert'>" . $error_message . "</div>";
                        }
                        ?>
                        <form action="" method="POST">
                            <div class="form-group mb-3">
                                <label for="email">Adresse e-mail</label>
                                <input type="email" class="form-control" id="email" name="email"
                                    value="<?php echo isset($email) ? $email : ''; ?>" required>
                            </div>
                            <div class="form-group mb-3">
                                <label for="password">Mot de passe</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>

                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                            <div class="form-group form-check mb-3">
                                <input type="checkbox" class="form-check-input" id="rememberMe" name="rememberMe">
                                <label class="form-check-label" for="rememberMe">Se souvenir de moi</label>
                            </div>
                            <div class="form-group mb-3">
                                <a href="forgot_password.php">Mot de passe oublié ?</a>
                            </div>
                            <button type="submit" class="btn btn-primary">Se connecter</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

</body>
</html>
