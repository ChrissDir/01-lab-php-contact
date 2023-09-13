<?php
session_start();

// Si l'utilisateur est déjà connecté, redirigez-le vers le tableau de bord
if (isset($_SESSION["user_id"])) {
    header("Location: dashboard.php");
    exit;
}

// Connexion à la base de données
$conn = new PDO('mysql:host=mysql;dbname='. getenv('MYSQL_DATABASE'), getenv('MYSQL_USER'), getenv('MYSQL_PASSWORD'));
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Vérification si le formulaire a été soumis
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);

    // Vérification de l'utilisateur dans la base de données
    $stmt = $conn->prepare("SELECT id, password FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user["password"])) {
        // L'utilisateur est authentifié
        $_SESSION["user_id"] = $user["id"];
        
        // Si "Se souvenir de moi" est coché
        if (isset($_POST["rememberMe"])) {
            setcookie("user_id", $user["id"], time() + (86400 * 30), "/");
        }
        
        header("Location: dashboard.php");
        exit;
    } else {
        $error_message = "Adresse e-mail ou mot de passe incorrect!";
    }
} elseif (isset($_COOKIE["user_id"])) {
    $_SESSION["user_id"] = $_COOKIE["user_id"];
    header("Location: dashboard.php");
    exit;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Formulaire de Connexion</title>
    <!-- Inclure les scripts Bootstrap -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js" defer></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js" defer></script>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-light bg-light">
    <a class="navbar-brand" href="#">Mon Site</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ml-auto">            
            <li class="nav-item">
                <a class="nav-link" href="signup.php">S'inscrire</a>
            </li>
        </ul>
    </div>
</nav>

<div class="container mt-5">
    <h2>Formulaire de Connexion</h2>
    <?php if (isset($error_message)) { echo "<div class='alert alert-danger mt-2' role='alert'>" . $error_message . "</div>"; } ?>
    <form action="#" method="POST">
        <div class="form-group">
            <label for="email">Adresse e-mail</label>
            <input type="email" class="form-control" id="email" name="email" required>
        </div>
        <div class="form-group">
            <label for="password">Mot de passe</label>
            <input type="password" class="form-control" id="password" name="password" required>
        </div>
        <div class="form-group form-check">
            <input type="checkbox" class="form-check-input" id="rememberMe" name="rememberMe">
            <label class="form-check-label" for="rememberMe">Se souvenir de moi</label>
        </div>
        <div class="form-group">
            <a href="forgot_password.php">Mot de passe oublié ?</a>
        </div>
        <button type="submit" class="btn btn-primary">Se connecter</button>
    </form>
</div>

</body>
</html>