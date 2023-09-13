<?php

session_start();

// Si l'utilisateur est déjà connecté, redirigez-le vers le tableau de bord
if (isset($_SESSION["user_id"])) {
    header("Location: dashboard.php");
    exit;
}

// Vérification si le formulaire a été soumis
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST["email"];
    $password = $_POST["password"];

    // Connexion à la base de données
    try {
        $conn = new PDO('mysql:host=mysql;dbname='. getenv('MYSQL_DATABASE'), getenv('MYSQL_USER'), getenv('MYSQL_PASSWORD'));
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Vérification de l'utilisateur dans la base de données
        $stmt = $conn->prepare("SELECT id, password FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user["password"])) {
            // L'utilisateur est authentifié
            // Stockez l'ID de l'utilisateur dans la session
            $_SESSION["user_id"] = $user["id"];
            // Redirigez vers le tableau de bord
            header("Location: dashboard.php");
            exit;
        } else {
            echo "Adresse e-mail ou mot de passe incorrect!";
            exit;
        }
    } catch (PDOException $e) {
        echo "Erreur : " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Formulaire de Connexion</title>
    <!-- Inclure les styles Bootstrap -->
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
    <form action="#" method="POST">
        <!-- Champ : Adresse e-mail -->
        <div class="form-group">
            <label for="email">Adresse e-mail</label>
            <input type="email" class="form-control" id="email" name="email" required>
        </div>

        <!-- Champ : Mot de passe -->
        <div class="form-group">
            <label for="password">Mot de passe</label>
            <input type="password" class="form-control" id="password" name="password" required>
        </div>

        <!-- Option : Se souvenir de moi -->
        <div class="form-group form-check">
            <input type="checkbox" class="form-check-input" id="rememberMe" name="rememberMe">
            <label class="form-check-label" for="rememberMe">Se souvenir de moi</label>
        </div>

        <!-- Lien : Mot de passe oublié -->
        <div class="form-group">
            <a href="#">Mot de passe oublié ?</a>
        </div>

        <!-- Bouton d'envoi -->
        <button type="submit" class="btn btn-primary">Se connecter</button>
    </form>
</div>

<!-- Inclure les scripts Bootstrap -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>

</body>
</html>
