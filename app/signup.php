<?php
// Protége contre les attaques de type cross-site scripting (XSS)
header('Content-Security-Policy: default-src \'self\'; script-src \'self\' https://code.jquery.com https://cdnjs.cloudflare.com https://maxcdn.bootstrapcdn.com; style-src \'self\' https://maxcdn.bootstrapcdn.com; img-src \'self\';');
// Protection contre le clickjacking, empêche les iframes
header('X-Frame-Options: DENY');
session_start();

// Génération du jeton CSRF s'il n'existe pas
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Vérification si le formulaire a été soumis
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Vérification du jeton CSRF
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('Invalid CSRF token');
    }

    $prenom = htmlspecialchars($_POST["prenom"], ENT_QUOTES, 'UTF-8');
    $nom = htmlspecialchars($_POST["nom"], ENT_QUOTES, 'UTF-8');
    $password = htmlspecialchars($_POST["password"], ENT_QUOTES, 'UTF-8');
    $password_repeat = htmlspecialchars($_POST["password_repeat"], ENT_QUOTES, 'UTF-8');
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);

    // Vérification de la longueur minimale du mot de passe
    if (strlen($password) < 8) {
        $error_message = "Le mot de passe doit comporter au moins 8 caractères!";
    }
    // Vérification si les mots de passe correspondent
    elseif ($password !== $password_repeat) {
        $error_message = "Les mots de passe ne correspondent pas!";
    } else {
        // Connexion à la base de données
        try {
            $conn = new PDO('mysql:host=mysql;dbname='. getenv('MYSQL_DATABASE'), getenv('MYSQL_USER'), getenv('MYSQL_PASSWORD'));
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Vérification si l'email existe déjà
            $stmt = $conn->prepare("SELECT email FROM users WHERE email = ?");
            $stmt->execute([$email]);
            if ($stmt->fetch()) {
                $error_message = "L'inscription a échoué. Veuillez réessayer.";
            } else {
                // Cryptage du mot de passe
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);

                // Insertion de l'utilisateur dans la base de données
                $stmt = $conn->prepare("INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)");
                $stmt->execute([$prenom, $nom, $email, $hashed_password]);
                $success_message = "Inscription réussie! Vous serez redirigé dans <span id='countdown'>3</span> secondes.";
            }
        } catch (PDOException $e) {
            $error_message = "Erreur : " . $e->getMessage();
        }
    }
}

// En-têtes de sécurité
header("Content-Security-Policy: default-src 'self'; script-src 'self' code.jquery.com cdnjs.cloudflare.com maxcdn.bootstrapcdn.com; style-src 'self' maxcdn.bootstrapcdn.com;");
header('X-Frame-Options: DENY');
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Formulaire d'Inscription</title>
    <!-- Inclure jQuery -->
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <!-- Inclure les styles Bootstrap -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">       
    <!-- Inclure les scripts Bootstrap -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js" defer></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js" defer></script>
</head>
<body>

<div class="container mt-5">
    <h2>Formulaire d'Inscription</h2>
    <?php
    // Afficher le message d'erreur s'il existe
    if (isset($error_message)) {
        echo "<div class='alert alert-danger mt-2' role='alert'>" . $error_message . "</div>";
    }
    if (isset($success_message)) {
        echo "<div class='alert alert-success mt-2' role='alert' id='success-message'>" . $success_message . "</div>";
        echo "<script>
            function startCountdown() {
                let countdown = 3;
                const interval = setInterval(() => {
                    if (countdown === 0) {
                        document.getElementById('success-message').innerText = \"C'est parti!\";
                        clearInterval(interval);
                        setTimeout(() => {
                            window.location.href = 'index.php';
                        }, 1000);
                    } else {
                        document.getElementById('countdown').innerText = countdown;
                        countdown--;
                    }
                }, 1000);
            }
            startCountdown();
        </script>";
    }
    ?>
    <form action="#" method="POST">
        <!-- Champ : Prénom -->
        <div class="form-group">
            <label for="prenom">Prénom</label>
            <input type="text" class="form-control" id="prenom" name="prenom" value="<?php echo isset($prenom) ? $prenom : ''; ?>" required>
        </div>

        <!-- Champ : Nom -->
        <div class="form-group">
            <label for="nom">Nom</label>
            <input type="text" class="form-control" id="nom" name="nom" value="<?php echo isset($nom) ? $nom : ''; ?>" required>
        </div>

        <!-- Champ : Adresse e-mail -->
        <div class="form-group">
            <label for="email">Adresse e-mail</label>
            <input type="email" class="form-control" id="email" name="email" value="<?php echo isset($email) ? $email : ''; ?>" required>
        </div>

        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

        <!-- Champ : Mot de passe -->
        <div class="form-group">
            <label for="password">Mot de passe</label>
            <input type="password" class="form-control" id="password" name="password" required>
        </div>

        <!-- Champ : Répéter le mot de passe -->
        <div class="form-group">
            <label for="password_repeat">Répéter le mot de passe</label>
            <input type="password" class="form-control" id="password_repeat" name="password_repeat" required>
        </div>

        <!-- Bouton d'envoi -->
        <button type="submit" class="btn btn-primary">S'inscrire</button>
        <a href="index.php" class="ml-4" style="text-decoration: underline;">Je me connecte</a>
    </form>
</div>
</body>
</html>
