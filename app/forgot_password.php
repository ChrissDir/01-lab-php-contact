<?php
session_start();

// Génération du jeton CSRF s'il n'existe pas
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Vérification du jeton CSRF
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('Invalid CSRF token');
    }

    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);

    // Connexion à la base de données
    try {
        $conn = new PDO('mysql:host=mysql;dbname='. getenv('MYSQL_DATABASE'), getenv('MYSQL_USER'), getenv('MYSQL_PASSWORD'));
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Vérification si l'email existe dans la base de données
        $stmt = $conn->prepare("SELECT email FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            // Générer un token unique pour la réinitialisation
            $reset_token = bin2hex(random_bytes(32));
            // Stocker ce token dans la base de données avec une date d'expiration
            // Envoyer un e-mail à l'utilisateur avec le lien de réinitialisation contenant le token
            // La logique d'envoi d'e-mail et de stockage du token doit être ajoutée ici
        }
        echo "Si cet e-mail est associé à un compte, un lien pour réinitialiser votre mot de passe vous a été envoyé.";
    } catch (PDOException $e) {
        echo "<div class='alert alert-danger' role='alert'>Erreur : " . $e->getMessage() . "</div>";
    }
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Réinitialisation du mot de passe</title>
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js" defer></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js" defer></script>
</head>
<body>
<div class="container mt-5">
    <h2>Réinitialiser votre mot de passe</h2>
    <form action="forgot_password.php" method="POST">
        <!-- Champ caché pour le jeton CSRF -->
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        
        <div class="form-group">
            <label for="email">Entrez votre adresse e-mail</label>
            <input type="email" class="form-control" id="email" name="email" required>
        </div>
        <button type="submit" class="btn btn-primary">Réinitialiser le mot de passe</button>
    </form>
</div>
</body>
</html>
