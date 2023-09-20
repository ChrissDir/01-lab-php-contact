<?php
// En-têtes de sécurité
setSecurityHeaders();
session_start();

// Génération du jeton CSRF s'il n'existe pas
initializeCSRFToken();

// Traitement du formulaire
$message = handleForm();

function setSecurityHeaders() {
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL' cdn.jsdelivr.net code.jquery.com cdnjs.cloudflare.com maxcdn.bootstrapcdn.com; style-src 'self' 'sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN' cdn.jsdelivr.net maxcdn.bootstrapcdn.com; img-src 'self' data:;");
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
}

function initializeCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

function handleForm() {
    if ($_SERVER["REQUEST_METHOD"] !== "POST") {
        return;
    }

    // Vérification du jeton CSRF
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('Invalid CSRF token');
    }

    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    return resetPassword($email);
}

function resetPassword($email) {
    try {
        $conn = new PDO('mysql:host=mysql;dbname='. getenv('MYSQL_DATABASE'), getenv('MYSQL_USER'), getenv('MYSQL_PASSWORD'));
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Vérification si l'email existe dans la base de données
        $stmt = $conn->prepare("SELECT email FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            // TODO: Ajoutez la logique de réinitialisation du mot de passe ici
            return "<div class='alert alert-success' role='alert'>Si cet e-mail est associé à un compte, un lien pour réinitialiser votre mot de passe vous a été envoyé !</div>";
        } else {
            return "<div class='alert alert-info' role='alert'>Si cet e-mail est associé à un compte, un lien pour réinitialiser votre mot de passe vous a été envoyé !</div>";
        }
    } catch (PDOException $e) {
        return "<div class='alert alert-danger' role='alert'>Erreur : " . $e->getMessage() . "</div>";
    }
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Réinitialisation du mot de passe</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous" defer></script>
</head>
<body class="bg-light">
<div class="container py-5">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card p-4">
                <div class="d-flex justify-content-between mb-4">
                    <h2>Réinitialiser votre mot de passe</h2>
                    <a href="index.php" class="btn btn-secondary align-self-start">Retour</a>
                </div>
                <form action="forgot_password.php" method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <div class="mb-3">
                        <label for="email" class="form-label">Entrez votre adresse e-mail</label>
                        <input type="email" class="form-control" id="email" name="email" required>
                    </div>
                    <?php
                    if (!empty($message)) {
                        echo "<div class='alert-info'>$message</div>";
                    } ?>
                    <button type="submit" class="btn btn-primary">Réinitialiser le mot de passe</button>
                </form>
            </div>
        </div>
    </div>
</div>
</body>
</html>

