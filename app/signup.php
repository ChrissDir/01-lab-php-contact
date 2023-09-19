<?php
session_start();

// Fonctions
function generateNonce() {
    return bin2hex(random_bytes(16));
}

function initializeCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

function sanitizeInput($input) {
    return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
}

function handleRegistrationForm() {
    global $error_message, $success_message;

    // Vérification du jeton CSRF
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('Invalid CSRF token');
    }

    $prenom = sanitizeInput($_POST["prenom"]);
    $nom = sanitizeInput($_POST["nom"]);
    $password = sanitizeInput($_POST["password"]);
    $password_repeat = sanitizeInput($_POST["password_repeat"]);
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);

    // Vérification de la complexité du mot de passe
    if (!preg_match('/[A-Z]/', $password) || !preg_match('/[a-z]/', $password) || !preg_match('/[0-9]/', $password) || strlen($password) < 8) {
        $error_message = "Le mot de passe doit comporter au moins 8 caractères, dont une majuscule, une minuscule et un chiffre.";
        return;
    }

    // Vérification si les mots de passe correspondent
    if ($password !== $password_repeat) {
        $error_message = "Les mots de passe ne correspondent pas!";
        return;
    }

    // Connexion à la base de données
    try {
        $conn = new PDO('mysql:host=mysql;dbname='. getenv('MYSQL_DATABASE'), getenv('MYSQL_USER'), getenv('MYSQL_PASSWORD'));
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Vérification si l'email existe déjà
        $stmt = $conn->prepare("SELECT email FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            $error_message = "L'adresse e-mail est déjà utilisée.";
            return;
        }

        // Cryptage du mot de passe
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Insertion de l'utilisateur dans la base de données
        $stmt = $conn->prepare("INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)");
        $stmt->execute([$prenom, $nom, $email, $hashed_password]);
        $success_message = "Inscription réussie! Vous serez redirigé dans <span id='countdown'>3</span> secondes.";
    } catch (PDOException $e) {
        error_log("Erreur lors de l'inscription : " . $e->getMessage()); // Log de l'erreur
        $error_message = "Une erreur est survenue. Veuillez réessayer plus tard.";
    }
}

// Génération d'un nonce pour la CSP
$nonce = generateNonce();
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://code.jquery.com https://cdnjs.cloudflare.com https://maxcdn.bootstrapcdn.com 'nonce-$nonce'; style-src 'self' https://maxcdn.bootstrapcdn.com 'nonce-$nonce';");
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');

// Génération du jeton CSRF s'il n'existe pas
initializeCSRFToken();

// Vérification si le formulaire a été soumis
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    handleRegistrationForm();
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Formulaire d'Inscription</title>
    <!-- Inclure jQuery -->
    <script src="https://code.jquery.com/jquery-3.5.1.min.js" defer></script>
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
    if (isset($error_message)) {
        echo "<div class='alert alert-danger mt-2' role='alert'>" . $error_message . "</div>";
    }
    if (isset($success_message)) {
        echo "<div class='alert alert-success mt-2' role='alert' id='success-message'>" . $success_message . "</div>";
        echo "<script nonce='$nonce'>
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
    <form action="" method="POST">
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
        <a href="index.php" class="ml-4">Je me connecte</a>
    </form>
    <style nonce="<?php echo $nonce; ?>">
            a.ml-4 {
                text-decoration: underline;
            }
    </style>
</div>
</body>
</html>
