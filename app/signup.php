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

    // Récupération et assainissement des données
    $prenom = sanitizeInput($_POST["prenom"]);
    $nom = sanitizeInput($_POST["nom"]);
    $password = sanitizeInput($_POST["password"]);
    $password_repeat = sanitizeInput($_POST["password_repeat"]);
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);

    // Validation du mot de passe
    if (!preg_match('/[A-Z]/', $password) || !preg_match('/[a-z]/', $password) || !preg_match('/[0-9]/', $password) || strlen($password) < 8) {
        $error_message = "Le mot de passe doit comporter au moins 8 caractères, dont une majuscule, une minuscule et un chiffre.";
        return;
    }

    // Vérification de la correspondance des mots de passe
    if ($password !== $password_repeat) {
        $error_message = "Les mots de passe ne correspondent pas!";
        return;
    }

    // Connexion à la base de données et inscription
    try {
        $conn = new PDO('mysql:host=mysql;dbname='. getenv('MYSQL_DATABASE'), getenv('MYSQL_USER'), getenv('MYSQL_PASSWORD'));
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Vérification de l'existence de l'email
        $stmt = $conn->prepare("SELECT email FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            $error_message = "L'adresse e-mail est déjà utilisée.";
            return;
        }

        // Inscription de l'utilisateur
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $conn->prepare("INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)");
        $stmt->execute([$prenom, $nom, $email, $hashed_password]);
        $success_message = "Inscription réussie! Vous serez redirigé dans <span id='countdown'>3</span> secondes.";
    } catch (PDOException $e) {
        error_log("Erreur lors de l'inscription : " . $e->getMessage());
        $error_message = "Une erreur est survenue. Veuillez réessayer plus tard.";
    }
}

// Configuration des en-têtes de sécurité
$nonce = generateNonce();
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://code.jquery.com 'nonce-$nonce' https://cdn.jsdelivr.net; style-src 'self' 'nonce-$nonce' https://cdn.jsdelivr.net;");
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');

// Initialisation du jeton CSRF
initializeCSRFToken();

// Gestion du formulaire d'inscription
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
                    <h2 class="mb-4">Formulaire d'Inscription</h2>
                    <?php
                if (isset($error_message)) {
                    echo "<div class='alert alert-danger alert-dismissible fade show mt-2 mb-4' role='alert'>
                            <i class='bi bi-exclamation-triangle-fill'></i> $error_message
                            <button type='button' class='btn-close' data-bs-dismiss='alert' aria-label='Close'></button>
                          </div>";
                }
                if (isset($success_message)) {
                    echo "<div class='alert alert-success mt-2 mb-4' role='alert' id='success-message'>" . $success_message . "</div>";
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
                    <form action="" method="POST" id="registrationForm" class="needs-validation" novalidate>
                        <div class="form-group mb-3">
                            <label for="prenom">Prénom</label>
                            <input type="text" class="form-control" id="prenom" name="prenom"
                                value="<?php echo isset($prenom) ? $prenom : ''; ?>" required>
                            <div class="invalid-feedback">
                                Veuillez entrer votre prénom.
                            </div>
                        </div>
                        <div class="form-group mb-3">
                            <label for="nom">Nom</label>
                            <input type="text" class="form-control" id="nom" name="nom"
                                value="<?php echo isset($nom) ? $nom : ''; ?>" required>
                            <div class="invalid-feedback">
                                Veuillez entrer votre nom.
                            </div>
                        </div>
                        <div class="form-group mb-3">
                            <label for="email">Adresse e-mail</label>
                            <input type="email" class="form-control" id="email" name="email"
                                value="<?php echo isset($email) ? $email : ''; ?>" required>
                            <div class="invalid-feedback">
                                Veuillez entrer votre adresse mail.
                            </div>
                        </div>
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group mb-3">
                            <label for="password">Mot de passe</label>
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
                        <button type="submit" class="btn btn-primary me-3">S'inscrire</button>
                        <a href="index.php" class="text-decoration-underline">Je me connecte</a>
                    </form>
                    <script nonce='<?php echo $nonce; ?>'>
                        document.addEventListener('DOMContentLoaded', function () {
                            const registrationForm = document.getElementById('registrationForm');
                            registrationForm.addEventListener('submit', function (event) {
                                const password = document.getElementById('password').value;
                                const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
                                if (!regex.test(password)) {
                                    event.preventDefault();
                                    event.stopPropagation();
                                    alert('Le mot de passe doit comporter au moins 8 caractères, dont une majuscule, une minuscule et un chiffre.');
                                }
                                if (!event.target.checkValidity()) {
                                    event.preventDefault();
                                    event.stopPropagation();
                                    event.target.classList.add('was-validated');
                                }
                            });

                            if (document.getElementById('success-message')) {
                                let countdown = 3;
                                const interval = setInterval(() => {
                                    if (countdown === 0) {
                                        document.getElementById('success-message').innerText = "C'est parti!";
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
                        });
                    </script>
                </div>
            </div>
        </div>
    </div>
</body>

</html>