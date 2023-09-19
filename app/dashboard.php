<?php
// Génération d'un nonce pour la CSP
$nonce = bin2hex(random_bytes(16));

// En-têtes de sécurité
setSecurityHeaders($nonce);
session_start();

// Gestion de l'inactivité
handleInactivity();

// Gestion des contacts
list($email_error, $success_message, $contacts) = manageContacts();

function setSecurityHeaders($nonce) {
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$nonce' https://code.jquery.com https://cdnjs.cloudflare.com https://maxcdn.bootstrapcdn.com; style-src 'self' https://maxcdn.bootstrapcdn.com 'nonce-$nonce'; img-src 'self' data:;");
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
}

function handleInactivity() {
    $timeout_duration = 1800;
    if (isset($_SESSION['LAST_ACTIVITY']) && (time() - $_SESSION['LAST_ACTIVITY'] > $timeout_duration)) {
        header("Location: logout.php");
        exit;
    }
    $_SESSION['LAST_ACTIVITY'] = time();
    if (!isset($_SESSION["user_id"])) {
        header("Location: index.php");
        exit;
    }
}

function manageContacts() {
    $email_error = "";
    $success_message = "";
    $contacts = [];
    
    $connected_user_id = $_SESSION["user_id"];

    // Connexion à la base de données
    try {
        $conn = new PDO('mysql:host=mysql;dbname='. getenv('MYSQL_DATABASE'), getenv('MYSQL_USER'), getenv('MYSQL_PASSWORD'));
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Si une demande de suppression de contact est soumise
        if (isset($_POST["delete_contact_id"])) {
            $contact_id_to_delete = intval($_POST["delete_contact_id"]);
            $stmt = $conn->prepare("DELETE FROM contacts WHERE id = ? AND user_id = ?");
            $stmt->execute([$contact_id_to_delete, $connected_user_id]);
            if ($stmt->rowCount() > 0) {
                $success_message = "Contact supprimé avec succès!";
            } else {
                $email_error = "Erreur lors de la suppression du contact!";
            }
        }

        // Si le formulaire d'ajout de contact est soumis
        if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["nom"])) {
            $nom = htmlspecialchars($_POST["nom"], ENT_QUOTES, 'UTF-8');
            $prenom = htmlspecialchars($_POST["prenom"], ENT_QUOTES, 'UTF-8');
            $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
            // Vérification si l'email du contact existe déjà
            $stmt = $conn->prepare("SELECT email FROM contacts WHERE email = ?");
            $stmt->execute([$email]);
            if ($stmt->fetch()) {
                $email_error = "Cette adresse email existe déjà!";
            } else {
                // Insertion du contact dans la base de données
                $stmt = $conn->prepare("INSERT INTO contacts (first_name, last_name, email, user_id) VALUES (?, ?, ?, ?)");
                $stmt->execute([$prenom, $nom, $email, $connected_user_id]);
                if ($stmt->rowCount() > 0) {
                    $success_message = "Contact ajouté avec succès!";
                } else {
                    $email_error = "Erreur lors de l'ajout du contact!";
                }
            }
        }

        // Récupération des contacts de l'utilisateur connecté
        $stmt = $conn->prepare("SELECT id, first_name, last_name, email FROM contacts WHERE user_id = ?");
        $stmt->execute([$connected_user_id]);
        $contacts = $stmt->fetchAll();

    } catch (PDOException $e) {
        $email_error = "Erreur : " . $e->getMessage();
    }
    
    return [$email_error, $success_message, $contacts];
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tableau de Bord - Gestion des Contacts</title>
    <!-- Inclure jQuery -->
    <script src="https://code.jquery.com/jquery-3.5.1.min.js" defer></script>
    <!-- Inclure les styles Bootstrap -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <!-- Inclure les scripts Bootstrap -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js" defer></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js" defer></script>
</head>
<body>
<script nonce="<?php echo $nonce; ?>">
    // Durée d'inactivité avant déconnexion (en millisecondes). Ici, 30 minutes.
    let timeoutDuration = 1800000;
    let timeout;

    // Réinitialisez le délai d'expiration à chaque interaction de l'utilisateur
    document.onmousemove = resetTimeout;
    document.onkeypress = resetTimeout;

    function logout() {
        window.location.href = 'logout.php';
    }

    function resetTimeout() {
        clearTimeout(timeout);
        timeout = setTimeout(logout, timeoutDuration);
    }

    // Initialisez le délai d'expiration
    resetTimeout();

    // Fonction pour confirmer la suppression d'un contact
    function confirmDelete() {
        return confirm("Êtes-vous sûr de vouloir supprimer ce contact?");
    }
</script>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
    <a class="navbar-brand" href="#">Mon Tableau de Bord</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ml-auto">            
            <li class="nav-item">
                <a class="nav-link" href="logout.php">Se déconnecter</a>
            </li>
        </ul>
    </div>
</nav>

<div class="container mt-5">
    <h2>Tableau de Bord - Gestion des Contacts</h2>
    <p>Bienvenue dans votre tableau de bord de gestion des contacts. Vous pouvez ajouter, modifier ou supprimer des contacts ici.</p>
    <div class="row">
        <div class="col-md-6">
            <!-- Formulaire d'ajout de contact -->
            <form action="" method="POST">
                <div class="form-group">
                    <label for="nom">Nom</label>
                    <input type="text" class="form-control" id="nom" name="nom" required>
                </div>
                <div class="form-group">
                    <label for="prenom">Prénom</label>
                    <input type="text" class="form-control" id="prenom" name="prenom" required>
                </div>

                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                <div class="form-group">
                    <label for="email">Adresse e-mail</label>
                    <input type="email" class="form-control" id="email" name="email" required>
                    <?php
                    if ($email_error) {
                        echo "<small class='text-danger'>$email_error</small>";
                    }
                    ?>
                    <?php
                    if ($success_message) {
                        echo "<div class='alert alert-success mt-3'>$success_message</div>";
                    }
                    ?>
                </div>
                <button type="submit" class="btn btn-primary">Ajouter Contact</button>
            </form>
        </div>
        <div class="col-md-6">
            <h3>Liste des Contacts</h3>
            <ul class="list-group">
                <?php
                    foreach ($contacts as $contact) {
                        echo "<li class='list-group-item'>";
                        echo "{$contact['first_name']} {$contact['last_name']} - {$contact['email']}";
                        // Début du formulaire de suppression
                        echo "<form method='post' class='d-inline-block ml-3 float-right' onsubmit='return confirmDelete($nonce);'>";
                        echo "<input type='hidden' name='delete_contact_id' value='{$contact['id']}'>";
                        echo "<button type='submit' class='btn btn-link p-0 border-0'>";
                        echo '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-trash" viewBox="0 0 20 20">';
                        echo '<path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5Zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5Zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6Z"/>';
                        echo '<path d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1ZM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118ZM2.5 3h11V2h-11v1Z"/>';
                        echo '</svg>';
                        echo "</button>";
                        echo "</form>";  // Fin du formulaire de suppression
                        echo "</li>";
                    }
                ?>
            </ul>
        </div>
    </div>
</div>
</body>
</html>