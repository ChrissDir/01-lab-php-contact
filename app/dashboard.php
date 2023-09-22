<?php
require_once 'database.php';  // Inclure le fichier database.php
// ------------------------------
// Configuration initiale
// ------------------------------
$nonce = bin2hex(random_bytes(16));
setSecurityHeaders($nonce);
session_start();
handleInactivity();
list($email_error, $success_message, $contacts) = manageContacts();

// ------------------------------
// Fonctions
// ------------------------------

// ------------------------------
// Configuration des en-têtes de sécurité
// ------------------------------
function setSecurityHeaders($nonce) {
    header("Content-Security-Policy: default-src 'self'; script-src 'self' https://code.jquery.com 'nonce-$nonce' https://cdn.jsdelivr.net; style-src 'self' 'nonce-$nonce' https://cdn.jsdelivr.net;");
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
}

// ------------------------------
// Gestion de l'inactivité de l'utilisateur
// ------------------------------
function handleInactivity() {
    $timeout_duration = 1800; // 30 minutes
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

// ------------------------------
// Gestion des contacts
// ------------------------------
function manageContacts() {
    // Initialisation des variables
    $email_error = "";
    $success_message = "";
    $contacts = [];
    $connected_user_id = $_SESSION["user_id"];

    // Connexion à la base de données
    $conn = connectToDatabase();  // Utilisation de la fonction depuis database.php

    try {
        // Gestion de la suppression de contacts
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

        // Gestion de l'ajout de contacts
        if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["nom"])) {
            $nom = htmlspecialchars($_POST["nom"], ENT_QUOTES, 'UTF-8');
            $prenom = htmlspecialchars($_POST["prenom"], ENT_QUOTES, 'UTF-8');
            $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
            
            // Vérification de l'existence de l'email
            $stmt = $conn->prepare("SELECT email FROM contacts WHERE email = ?");
            $stmt->execute([$email]);
            if ($stmt->fetch()) {
                $email_error = "Cette adresse email existe déjà!";
            } else {
                // Insertion du contact
                $stmt = $conn->prepare("INSERT INTO contacts (first_name, last_name, email, user_id) VALUES (?, ?, ?, ?)");
                $stmt->execute([$prenom, $nom, $email, $connected_user_id]);
                if ($stmt->rowCount() > 0) {
                    $success_message = "Contact ajouté avec succès!";
                } else {
                    $email_error = "Erreur lors de l'ajout du contact!";
                }
            }
        }

        // Récupération des contacts
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
    <!-- Inclure le CSS de Bootstrap -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    <!-- Inclure le JS de Bootstrap (qui inclut également Popper.js) -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous" defer></script>
    <script src="./dashboard.js" defer></script>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark bg-primary">
    <div class="container-fluid d-flex justify-content-between">
        <p class="navbar-brand m-0 ml-3">
        <?php 
        echo isset($_SESSION["first_name"]) ? "Tableau de bord de " . ucfirst($_SESSION["first_name"]) . " " . ucfirst($_SESSION["last_name"]) : "Mon Tableau de Bord"; 
        ?>
        </p>
        <a class="navbar-brand m-0 mr-3" href="logout.php">Se déconnecter</a>
    </div>
</nav>

<div class="container mt-5">
    <h2 class="mb-4">Tableau de Bord - Gestion des Contacts</h2>
    <p class="mb-4">Bienvenue dans votre tableau de bord de gestion des contacts. Vous pouvez ajouter ou supprimer des contacts ici.</p>
    <div class="row">
        <div class="col-md-6 mb-4">
            <!-- Formulaire d'ajout de contact -->
            <div class="card p-4">
                <h4 class="mb-3">Ajouter un contact</h4>
                <form action="" method="POST">
                    <div class="form-group mb-3">
                        <label for="nom">Nom</label>
                        <input type="text" class="form-control" id="nom" name="nom" required>
                    </div>
                    <div class="form-group mb-3">
                        <label for="prenom">Prénom</label>
                        <input type="text" class="form-control" id="prenom" name="prenom" required>
                    </div>

                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                    <div class="form-group mb-3">
                        <label for="email">Adresse e-mail</label>
                        <input type="email" class="form-control" id="email" name="email" required>
                        <?php
                        if ($email_error) {
                            echo "<small class='text-danger mt-2 d-block'>$email_error</small>";
                        }
                        if ($success_message) {
                            echo "<div class='alert alert-success mt-3'>$success_message</div>";
                        }
                        ?>
                    </div>
                    <button type="submit" class="btn btn-primary mt-2">Ajouter Contact</button>
                </form>
            </div>
        </div>
        <div class="col-md-6">
            <h3 class="mb-4">Liste des Contacts</h3>
            <ul class="list-group">
                <?php
                    foreach ($contacts as $contact) {
                        echo "<li class='list-group-item d-flex justify-content-between align-items-center'>";
                        echo "{$contact['first_name']} {$contact['last_name']} - {$contact['email']}";
                        // Début du formulaire de suppression
                        echo "<form method='post' class='d-inline-block delete-contact-form'>";
                        echo "<input type='hidden' name='delete_contact_id' value='{$contact['id']}'>";
                        echo "<button type='submit' class='btn btn-link p-0 border-0 text-danger'>";
                        echo '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-trash" viewBox="0 0 20 20">';
                        echo '<path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5Zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5Zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6Z"/>';
                        echo '<path d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1ZM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118ZM2.5 3h11V2h-11v1Z"/>';
                        echo '</svg>';
                        echo "</button>";
                        echo "</form>";
                        echo "</li>";
                    }
                ?>
            </ul>
        </div>
    </div>
</div>