<?php
session_start();

// Si l'utilisateur n'est pas connecté, redirigez-le vers la page de connexion
if (!isset($_SESSION["user_id"])) {
    header("Location: index.php");
    exit;
}

$connected_user_id = $_SESSION["user_id"];

// Connexion à la base de données
try {
    $conn = new PDO('mysql:host=mysql;dbname='. getenv('MYSQL_DATABASE'), getenv('MYSQL_USER'), getenv('MYSQL_PASSWORD'));
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Si le formulaire d'ajout de contact est soumis
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $nom = $_POST["nom"];
        $prenom = $_POST["prenom"];
        $email = $_POST["email"];

        // Vérification si l'email du contact existe déjà
        $stmt = $conn->prepare("SELECT email FROM contacts WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            echo "Cette adresse email existe déjà!";
            exit;
        }

        // Insertion du contact dans la base de données
        $stmt = $conn->prepare("INSERT INTO contacts (first_name, last_name, email, user_id) VALUES (?, ?, ?, ?)");
        $stmt->execute([$prenom, $nom, $email, $connected_user_id]);
        echo "Contact ajouté avec succès!";
    }

    // Récupération des contacts de l'utilisateur connecté
    $stmt = $conn->prepare("SELECT first_name, last_name, email FROM contacts WHERE user_id = ?");
    $stmt->execute([$connected_user_id]);
    $contacts = $stmt->fetchAll();

} catch (PDOException $e) {
    echo "Erreur : " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tableau de Bord - Gestion des Contacts</title>
    <!-- Inclure les styles Bootstrap -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>

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
            <form>
                <div class="form-group">
                    <label for="nom">Nom</label>
                    <input type="text" class="form-control" id="nom" name="nom" required>
                </div>
                <div class="form-group">
                    <label for="prenom">Prénom</label>
                    <input type="text" class="form-control" id="prenom" name="prenom" required>
                </div>
                <div class="form-group">
                    <label for="email">Adresse e-mail</label>
                    <input type="email" class="form-control" id="email" name="email" required>
                </div>
                <button type="submit" class="btn btn-primary">Ajouter Contact</button>
            </form>
        </div>
        <div class="col-md-6">
            <!-- Liste des contacts -->
            <h3>Liste des Contacts</h3>
            <ul class="list-group">
                <?php
                    foreach ($contacts as $contact) {
                        echo "<li class='list-group-item'>{$contact['first_name']} {$contact['last_name']} - {$contact['email']}</li>";
                    }
                ?>
            </ul>
        </div>
    </div>
</div>

<!-- Inclure les scripts Bootstrap -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>

</body>
</html>
