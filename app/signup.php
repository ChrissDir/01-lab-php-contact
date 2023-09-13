<?php
// Vérification si le formulaire a été soumis
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $prenom = $_POST["prenom"];
    $nom = $_POST["nom"];
    $email = $_POST["email"];
    $password = $_POST["password"];
    $password_repeat = $_POST["password_repeat"];

    // Vérification si les mots de passe correspondent
    if ($password !== $password_repeat) {
        echo "Les mots de passe ne correspondent pas!";
        exit;
    }

    // Connexion à la base de données
    try {
        $conn = new PDO('mysql:host=mysql;dbname='. getenv('MYSQL_DATABASE'), getenv('MYSQL_USER'), getenv('MYSQL_PASSWORD'));
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Vérification si l'email existe déjà
        $stmt = $conn->prepare("SELECT email FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            echo "Cette adresse email existe déjà!";
            exit;
        }

        // Cryptage du mot de passe
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Insertion de l'utilisateur dans la base de données
        $stmt = $conn->prepare("INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)");
        $stmt->execute([$prenom, $nom, $email, $hashed_password]);
        echo "Inscription réussie!";
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
    <title>Formulaire d'Inscription</title>
    <!-- Inclure les styles Bootstrap -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>

<div class="container mt-5">
    <h2>Formulaire d'Inscription</h2>
    <form action="#" method="POST">
        <!-- Champ : Prénom -->
        <div class="form-group">
            <label for="prenom">Prénom</label>
            <input type="text" class="form-control" id="prenom" name="prenom" required>
        </div>

        <!-- Champ : Nom -->
        <div class="form-group">
            <label for="nom">Nom</label>
            <input type="text" class="form-control" id="nom" name="nom" required>
        </div>

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

        <!-- Champ : Répéter le mot de passe -->
        <div class="form-group">
            <label for="password_repeat">Répéter le mot de passe</label>
            <input type="password" class="form-control" id="password_repeat" name="password_repeat" required>
        </div>

        <!-- Bouton d'envoi -->
        <button type="submit" class="btn btn-primary">S'inscrire</button>
    </form>
</div>

<!-- Inclure les scripts Bootstrap -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>

</body>
</html>
