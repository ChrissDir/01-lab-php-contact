<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    // Ici, vérifiez si l'email existe dans la base de données.
    // Si c'est le cas, envoyez un e-mail avec un lien pour réinitialiser le mot de passe.
    echo "Si cet e-mail est associé à un compte, un lien pour réinitialiser votre mot de passe vous a été envoyé.";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Réinitialisation du mot de passe</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js" defer></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js" defer></script>
</head>
<body>
<div class="container mt-5">
    <h2>Réinitialiser votre mot de passe</h2>
    <form action="forgot_password.php" method="POST">
        <div class="form-group">
            <label for="email">Entrez votre adresse e-mail</label>
            <input type="email" class="form-control" id="email" name="email" required>
        </div>
        <button type="submit" class="btn btn-primary">Réinitialiser le mot de passe</button>
    </form>
</div>
</body>
</html>
