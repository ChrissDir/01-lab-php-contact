-- Vérification de l'existence de la base de données pr1
CREATE DATABASE IF NOT EXISTS pr1;

-- Utilisation de la base de données pr1
USE pr1;

-- Vérification de l'existence de la table users et création si elle n'existe pas
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    resetToken VARCHAR(64) DEFAULT NULL, -- Ajout de la colonne resetToken
    resetTokenExpiration DATETIME DEFAULT NULL -- Ajout de la colonne resetTokenExpiration
);

-- Vérification de l'existence de la table contacts et création si elle n'existe pas
CREATE TABLE IF NOT EXISTS contacts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);