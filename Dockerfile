FROM php:apache-bullseye

WORKDIR /app

RUN docker-php-ext-install pdo_mysql
