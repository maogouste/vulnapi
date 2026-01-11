FROM php:8.2-cli

# Install SQLite extension
RUN docker-php-ext-install pdo pdo_sqlite

WORKDIR /app

COPY index.php vulnerabilities.json ./

EXPOSE 3003

CMD ["php", "-S", "0.0.0.0:3003", "index.php"]
