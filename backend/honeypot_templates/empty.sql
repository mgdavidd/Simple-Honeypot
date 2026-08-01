-- Plantilla vacía para MySQL honeypot
CREATE DATABASE IF NOT EXISTS honeypot;
USE honeypot;

-- Tabla de ejemplo
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE,
    password VARCHAR(255),
    email VARCHAR(255)
);

INSERT INTO users (username, password, email) VALUES
('admin', 'admin123', 'admin@honeypot.local'),
('test', 'test123', 'test@honeypot.local');