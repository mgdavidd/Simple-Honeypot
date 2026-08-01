CREATE DATABASE IF NOT EXISTS wordpress;
USE wordpress;

CREATE TABLE wp_users (
    ID BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_login VARCHAR(60) UNIQUE,
    user_pass VARCHAR(255),
    user_email VARCHAR(100) UNIQUE,
    user_registered DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_status INT DEFAULT 0
);

CREATE TABLE wp_posts (
    ID BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    post_author BIGINT UNSIGNED,
    post_date DATETIME,
    post_content LONGTEXT,
    post_title TEXT,
    post_name VARCHAR(200),
    post_type VARCHAR(20) DEFAULT 'post',
    post_status VARCHAR(20) DEFAULT 'publish',
    FOREIGN KEY (post_author) REFERENCES wp_users(ID)
);

CREATE TABLE wp_options (
    option_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    option_name VARCHAR(191) UNIQUE,
    option_value LONGTEXT,
    autoload VARCHAR(20) DEFAULT 'yes'
);

INSERT INTO wp_users (user_login, user_pass, user_email) VALUES
('admin', '$2y$10$DXN3E8RCS33K2F.mZfsHXOAMFr2NHqH3rJZY8qH.L.XXVJ1TFm9Ia', 'admin@wordpress.local'),
('editor', '$2y$10$fakepasswordhash123456789', 'editor@wordpress.local');

INSERT INTO wp_options (option_name, option_value) VALUES
('siteurl', 'http://honeypot.local'),
('home', 'http://honeypot.local'),
('admin_email', 'admin@honeypot.local'),
('users_can_register', '0');

INSERT INTO wp_posts (post_author, post_date, post_content, post_title, post_name, post_type) VALUES
(1, NOW(), 'Welcome to our honeypot', 'Hello World', 'hello-world', 'post');