-- ============================================================
-- Honeypot E-commerce Database Template
-- Simula una tienda online con clientes, pedidos y productos
-- ============================================================

-- Crear la base de datos (opcional, el sistema la crea automáticamente)
CREATE DATABASE IF NOT EXISTS ecommerce;
USE ecommerce;

-- ============================================================
-- 1. TABLA DE CLIENTES
-- ============================================================
CREATE TABLE IF NOT EXISTS customers (
    customer_id INT PRIMARY KEY AUTO_INCREMENT,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    phone VARCHAR(20),
    address TEXT,
    city VARCHAR(50),
    state VARCHAR(50),
    postal_code VARCHAR(20),
    country VARCHAR(50) DEFAULT 'Colombia',
    registration_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    status ENUM('active', 'inactive', 'suspended') DEFAULT 'active',
    notes TEXT,
    INDEX idx_email (email),
    INDEX idx_status (status)
);

-- ============================================================
-- 2. TABLA DE PRODUCTOS
-- ============================================================
CREATE TABLE IF NOT EXISTS products (
    product_id INT PRIMARY KEY AUTO_INCREMENT,
    sku VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    category VARCHAR(50),
    subcategory VARCHAR(50),
    price DECIMAL(10,2) NOT NULL,
    cost DECIMAL(10,2),
    stock_quantity INT DEFAULT 0,
    min_stock INT DEFAULT 5,
    weight DECIMAL(8,2),
    dimensions VARCHAR(50),
    manufacturer VARCHAR(100),
    supplier VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_sku (sku),
    INDEX idx_category (category),
    INDEX idx_price (price)
);

-- ============================================================
-- 3. TABLA DE PEDIDOS
-- ============================================================
CREATE TABLE IF NOT EXISTS orders (
    order_id INT PRIMARY KEY AUTO_INCREMENT,
    order_number VARCHAR(20) UNIQUE NOT NULL,
    customer_id INT NOT NULL,
    order_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    status ENUM('pending', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded') DEFAULT 'pending',
    payment_method VARCHAR(50),
    payment_status ENUM('pending', 'paid', 'failed', 'refunded') DEFAULT 'pending',
    shipping_address TEXT NOT NULL,
    shipping_method VARCHAR(50),
    shipping_cost DECIMAL(10,2) DEFAULT 0.00,
    subtotal DECIMAL(10,2) NOT NULL,
    tax DECIMAL(10,2) DEFAULT 0.00,
    discount DECIMAL(10,2) DEFAULT 0.00,
    total DECIMAL(10,2) NOT NULL,
    notes TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id),
    INDEX idx_order_number (order_number),
    INDEX idx_customer (customer_id),
    INDEX idx_status (status),
    INDEX idx_date (order_date)
);

-- ============================================================
-- 4. TABLA DE DETALLES DE PEDIDO
-- ============================================================
CREATE TABLE IF NOT EXISTS order_items (
    order_item_id INT PRIMARY KEY AUTO_INCREMENT,
    order_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL,
    unit_price DECIMAL(10,2) NOT NULL,
    discount DECIMAL(10,2) DEFAULT 0.00,
    total DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(order_id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(product_id),
    INDEX idx_order (order_id),
    INDEX idx_product (product_id)
);

-- ============================================================
-- 5. TABLA DE CATEGORÍAS (relación muchos a muchos opcional)
-- ============================================================
CREATE TABLE IF NOT EXISTS categories (
    category_id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    parent_category_id INT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (parent_category_id) REFERENCES categories(category_id)
);

-- ============================================================
-- 6. TABLA DE RESEÑAS
-- ============================================================
CREATE TABLE IF NOT EXISTS reviews (
    review_id INT PRIMARY KEY AUTO_INCREMENT,
    product_id INT NOT NULL,
    customer_id INT NOT NULL,
    rating INT CHECK (rating BETWEEN 1 AND 5),
    title VARCHAR(100),
    comment TEXT,
    is_verified_purchase BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES products(product_id) ON DELETE CASCADE,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id),
    INDEX idx_product (product_id),
    INDEX idx_rating (rating)
);

-- ============================================================
-- 7. TABLA DE CARRITO DE COMPRAS
-- ============================================================
CREATE TABLE IF NOT EXISTS shopping_cart (
    cart_id INT PRIMARY KEY AUTO_INCREMENT,
    customer_id INT NOT NULL,
    session_id VARCHAR(100),
    product_id INT NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id),
    FOREIGN KEY (product_id) REFERENCES products(product_id),
    INDEX idx_customer (customer_id),
    INDEX idx_session (session_id)
);

-- ============================================================
-- 8. TABLA DE LOG DE ACTIVIDAD
-- ============================================================
CREATE TABLE IF NOT EXISTS activity_log (
    log_id INT PRIMARY KEY AUTO_INCREMENT,
    customer_id INT,
    action_type VARCHAR(50) NOT NULL,
    action_description TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_customer (customer_id),
    INDEX idx_action (action_type),
    INDEX idx_date (created_at)
);

-- ============================================================
-- INSERCIÓN DE DATOS DE PRUEBA (CLIENTES)
-- ============================================================
INSERT INTO customers (first_name, last_name, email, phone, address, city, state, postal_code, country) VALUES
('Juan', 'Pérez', 'juan.perez@email.com', '3105551234', 'Calle 45 # 23-12', 'Bogotá', 'Cundinamarca', '110111', 'Colombia'),
('María', 'Gómez', 'maria.gomez@email.com', '3205555678', 'Carrera 78 # 34-56', 'Medellín', 'Antioquia', '050001', 'Colombia'),
('Carlos', 'Rodríguez', 'carlos.rodriguez@email.com', '3005559012', 'Avenida 76 # 45-78', 'Cali', 'Valle del Cauca', '760001', 'Colombia'),
('Ana', 'Martínez', 'ana.martinez@email.com', '3185553456', 'Calle 12 # 8-34', 'Barranquilla', 'Atlántico', '080001', 'Colombia'),
('Luis', 'García', 'luis.garcia@email.com', '3125557890', 'Carrera 56 # 67-89', 'Bucaramanga', 'Santander', '680001', 'Colombia'),
('Laura', 'Fernández', 'laura.fernandez@email.com', '3155552345', 'Calle 32 # 45-67', 'Cartagena', 'Bolívar', '130001', 'Colombia'),
('Pedro', 'López', 'pedro.lopez@email.com', '3115556789', 'Avenida 89 # 12-34', 'Pereira', 'Risaralda', '660001', 'Colombia'),
('Sofía', 'Torres', 'sofia.torres@email.com', '3135551234', 'Carrera 23 # 56-78', 'Santa Marta', 'Magdalena', '470001', 'Colombia');

-- ============================================================
-- INSERCIÓN DE PRODUCTOS
-- ============================================================
INSERT INTO products (sku, name, description, category, subcategory, price, cost, stock_quantity, manufacturer, supplier) VALUES
('ELEC-001', 'Smartphone Galaxy S23 Ultra', 'Teléfono inteligente 5G, pantalla 6.8", cámara 200MP', 'Electrónica', 'Teléfonos', 1299.99, 900.00, 25, 'Samsung', 'Tecnología S.A.'),
('ELEC-002', 'Laptop Pro 16" M2', 'Laptop con procesador M2 Pro, 16GB RAM, 512GB SSD', 'Electrónica', 'Laptops', 2499.99, 1800.00, 12, 'Apple', 'Digital World'),
('ROPA-001', 'Camisa Polo Clásica', 'Camisa polo de algodón pima, cuello clásico', 'Ropa', 'Camisas', 45.99, 25.00, 75, 'Polo Classic', 'Textil Express'),
('ROPA-002', 'Jeans Slim Fit', 'Pantalones jeans ajustados, tela stretch', 'Ropa', 'Pantalones', 59.99, 32.00, 50, 'Denim Co', 'Moda Distribuidora'),
('HOGAR-001', 'Set de Sábanas Premium', 'Set completo 6 piezas 100% algodón egipcio', 'Hogar', 'Ropa de Cama', 89.99, 45.00, 30, 'Comfort Home', 'Hogar Ideal'),
('HOGAR-002', 'Licuadora Professional', 'Licuadora 1200W, jarra de vidrio 2L', 'Hogar', 'Electrodomésticos', 79.99, 40.00, 20, 'Kitchen Pro', 'Electro Hogar'),
('DEP-001', 'Bicicleta Montaña XC', 'Bicicleta todo terreno, suspensión delantera, 24 velocidades', 'Deportes', 'Ciclismo', 899.99, 600.00, 8, 'Mountain Bike Co', 'Bici Centro'),
('DEP-002', 'Pelota de Fútbol Pro', 'Pelota oficial tamaño 5, certificada FIFA', 'Deportes', 'Fútbol', 39.99, 20.00, 45, 'Goal Sports', 'Deportes Unidos');

-- ============================================================
-- INSERCIÓN DE PEDIDOS (ejemplo con estado variado)
-- ============================================================
INSERT INTO orders (order_number, customer_id, status, payment_method, payment_status, shipping_address, subtotal, tax, total) VALUES
('ORD-2024-0001', 1, 'delivered', 'credit_card', 'paid', 'Calle 45 # 23-12, Bogotá', 1345.98, 75.00, 1420.98),
('ORD-2024-0002', 2, 'processing', 'paypal', 'paid', 'Carrera 78 # 34-56, Medellín', 59.99, 3.00, 62.99),
('ORD-2024-0003', 3, 'shipped', 'bank_transfer', 'paid', 'Avenida 76 # 45-78, Cali', 169.98, 8.50, 178.48),
('ORD-2024-0004', 4, 'pending', 'credit_card', 'pending', 'Calle 12 # 8-34, Barranquilla', 89.99, 4.50, 94.49),
('ORD-2024-0005', 5, 'delivered', 'paypal', 'paid', 'Carrera 56 # 67-89, Bucaramanga', 2599.98, 145.00, 2744.98),
('ORD-2024-0006', 6, 'cancelled', 'credit_card', 'refunded', 'Calle 32 # 45-67, Cartagena', 79.99, 4.00, 83.99);

-- ============================================================
-- INSERCIÓN DE DETALLES DE PEDIDO
-- ============================================================
INSERT INTO order_items (order_id, product_id, quantity, unit_price, total) VALUES
(1, 1, 1, 1299.99, 1299.99),
(1, 5, 1, 45.99, 45.99),
(2, 3, 1, 59.99, 59.99),
(3, 4, 2, 89.99, 179.98),
(4, 5, 1, 89.99, 89.99),
(5, 2, 1, 2499.99, 2499.99),
(5, 8, 1, 99.99, 99.99),
(6, 6, 1, 79.99, 79.99);

-- ============================================================
-- INSERCIÓN DE CATEGORÍAS
-- ============================================================
INSERT INTO categories (name, description) VALUES
('Electrónica', 'Dispositivos electrónicos y tecnología'),
('Ropa', 'Prendas de vestir y accesorios'),
('Hogar', 'Artículos para el hogar y decoración'),
('Deportes', 'Equipamiento deportivo y ropa deportiva'),
('Libros', 'Libros físicos y digitales'),
('Juguetes', 'Juguetes y juegos');

-- ============================================================
-- INSERCIÓN DE RESEÑAS
-- ============================================================
INSERT INTO reviews (product_id, customer_id, rating, title, comment, is_verified_purchase) VALUES
(1, 1, 5, 'Excelente teléfono', 'La mejor cámara que he probado, la batería dura todo el día.', TRUE),
(2, 2, 4, 'Muy buena laptop', 'Rápida y eficiente, aunque un poco costosa.', TRUE),
(3, 3, 5, 'Camisa de calidad', 'El algodón es suave y la talla perfecta.', TRUE),
(4, 4, 3, 'Buenos jeans pero...', 'La tela es buena pero el talle viene un poco pequeño.', TRUE),
(5, 5, 5, 'Sábanas espectaculares', 'La mejor compra del mes, son muy suaves.', TRUE);

-- ============================================================
-- INSERCIÓN EN EL CARRITO DE COMPRAS
-- ============================================================
INSERT INTO shopping_cart (customer_id, session_id, product_id, quantity) VALUES
(7, 'session_abc123', 1, 1),
(7, 'session_abc123', 3, 2),
(8, 'session_def456', 4, 1),
(8, 'session_def456', 8, 1);

-- ============================================================
-- INSERCIÓN DE LOGS DE ACTIVIDAD
-- ============================================================
INSERT INTO activity_log (customer_id, action_type, action_description, ip_address, user_agent) VALUES
(1, 'login', 'Usuario inició sesión', '192.168.1.100', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
(1, 'purchase', 'Realizó pedido #ORD-2024-0001', '192.168.1.100', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
(2, 'login', 'Usuario inició sesión', '192.168.1.101', 'Mozilla/5.0 (iPhone; CPU iPhone OS)'),
(2, 'purchase', 'Realizó pedido #ORD-2024-0002', '192.168.1.101', 'Mozilla/5.0 (iPhone; CPU iPhone OS)'),
(3, 'login_failed', 'Intento de login fallido', '192.168.1.50', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
(3, 'purchase', 'Realizó pedido #ORD-2024-0003', '192.168.1.102', 'Mozilla/5.0 (Macintosh; Intel Mac OS X)');

-- ============================================================
-- CREACIÓN DE VISTAS ÚTILES
-- ============================================================
CREATE VIEW v_order_summary AS
SELECT 
    o.order_number,
    c.email,
    c.first_name,
    c.last_name,
    o.order_date,
    o.status,
    o.total,
    COUNT(oi.order_item_id) AS item_count
FROM orders o
JOIN customers c ON o.customer_id = c.customer_id
LEFT JOIN order_items oi ON o.order_id = oi.order_id
GROUP BY o.order_id
ORDER BY o.order_date DESC;

CREATE VIEW v_product_stock AS
SELECT 
    p.product_id,
    p.sku,
    p.name,
    p.price,
    p.stock_quantity,
    p.min_stock,
    CASE 
        WHEN p.stock_quantity <= p.min_stock THEN 'CRITICAL'
        WHEN p.stock_quantity <= p.min_stock * 2 THEN 'LOW'
        ELSE 'OK'
    END AS stock_status
FROM products p
ORDER BY stock_quantity ASC;

-- ============================================================
-- PROCEDIMIENTOS ALMACENADOS ÚTILES
-- ============================================================
DELIMITER //

CREATE PROCEDURE sp_get_customer_orders(IN p_customer_id INT)
BEGIN
    SELECT 
        o.order_id,
        o.order_number,
        o.order_date,
        o.status,
        o.total,
        COUNT(oi.order_item_id) AS total_items
    FROM orders o
    LEFT JOIN order_items oi ON o.order_id = oi.order_id
    WHERE o.customer_id = p_customer_id
    GROUP BY o.order_id
    ORDER BY o.order_date DESC;
END //

CREATE PROCEDURE sp_restock_alert()
BEGIN
    SELECT 
        product_id,
        sku,
        name,
        stock_quantity,
        min_stock
    FROM products
    WHERE stock_quantity <= min_stock
    ORDER BY stock_quantity ASC;
END //

DELIMITER ;

-- ============================================================
-- TRIGGER PARA ACTUALIZAR STOCK DESPUÉS DE UN PEDIDO
-- ============================================================
DELIMITER //
CREATE TRIGGER tr_after_order_item
AFTER INSERT ON order_items
FOR EACH ROW
BEGIN
    UPDATE products 
    SET stock_quantity = stock_quantity - NEW.quantity
    WHERE product_id = NEW.product_id;
END //

DELIMITER ;

-- ============================================================
-- TRIGGER PARA REGISTRAR LOG DE ACTIVIDAD EN AUTENTICACIÓN
-- (esto se usa para registrar cuando un atacante intenta login)
-- ============================================================
DELIMITER //
CREATE TRIGGER tr_login_activity
BEFORE INSERT ON activity_log
FOR EACH ROW
BEGIN
    IF NEW.action_type = 'login_failed' THEN
        SET NEW.action_description = CONCAT('Intento fallido desde IP: ', NEW.ip_address);
    END IF;
END //

DELIMITER ;

-- ============================================================
-- INSERT DE UN USUARIO ADMIN (SEÑUELO)
-- Esto simula que existe un panel administrativo
-- ============================================================
CREATE TABLE IF NOT EXISTS admin_users (
    admin_id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE,
    full_name VARCHAR(100),
    role ENUM('admin', 'staff', 'viewer') DEFAULT 'staff',
    is_active BOOLEAN DEFAULT TRUE,
    last_login DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO admin_users (username, password_hash, email, full_name, role) VALUES
('admin', '$2y$10$AdminDefaultHashDummyValueNotReal', 'admin@ecommerce.com', 'Administrador del Sistema', 'admin'),
('staff', '$2y$10$StaffDefaultHashDummyValueNotReal', 'staff@ecommerce.com', 'Staff de Soporte', 'staff');

-- ============================================================
-- ÍNDICES ADICIONALES PARA OPTIMIZACIÓN
-- ============================================================
CREATE INDEX idx_orders_status_date ON orders(status, order_date);
CREATE INDEX idx_products_category_price ON products(category, price);
CREATE INDEX idx_customers_city ON customers(city);
CREATE INDEX idx_reviews_product_rating ON reviews(product_id, rating);

-- ============================================================
-- DATOS ESTADÍSTICOS (por si el atacante los consulta)
-- ============================================================
CREATE TABLE IF NOT EXISTS store_stats (
    stat_id INT PRIMARY KEY AUTO_INCREMENT,
    stat_date DATE NOT NULL,
    total_orders INT DEFAULT 0,
    total_revenue DECIMAL(15,2) DEFAULT 0.00,
    avg_order_value DECIMAL(10,2) DEFAULT 0.00,
    new_customers INT DEFAULT 0,
    UNIQUE KEY uq_stats_date (stat_date)
);

-- Insert algunos datos estadísticos de ejemplo
INSERT INTO store_stats (stat_date, total_orders, total_revenue, avg_order_value, new_customers) VALUES
('2024-01-01', 15, 12500.50, 833.37, 8),
('2024-01-02', 22, 18900.25, 859.10, 12),
('2024-01-03', 18, 15200.75, 844.49, 10),
('2024-01-04', 25, 21050.00, 842.00, 15),
('2024-01-05', 20, 17800.30, 890.02, 11),
('2024-01-06', 28, 23500.60, 839.31, 18),
('2024-01-07', 32, 26800.80, 837.53, 22);

-- ============================================================
-- FIN DEL SCRIPT
-- ============================================================
SELECT 'Base de datos ecommerce creada exitosamente' AS mensaje;