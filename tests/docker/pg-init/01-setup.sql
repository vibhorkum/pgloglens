-- Initialize test database with tables for log generation scenarios

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Orders table
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    status VARCHAR(50) DEFAULT 'pending',
    total DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Products table
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    price DECIMAL(10,2),
    category_id INTEGER,
    active BOOLEAN DEFAULT true
);

-- Large table for temp file generation
CREATE TABLE large_data (
    id SERIAL PRIMARY KEY,
    data TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table for lock testing
CREATE TABLE inventory (
    id SERIAL PRIMARY KEY,
    product_id INTEGER,
    quantity INTEGER DEFAULT 0,
    warehouse_id INTEGER
);

-- Insert sample data
INSERT INTO users (email, name)
SELECT
    'user' || i || '@example.com',
    'User ' || i
FROM generate_series(1, 1000) AS i;

INSERT INTO products (name, price, category_id, active)
SELECT
    'Product ' || i,
    (random() * 100)::DECIMAL(10,2),
    (i % 10) + 1,
    true
FROM generate_series(1, 500) AS i;

INSERT INTO orders (user_id, status, total)
SELECT
    (random() * 999 + 1)::INTEGER,
    CASE (i % 4)
        WHEN 0 THEN 'pending'
        WHEN 1 THEN 'shipped'
        WHEN 2 THEN 'delivered'
        ELSE 'cancelled'
    END,
    (random() * 500)::DECIMAL(10,2)
FROM generate_series(1, 5000) AS i;

INSERT INTO inventory (product_id, quantity, warehouse_id)
SELECT
    (random() * 499 + 1)::INTEGER,
    (random() * 100)::INTEGER,
    (i % 5) + 1
FROM generate_series(1, 1000) AS i;

-- Insert large data for temp file scenarios
INSERT INTO large_data (data)
SELECT repeat('x', 10000)
FROM generate_series(1, 500) AS i;

-- Create indexes
CREATE INDEX idx_orders_user_id ON orders(user_id);
CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_products_category ON products(category_id);
CREATE INDEX idx_inventory_product ON inventory(product_id);

-- Analyze tables
ANALYZE;
