CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE complaints (
    id SERIAL PRIMARY KEY,
    situation TEXT,
    solution TEXT,
    embedding VECTOR(768)
);

CREATE TABLE chat_history (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(50),
    message TEXT,
    response TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name TEXT,
    description TEXT,
    category TEXT,
    price DECIMAL,
    embedding VECTOR(768)
);
