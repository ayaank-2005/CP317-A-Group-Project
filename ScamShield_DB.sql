CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scam_reports (
    id SERIAL PRIMARY KEY,
    user_id INT NULL REFERENCES users (id),
    scam_type_id INT NULL REFERENCES scam_types (scam_type_id),
    description TEXT,
    reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scam_types (
    scam_type_id SERIAL PRIMARY KEY,
    type_name VARCHAR(50) NOT NULL UNIQUE
);

CREATE Table scam_emails (
    id SERIAL PRIMARY KEY,
    scam_report_id INT REFERENCES scam_reports (id),
    email_address VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE table scam_messages (
    id SERIAL PRIMARY KEY,
    scam_report_id INT REFERENCES scam_reports (id),
    message_content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scam_websites (
    id SERIAL PRIMARY KEY,
    scam_report_id INT REFERENCES scam_reports (id),
    website_url VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scam_phone_numbers (
    id SERIAL PRIMARY KEY,
    scam_report_id INT REFERENCES scam_reports (id),
    phone_number VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scam_attachments (
    id SERIAL PRIMARY KEY,
    scam_report_id INT REFERENCES scam_reports (id),
    file_path VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
