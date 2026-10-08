CREATE DATABASE IF NOT EXISTS cymercmd;

USE cymercmd;

CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tool VARCHAR(50) NOT NULL,
    target VARCHAR(255) NOT NULL,
    status VARCHAR(30) NOT NULL,
    duration DECIMAL(10,2),
    http_status INT,
    open_ports INT,
    services INT,
    result LONGTEXT,
    error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);