CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(20) DEFAULT 'user',
  is_deleted BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  admin_id INT,
  action VARCHAR(50),
  target_user_id INT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 👑 DEFAULT ADMIN USER
INSERT INTO users (username, password, role)
VALUES (
  'admin',
  '$2b$10$6xl4loT5lmTY//WC/t5Yk.4yZ8MObGd5TaN4NLm6YfjScIVFt03Ke',
  'admin'
);
