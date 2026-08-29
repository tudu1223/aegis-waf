-- ============================================================
-- 靶场数据库初始化脚本
-- 用途：为 AEGIS 攻防演示提供业务数据
-- 注意：本靶场仅用于本地隔离环境的安全教学演示
-- ============================================================

DROP TABLE IF EXISTS notes;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS notes_backup;

-- 用户表
CREATE TABLE users (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(64)  NOT NULL UNIQUE,
    -- password_md5 为脆弱实现使用（TC-15 演示弱哈希）
    password_md5  VARCHAR(64),
    -- password_hash 为安全实现使用（BCrypt 加盐）
    password_hash VARCHAR(128),
    email       VARCHAR(128),
    role        VARCHAR(16)  NOT NULL DEFAULT 'USER',
    phone       VARCHAR(32),
    created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

-- 笔记表
CREATE TABLE notes (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    owner_id    BIGINT       NOT NULL,
    title       VARCHAR(256) NOT NULL,
    content     CLOB,
    visibility  VARCHAR(16)  NOT NULL DEFAULT 'PRIVATE',
    created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

-- 备份表，用于演示堆叠查询的破坏效果（TC-06）
CREATE TABLE notes_backup (
    id          BIGINT PRIMARY KEY,
    title       VARCHAR(256),
    archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 审计日志表
CREATE TABLE audit_logs (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    actor       VARCHAR(64),
    action      VARCHAR(64),
    detail      VARCHAR(512),
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- 初始数据
-- 说明：password_md5 为明文口令的 MD5（脆弱实现，TC-15 演示用）
--       password_hash 为 BCrypt 哈希（安全实现）
--       演示账户口令统一为 "password123"，管理员为 "admin123"
-- ============================================================

-- admin123 的 MD5 = 0192023a7bbd73250516f069df18b500
INSERT INTO users (username, password_md5, password_hash, email, role, phone) VALUES
('admin', '0192023a7bbd73250516f069df18b500',
 '$2a$12$8Xq3vJZ5N.kZ9mR7wYtOxeH5nQ4pL2sT6vC8bA1dE3fG7hI9jK0lm',
 'admin@aegis.local', 'ADMIN', '13800138000');

-- password123 的 MD5 = 482c811da5d5b4bc6d497ffa98491e38
INSERT INTO users (username, password_md5, password_hash, email, role, phone) VALUES
('alice', '482c811da5d5b4bc6d497ffa98491e38',
 '$2a$12$9Yr4wKa6O.lA0nS8xZuPyfI6oR5qM3tU7wD9cB2eF4gH8iJ0kL1mn',
 'alice@example.com', 'USER', '13900139001'),
('bob', '482c811da5d5b4bc6d497ffa98491e38',
 '$2a$12$0Zs5xLb7P.mB1oT9yAvQzgJ7pS6rN4uV8xE0dC3fG5hI9jK1lM2no',
 'bob@example.com', 'USER', '13900139002'),
('carol', '482c811da5d5b4bc6d497ffa98491e38',
 '$2a$12$1At6yMc8Q.nC2pU0zBwRahK8qT7sO5vW9yF1eD4gH6iJ0kL2mN3op',
 'carol@example.com', 'USER', '13900139003');

INSERT INTO notes (owner_id, title, content, visibility) VALUES
(2, '项目周报', '<p>本周完成了检测引擎的<strong>核心算法</strong>实现。</p>', 'PRIVATE'),
(2, '读书笔记：网络安全', '<p>纵深防御的核心在于<em>不依赖单点防护</em>。</p>', 'PUBLIC'),
(2, 'API 设计规范', '<p>所有接口必须做输入校验与输出编码。</p>', 'PRIVATE'),
(3, 'Bob 的私密笔记', '<p>这是只有 Bob 能看到的内容，用于越权测试。</p>', 'PRIVATE'),
(3, '会议纪要', '<p>讨论了下一阶段的开发计划。</p>', 'PRIVATE'),
(4, 'Carol 的日记', '<p>今天学习了 SQL 注入的原理。</p>', 'PRIVATE'),
(1, '系统公告', '<p>欢迎使用 AEGIS 安全靶场。</p>', 'PUBLIC');

INSERT INTO notes_backup (id, title) VALUES
(1, '项目周报'), (2, '读书笔记：网络安全');
