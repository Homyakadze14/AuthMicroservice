CREATE TABLE IF NOT EXISTS account(
    id INT PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
    username VARCHAR(250) UNIQUE NOT NULL,
    email VARCHAR(250) UNIQUE NOT NULL,
    password VARCHAR(250) NOT NULL,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS token(
    id INT PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
    user_id INT REFERENCES account(id) ON DELETE CASCADE,
    refresh_token VARCHAR(250) UNIQUE NOT NULL,
    expires_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS link(
    id INT PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
    user_id INT UNIQUE REFERENCES account(id) ON DELETE CASCADE,
    link VARCHAR(250) UNIQUE NOT NULL,
    is_activated BOOLEAN NOT NULL DEFAULT FALSE
);