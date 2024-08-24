-- +goose Up
CREATE TABLE IF NOT EXISTS users (
    "id" UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    "email" VARCHAR(255) UNIQUE NOT NULL,
    "password" VARCHAR(255) NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS users;
