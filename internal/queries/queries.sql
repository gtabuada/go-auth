-- name: GetUsers :many
SELECT
    id,
    email
FROM
    users;

-- name: CreateUser :one
INSERT INTO users (
    email, password
) VALUES ($1, $2) RETURNING id, email;

-- name: UpdateUser :one
UPDATE users SET email = $2 WHERE id = $1 RETURNING id, email;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1 RETURNING id;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserById :one
SELECT
    id,
    email
FROM users WHERE id = $1;
