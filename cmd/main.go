package main

import (
	"context"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5"

	store "auth/internal"
	"auth/internal/api"
)

func main() {
	conn, err := pgx.Connect(
		context.Background(),
		os.Getenv("DATABASE_URL"),
	)
	if err != nil {
		panic(err)
	}
	defer conn.Close(context.Background())

	handler := api.NewApi(store.New(conn))

	server := http.Server{
		Addr:    ":3005",
		Handler: handler,
	}

	server.ListenAndServe()
}
