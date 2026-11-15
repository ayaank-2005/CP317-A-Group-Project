// Command scamshield serves the ScamShield site and its JSON API.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"scamshield/internal/server"
)

func main() {
	addr := flag.String("addr", envOr("ADDR", ":8080"), "listen address")
	static := flag.String("static", envOr("STATIC_DIR", "."), "directory holding index.html")
	dbURL := flag.String("db", os.Getenv("DATABASE_URL"), "Postgres connection URL (or DATABASE_URL)")
	secure := flag.Bool("secure-cookies", os.Getenv("SECURE_COOKIES") == "1", "mark session cookies Secure (HTTPS only)")
	flag.Parse()

	if *dbURL == "" {
		log.Fatal("set DATABASE_URL or -db, e.g. postgres://localhost/scamshield")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, *dbURL)
	if err != nil {
		log.Fatalf("connect to database: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("connect to database: %v", err)
	}

	app := server.New(pool, *static)
	app.SecureCookies = *secure

	srv := &http.Server{
		Addr:              *addr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("ScamShield listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
