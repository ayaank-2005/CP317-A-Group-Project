// internal/store/store.go
// Package talks to Postgres.
package store

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"scamshield/internal/reports"
)

type Store struct {
	pool *pgxpool.Pool
}

// Opens a small connection pool using DATABASE_URL environment variable.
func New(ctx context.Context) (*Store, error) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return nil, errors.New("DATABASE_URL is not set")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("DATABASE_URL could not be parsed") // not wrapped: the text could contain the password
	}

	cfg.MaxConns = 4
	cfg.MaxConnIdleTime = 30 * time.Second
	// Pooled connection strings (Neon, Supabase, PgBouncer)
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

// SearchReports runs the count and the page query built by reports.BuildSearch. It returns a Page with the results and total count.
func (s *Store) SearchReports(ctx context.Context, p reports.Params) (reports.Page, error) {
	q := reports.BuildSearch(p)
	page := reports.Page{Results: []reports.Report{}, Page: p.Page, PageSize: p.PageSize}

	if err := s.pool.QueryRow(ctx, q.CountSQL, q.CountArgs...).Scan(&page.Total); err != nil {
		return page, err
	}
	if page.Total == 0 {
		return page, nil
	}

	rows, err := s.pool.Query(ctx, q.SQL, q.Args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()

	for rows.Next() {
		r, err := reports.ScanReport(rows.Scan)
		if err != nil {
			return page, err
		}
		page.Results = append(page.Results, r)
	}
	return page, rows.Err()
}

// ListCategories returns the scam types for the filter drop-down.
func (s *Store) ListCategories(ctx context.Context) ([]reports.Category, error) {
	rows, err := s.pool.Query(ctx, `SELECT code, name FROM scam_categories ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cats := []reports.Category{}
	for rows.Next() {
		var c reports.Category
		if err := rows.Scan(&c.Code, &c.Name); err != nil {
			return nil, err
		}
		cats = append(cats, c)
	}
	return cats, rows.Err()
}
