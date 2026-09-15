// Package db provides database connectivity with automatic PostgreSQL/SQLite fallback.
package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/glebarez/go-sqlite"
	_ "github.com/lib/pq"
)

// DB is the global database connection pool.
var DB *sql.DB
var DriverName string = "postgres"

// Connect initializes PostgreSQL or falls back to SQLite.
func Connect() error {
	driver := getEnv("DB_DRIVER", "")

	if driver == "sqlite" {
		return connectSQLite()
	}

	// Try PostgreSQL first
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "5432")
	user := getEnv("DB_USER", "postgres")
	password := getEnv("DB_PASSWORD", "postgres")
	dbname := getEnv("DB_NAME", "securemailscope")
	sslmode := getEnv("DB_SSLMODE", "disable")

	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s connect_timeout=2",
		host, port, user, password, dbname, sslmode,
	)

	var err error
	DB, err = sql.Open("postgres", connStr)
	if err == nil {
		err = DB.Ping()
	}

	if err == nil {
		DriverName = "postgres"
		DB.SetMaxOpenConns(25)
		DB.SetMaxIdleConns(5)
		log.Println("Connected to PostgreSQL database successfully")
		return nil
	}

	log.Printf("PostgreSQL connection failed (%v). Falling back to SQLite database...", err)
	return connectSQLite()
}

func connectSQLite() error {
	dbPath := getEnv("SQLITE_PATH", "securemailscope.db")
	var err error
	DB, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open SQLite database: %w", err)
	}

	if err = DB.Ping(); err != nil {
		return fmt.Errorf("failed to ping SQLite database: %w", err)
	}

	DriverName = "sqlite"
	log.Printf("Connected to SQLite database at %s", dbPath)
	return nil
}

// Migrate creates the required database tables.
func Migrate() error {
	var schema string

	if DriverName == "sqlite" {
		schema = `
		CREATE TABLE IF NOT EXISTS analyses (
			id TEXT PRIMARY KEY,
			pcap_filename TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			overall_score REAL DEFAULT 0,
			overall_severity TEXT DEFAULT 'INFO',
			total_sessions INTEGER DEFAULT 0,
			total_packets INTEGER DEFAULT 0,
			severity_breakdown TEXT DEFAULT '{}',
			tls_version_breakdown TEXT DEFAULT '{}',
			protocol_breakdown TEXT DEFAULT '{}',
			anomaly_count INTEGER DEFAULT 0,
			forward_secrecy_pct REAL DEFAULT 0,
			results_json TEXT DEFAULT '{}',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			completed_at DATETIME
		);

		CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			analysis_id TEXT REFERENCES analyses(id) ON DELETE CASCADE,
			session_key TEXT NOT NULL,
			protocol TEXT,
			src_ip TEXT,
			src_port INTEGER,
			dst_ip TEXT,
			dst_port INTEGER,
			tls_version TEXT,
			negotiated_cipher TEXT,
			has_forward_secrecy BOOLEAN DEFAULT FALSE,
			has_starttls BOOLEAN DEFAULT FALSE,
			is_encrypted BOOLEAN DEFAULT FALSE,
			risk_score REAL DEFAULT 1.0,
			severity TEXT DEFAULT 'INFO',
			anomaly_score REAL DEFAULT 0,
			is_anomalous BOOLEAN DEFAULT FALSE,
			findings TEXT DEFAULT '[]',
			remediations TEXT DEFAULT '[]',
			scores TEXT DEFAULT '{}',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS certificates (
			id TEXT PRIMARY KEY,
			session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
			subject TEXT,
			issuer TEXT,
			serial_number TEXT,
			not_before DATETIME,
			not_after DATETIME,
			public_key_algorithm TEXT,
			public_key_bit_length INTEGER,
			signature_algorithm TEXT,
			is_self_signed BOOLEAN DEFAULT FALSE,
			is_expired BOOLEAN DEFAULT FALSE,
			is_weak_key BOOLEAN DEFAULT FALSE,
			is_weak_signature BOOLEAN DEFAULT FALSE,
			dns_names TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_sessions_analysis ON sessions(analysis_id);
		CREATE INDEX IF NOT EXISTS idx_sessions_severity ON sessions(severity);
		CREATE INDEX IF NOT EXISTS idx_certificates_session ON certificates(session_id);
		CREATE INDEX IF NOT EXISTS idx_analyses_status ON analyses(status);
		`
	} else {
		schema = `
		CREATE TABLE IF NOT EXISTS analyses (
			id UUID PRIMARY KEY,
			pcap_filename TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			overall_score REAL DEFAULT 0,
			overall_severity TEXT DEFAULT 'INFO',
			total_sessions INTEGER DEFAULT 0,
			total_packets INTEGER DEFAULT 0,
			severity_breakdown JSONB DEFAULT '{}',
			tls_version_breakdown JSONB DEFAULT '{}',
			protocol_breakdown JSONB DEFAULT '{}',
			anomaly_count INTEGER DEFAULT 0,
			forward_secrecy_pct REAL DEFAULT 0,
			results_json JSONB DEFAULT '{}',
			created_at TIMESTAMPTZ DEFAULT NOW(),
			completed_at TIMESTAMPTZ
		);

		CREATE TABLE IF NOT EXISTS sessions (
			id UUID PRIMARY KEY,
			analysis_id UUID REFERENCES analyses(id) ON DELETE CASCADE,
			session_key TEXT NOT NULL,
			protocol TEXT,
			src_ip TEXT,
			src_port INTEGER,
			dst_ip TEXT,
			dst_port INTEGER,
			tls_version TEXT,
			negotiated_cipher TEXT,
			has_forward_secrecy BOOLEAN DEFAULT FALSE,
			has_starttls BOOLEAN DEFAULT FALSE,
			is_encrypted BOOLEAN DEFAULT FALSE,
			risk_score REAL DEFAULT 1.0,
			severity TEXT DEFAULT 'INFO',
			anomaly_score REAL DEFAULT 0,
			is_anomalous BOOLEAN DEFAULT FALSE,
			findings JSONB DEFAULT '[]',
			remediations JSONB DEFAULT '[]',
			scores JSONB DEFAULT '{}',
			created_at TIMESTAMPTZ DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS certificates (
			id UUID PRIMARY KEY,
			session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
			subject TEXT,
			issuer TEXT,
			serial_number TEXT,
			not_before TIMESTAMPTZ,
			not_after TIMESTAMPTZ,
			public_key_algorithm TEXT,
			public_key_bit_length INTEGER,
			signature_algorithm TEXT,
			is_self_signed BOOLEAN DEFAULT FALSE,
			is_expired BOOLEAN DEFAULT FALSE,
			is_weak_key BOOLEAN DEFAULT FALSE,
			is_weak_signature BOOLEAN DEFAULT FALSE,
			dns_names TEXT[],
			created_at TIMESTAMPTZ DEFAULT NOW()
		);

		CREATE INDEX IF NOT EXISTS idx_sessions_analysis ON sessions(analysis_id);
		CREATE INDEX IF NOT EXISTS idx_sessions_severity ON sessions(severity);
		CREATE INDEX IF NOT EXISTS idx_certificates_session ON certificates(session_id);
		CREATE INDEX IF NOT EXISTS idx_analyses_status ON analyses(status);
		`
	}

	_, err := DB.Exec(schema)
	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	log.Printf("Database migration completed (%s driver)", DriverName)
	return nil
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}
