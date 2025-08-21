package db

import (
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestInitialize_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		dbPath  string
		setup   func()
		cleanup func()
		wantErr bool
	}{
		{
			name:    "Invalid database path",
			dbPath:  "/invalid/path/to/database.db",
			wantErr: true,
		},
		{
			name:   "Read-only file system",
			dbPath: "/tmp/readonly_test.db",
			setup: func() {
				// Create a database file and make it read-only
				db, _ := sql.Open("sqlite3", "/tmp/readonly_test.db")
				db.Close()
				os.Chmod("/tmp/readonly_test.db", 0444)
			},
			cleanup: func() {
				os.Remove("/tmp/readonly_test.db")
			},
			wantErr: false, // SQLite can open read-only but WAL might fail
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			if tt.cleanup != nil {
				defer tt.cleanup()
			}

			db, err := Initialize(tt.dbPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}
			if db != nil {
				db.Close()
			}
		})
	}
}

func TestRunMigrations_Comprehensive(t *testing.T) {
	db, err := Initialize(":memory:")
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Run migrations
	err = RunMigrations(db)
	if err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Verify all tables exist
	tables := []string{
		"users",
		"messages",
		"broadcast_deliveries",
		"sessions",
		"message_events",
	}

	for _, table := range tables {
		var count int
		query := `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`
		err := db.QueryRow(query, table).Scan(&count)
		if err != nil {
			t.Errorf("Failed to check table %s: %v", table, err)
		}
		if count != 1 {
			t.Errorf("Table %s does not exist", table)
		}
	}

	// Test that we can insert into tables
	t.Run("InsertUser", func(t *testing.T) {
		_, err := db.Exec(`
			INSERT INTO users (user_id, username, public_key, x25519_public_key) 
			VALUES (?, ?, ?, ?)`,
			"test_user", "Test User", "public_key_123", "x25519_key_123")
		if err != nil {
			t.Errorf("Failed to insert user: %v", err)
		}
	})

	t.Run("InsertMessage", func(t *testing.T) {
		_, err := db.Exec(`
			INSERT INTO messages (from_user, to_user, content, status, is_broadcast, signature) 
			VALUES (?, ?, ?, ?, ?, ?)`,
			"test_user", "recipient", "Hello", "pending", false, "signature_123")
		if err != nil {
			t.Errorf("Failed to insert message: %v", err)
		}
	})

	t.Run("InsertSession", func(t *testing.T) {
		_, err := db.Exec(`
			INSERT INTO sessions (session_id, user_id, start_time, end_time, duration) 
			VALUES (?, ?, ?, ?, ?)`,
			"session_123", "test_user", time.Now(), time.Now().Add(time.Hour), 3600)
		if err != nil {
			t.Errorf("Failed to insert session: %v", err)
		}
	})

	t.Run("InsertMessageEvent", func(t *testing.T) {
		_, err := db.Exec(`
			INSERT INTO message_events (session_id, user_id, is_broadcast) 
			VALUES (?, ?, ?)`,
			"session_123", "test_user", false)
		if err != nil {
			t.Errorf("Failed to insert message event: %v", err)
		}
	})

	t.Run("InsertBroadcastDelivery", func(t *testing.T) {
		// First get a message ID
		var messageID int
		err := db.QueryRow("SELECT id FROM messages LIMIT 1").Scan(&messageID)
		if err != nil {
			t.Skipf("No messages to test with: %v", err)
		}

		_, err = db.Exec(`
			INSERT INTO broadcast_deliveries (message_id, user_id) 
			VALUES (?, ?)`,
			messageID, "test_user")
		if err != nil {
			t.Errorf("Failed to insert broadcast delivery: %v", err)
		}
	})
}

func TestRunMigrations_Idempotent(t *testing.T) {
	db, err := Initialize(":memory:")
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Run migrations twice
	err = RunMigrations(db)
	if err != nil {
		t.Fatalf("First migration failed: %v", err)
	}

	err = RunMigrations(db)
	if err != nil {
		t.Fatalf("Second migration failed (should be idempotent): %v", err)
	}

	// Verify tables still exist and are not duplicated
	var count int
	query := `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'`
	err = db.QueryRow(query).Scan(&count)
	if err != nil {
		t.Errorf("Failed to check users table: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected exactly 1 users table, got %d", count)
	}
}

func TestRunMigrations_ForeignKeys(t *testing.T) {
	db, err := Initialize(":memory:")
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Enable foreign key constraints
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	err = RunMigrations(db)
	if err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Try to insert a message with non-existent user (should fail with FK enabled)
	_, err = db.Exec(`
		INSERT INTO messages (from_user, to_user, content, status) 
		VALUES (?, ?, ?, ?)`,
		"non_existent", "also_non_existent", "Hello", "pending")

	// This should fail due to foreign key constraint
	if err == nil {
		t.Error("Expected foreign key constraint error, but insert succeeded")
	}
}

func TestRunMigrations_ColumnTypes(t *testing.T) {
	db, err := Initialize(":memory:")
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	err = RunMigrations(db)
	if err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Check column types using pragma table_info
	tables := map[string][]string{
		"users": {
			"user_id",
			"username",
			"public_key",
			"x25519_public_key",
			"created_at",
		},
		"messages": {
			"id",
			"from_user",
			"to_user",
			"timestamp",
			"content",
			"status",
			"is_broadcast",
			"message_type",
			"signature",
		},
		"sessions": {
			"session_id",
			"user_id",
			"start_time",
			"end_time",
			"duration",
		},
	}

	for table, expectedColumns := range tables {
		rows, err := db.Query("PRAGMA table_info(" + table + ")")
		if err != nil {
			t.Errorf("Failed to get table info for %s: %v", table, err)
			continue
		}
		defer rows.Close()

		columnMap := make(map[string]bool)
		for rows.Next() {
			var cid int
			var name string
			var dataType string
			var notNull int
			var defaultValue sql.NullString
			var pk int

			err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk)
			if err != nil {
				t.Errorf("Failed to scan column info: %v", err)
				continue
			}
			columnMap[name] = true
		}

		// Check that all expected columns exist
		for _, col := range expectedColumns {
			if !columnMap[col] {
				t.Errorf("Table %s missing column %s", table, col)
			}
		}
	}
}

func TestDatabase_Concurrency(t *testing.T) {
	// Create a temporary database file instead of in-memory for concurrency
	tmpFile := "/tmp/test_concurrent.db"
	defer os.Remove(tmpFile)

	db, err := Initialize(tmpFile)
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	err = RunMigrations(db)
	if err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Create test user
	_, err = db.Exec(`INSERT INTO users (user_id, username, public_key) VALUES (?, ?, ?)`,
		"concurrent_user", "Concurrent User", "public_key")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test concurrent inserts
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			_, err := db.Exec(`
				INSERT INTO messages (from_user, to_user, content, status) 
				VALUES (?, ?, ?, ?)`,
				"concurrent_user", "concurrent_user",
				"Message "+string(rune(id)), "pending")
			if err != nil {
				t.Errorf("Concurrent insert %d failed: %v", id, err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all messages were inserted
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count)
	if err != nil {
		t.Errorf("Failed to count messages: %v", err)
	}
	if count != 10 {
		t.Errorf("Expected 10 messages, got %d", count)
	}
}

func TestDatabase_WALMode(t *testing.T) {
	// Create a temporary database file
	tmpFile := "/tmp/test_wal.db"
	defer os.Remove(tmpFile)
	defer os.Remove(tmpFile + "-wal")
	defer os.Remove(tmpFile + "-shm")

	db, err := Initialize(tmpFile)
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Verify WAL mode is enabled
	var mode string
	err = db.QueryRow("PRAGMA journal_mode").Scan(&mode)
	if err != nil {
		t.Errorf("Failed to get journal mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("Expected WAL mode, got %s", mode)
	}

	// Verify WAL file is created after a write
	err = RunMigrations(db)
	if err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Check if WAL file exists
	if _, err := os.Stat(tmpFile + "-wal"); os.IsNotExist(err) {
		t.Error("WAL file was not created")
	}
}

func BenchmarkInitialize_Enhanced(b *testing.B) {
	for i := 0; i < b.N; i++ {
		db, err := Initialize(":memory:")
		if err != nil {
			b.Fatalf("Failed to initialize: %v", err)
		}
		db.Close()
	}
}

func BenchmarkRunMigrations_Enhanced(b *testing.B) {
	for i := 0; i < b.N; i++ {
		db, _ := Initialize(":memory:")
		RunMigrations(db)
		db.Close()
	}
}
