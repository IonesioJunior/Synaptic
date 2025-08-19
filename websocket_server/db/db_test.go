package db

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestInitialize(t *testing.T) {
	tests := []struct {
		name    string
		dbPath  string
		wantErr bool
	}{
		{
			name:    "Valid in-memory database",
			dbPath:  ":memory:",
			wantErr: false,
		},
		{
			name:    "Valid file database",
			dbPath:  "test.db",
			wantErr: false,
		},
		{
			name:    "Empty path should work (creates file)",
			dbPath:  "",
			wantErr: false, // Empty path creates default database
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up any existing test database
			if tt.dbPath != ":memory:" && tt.dbPath != "" {
				os.Remove(tt.dbPath)
				defer os.Remove(tt.dbPath)
			}

			db, err := Initialize(tt.dbPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("Initialize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				defer db.Close()

				// Verify WAL mode is enabled (except for memory databases and empty path)
				if tt.dbPath != ":memory:" && tt.dbPath != "" {
					var journalMode string
					err = db.QueryRow("PRAGMA journal_mode").Scan(&journalMode)
					if err != nil {
						t.Errorf("Failed to query journal mode: %v", err)
					}
					if journalMode != "wal" {
						t.Errorf("Expected WAL mode, got %s", journalMode)
					}
				}

				// Verify database connection is functional
				err = db.Ping()
				if err != nil {
					t.Errorf("Database ping failed: %v", err)
				}
			}
		})
	}
}

func TestRunMigrations(t *testing.T) {
	db, err := Initialize(":memory:")
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Test successful migration
	err = RunMigrations(db)
	if err != nil {
		t.Errorf("RunMigrations() failed: %v", err)
	}

	// Verify all tables were created
	expectedTables := []string{
		"users",
		"messages", 
		"broadcast_deliveries",
		"sessions",
		"message_events",
	}

	for _, table := range expectedTables {
		var name string
		query := "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
		err = db.QueryRow(query, table).Scan(&name)
		if err != nil {
			t.Errorf("Table %s was not created: %v", table, err)
		}
		if name != table {
			t.Errorf("Expected table %s, got %s", table, name)
		}
	}

	// Test running migrations twice (should not fail)
	err = RunMigrations(db)
	if err != nil {
		t.Errorf("Running migrations twice should not fail: %v", err)
	}
}

func TestMigrationsTableStructure(t *testing.T) {
	db, err := Initialize(":memory:")
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	err = RunMigrations(db)
	if err != nil {
		t.Fatalf("RunMigrations() failed: %v", err)
	}

	// Test users table structure
	t.Run("UsersTable", func(t *testing.T) {
		expectedColumns := map[string]bool{
			"user_id":           false,
			"username":          false,
			"public_key":        false,
			"x25519_public_key": false,
			"created_at":        false,
		}

		rows, err := db.Query("PRAGMA table_info(users)")
		if err != nil {
			t.Fatalf("Failed to get users table info: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var cid int
			var name, dataType string
			var notNull, pk int
			var defaultValue sql.NullString
			
			err = rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk)
			if err != nil {
				t.Fatalf("Failed to scan column info: %v", err)
			}

			if _, exists := expectedColumns[name]; exists {
				expectedColumns[name] = true
			}
		}

		for col, found := range expectedColumns {
			if !found {
				t.Errorf("Expected column %s not found in users table", col)
			}
		}
	})

	// Test messages table structure
	t.Run("MessagesTable", func(t *testing.T) {
		expectedColumns := []string{
			"id", "from_user", "to_user", "timestamp", "content", 
			"status", "is_broadcast", "message_type", "signature",
		}

		for _, col := range expectedColumns {
			var count int
			query := "SELECT COUNT(*) FROM pragma_table_info('messages') WHERE name = ?"
			err = db.QueryRow(query, col).Scan(&count)
			if err != nil {
				t.Fatalf("Failed to check column %s: %v", col, err)
			}
			if count != 1 {
				t.Errorf("Column %s not found in messages table", col)
			}
		}
	})

	// Test foreign key constraints
	t.Run("ForeignKeyConstraints", func(t *testing.T) {
		// Check if foreign keys are properly defined
		rows, err := db.Query("PRAGMA foreign_key_list(messages)")
		if err != nil {
			t.Fatalf("Failed to get foreign key info: %v", err)
		}
		defer rows.Close()

		fkCount := 0
		for rows.Next() {
			fkCount++
		}

		// messages table should have 2 foreign keys (from_user and to_user)
		if fkCount < 2 {
			t.Errorf("Expected at least 2 foreign keys in messages table, got %d", fkCount)
		}
	})
}

func TestMigrationsWithInvalidDatabase(t *testing.T) {
	// Create a read-only database connection to test error handling
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Close the database to make it invalid
	db.Close()

	err = RunMigrations(db)
	if err == nil {
		t.Error("Expected error when running migrations on closed database")
	}
}

func TestDatabaseConcurrency(t *testing.T) {
	db, err := Initialize(":memory:")
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	err = RunMigrations(db)
	if err != nil {
		t.Fatalf("RunMigrations() failed: %v", err)
	}

	// Test concurrent database operations
	const numGoroutines = 10
	const numOperations = 100

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			for j := 0; j < numOperations; j++ {
				// Perform a simple query to test concurrency
				var count int
				err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").Scan(&count)
				if err != nil {
					t.Errorf("Concurrent query failed: %v", err)
					return
				}
				// Just verify query works - table count may vary during concurrent setup
				if count < 0 {
					t.Errorf("Invalid table count: %d", count)
					return
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestX25519ColumnMigration(t *testing.T) {
	// Test the ALTER TABLE migration for x25519_public_key column
	db, err := Initialize(":memory:")
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Create users table without x25519_public_key column first
	createUsersTable := `
	CREATE TABLE users (
		user_id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		public_key TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.Exec(createUsersTable)
	if err != nil {
		t.Fatalf("Failed to create initial users table: %v", err)
	}

	// Run migrations which should add the x25519_public_key column
	err = RunMigrations(db)
	if err != nil {
		t.Fatalf("RunMigrations() failed: %v", err)
	}

	// Verify the x25519_public_key column exists
	var count int
	query := "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'x25519_public_key'"
	err = db.QueryRow(query).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to check x25519_public_key column: %v", err)
	}
	if count != 1 {
		t.Errorf("x25519_public_key column should exist after migration")
	}
}

func BenchmarkInitialize(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db, err := Initialize(":memory:")
		if err != nil {
			b.Fatalf("Initialize failed: %v", err)
		}
		db.Close()
	}
}

func BenchmarkRunMigrations(b *testing.B) {
	db, err := Initialize(":memory:")
	if err != nil {
		b.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Drop all tables first
		tables := []string{"users", "messages", "broadcast_deliveries", "sessions", "message_events"}
		for _, table := range tables {
			db.Exec("DROP TABLE IF EXISTS " + table)
		}

		err := RunMigrations(db)
		if err != nil {
			b.Fatalf("RunMigrations failed: %v", err)
		}
	}
}