package config

import (
	"os"
	"reflect"
	"testing"
)

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		defaultVal string
		envValue   string
		setEnv     bool
		expected   string
	}{
		{
			name:       "Environment variable exists",
			key:        "TEST_VAR_1",
			defaultVal: "default",
			envValue:   "custom_value",
			setEnv:     true,
			expected:   "custom_value",
		},
		{
			name:       "Environment variable does not exist",
			key:        "TEST_VAR_NONEXISTENT",
			defaultVal: "default_value",
			envValue:   "",
			setEnv:     false,
			expected:   "default_value",
		},
		{
			name:       "Empty environment variable",
			key:        "TEST_VAR_EMPTY",
			defaultVal: "default",
			envValue:   "",
			setEnv:     true,
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up environment
			os.Unsetenv(tt.key)
			defer os.Unsetenv(tt.key)

			if tt.setEnv {
				os.Setenv(tt.key, tt.envValue)
			}

			result := GetEnv(tt.key, tt.defaultVal)
			if result != tt.expected {
				t.Errorf("GetEnv() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestGetEnvFloat(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		defaultVal float64
		envValue   string
		setEnv     bool
		expected   float64
	}{
		{
			name:       "Valid float environment variable",
			key:        "TEST_FLOAT_1",
			defaultVal: 1.0,
			envValue:   "5.5",
			setEnv:     true,
			expected:   5.5,
		},
		{
			name:       "Invalid float environment variable",
			key:        "TEST_FLOAT_2",
			defaultVal: 2.5,
			envValue:   "invalid_float",
			setEnv:     true,
			expected:   2.5, // Should return default on parse error
		},
		{
			name:       "Environment variable does not exist",
			key:        "TEST_FLOAT_NONEXISTENT",
			defaultVal: 3.14,
			envValue:   "",
			setEnv:     false,
			expected:   3.14,
		},
		{
			name:       "Integer as float",
			key:        "TEST_FLOAT_3",
			defaultVal: 1.0,
			envValue:   "42",
			setEnv:     true,
			expected:   42.0,
		},
		{
			name:       "Scientific notation",
			key:        "TEST_FLOAT_4",
			defaultVal: 1.0,
			envValue:   "1.5e2",
			setEnv:     true,
			expected:   150.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up environment
			os.Unsetenv(tt.key)
			defer os.Unsetenv(tt.key)

			if tt.setEnv {
				os.Setenv(tt.key, tt.envValue)
			}

			result := GetEnvFloat(tt.key, tt.defaultVal)
			if result != tt.expected {
				t.Errorf("GetEnvFloat() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		defaultVal int
		envValue   string
		setEnv     bool
		expected   int
	}{
		{
			name:       "Valid integer environment variable",
			key:        "TEST_INT_1",
			defaultVal: 1,
			envValue:   "100",
			setEnv:     true,
			expected:   100,
		},
		{
			name:       "Invalid integer environment variable",
			key:        "TEST_INT_2",
			defaultVal: 50,
			envValue:   "not_an_integer",
			setEnv:     true,
			expected:   50, // Should return default on parse error
		},
		{
			name:       "Environment variable does not exist",
			key:        "TEST_INT_NONEXISTENT",
			defaultVal: 42,
			envValue:   "",
			setEnv:     false,
			expected:   42,
		},
		{
			name:       "Negative integer",
			key:        "TEST_INT_3",
			defaultVal: 1,
			envValue:   "-25",
			setEnv:     true,
			expected:   -25,
		},
		{
			name:       "Zero value",
			key:        "TEST_INT_4",
			defaultVal: 10,
			envValue:   "0",
			setEnv:     true,
			expected:   0,
		},
		{
			name:       "Float as integer (should fail)",
			key:        "TEST_INT_5",
			defaultVal: 15,
			envValue:   "3.14",
			setEnv:     true,
			expected:   15, // Should return default on parse error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up environment
			os.Unsetenv(tt.key)
			defer os.Unsetenv(tt.key)

			if tt.setEnv {
				os.Setenv(tt.key, tt.envValue)
			}

			result := GetEnvInt(tt.key, tt.defaultVal)
			if result != tt.expected {
				t.Errorf("GetEnvInt() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	// Save original environment
	originalEnv := map[string]string{
		"SERVER_ADDR":         os.Getenv("SERVER_ADDR"),
		"MESSAGE_RATE_LIMIT":  os.Getenv("MESSAGE_RATE_LIMIT"),
		"MESSAGE_BURST_LIMIT": os.Getenv("MESSAGE_BURST_LIMIT"),
		"ALLOWED_ORIGINS":     os.Getenv("ALLOWED_ORIGINS"),
		"SECURITY_LOG_FILE":   os.Getenv("SECURITY_LOG_FILE"),
	}

	// Clean up environment variables
	defer func() {
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}()

	tests := []struct {
		name     string
		envVars  map[string]string
		expected *Config
	}{
		{
			name:    "Default configuration",
			envVars: map[string]string{},
			expected: &Config{
				ServerAddr:        ":443",
				MessageRateLimit:  5.0,
				MessageBurstLimit: 10,
				AllowedOrigins:    nil,
				SecurityLogFile:   "",
			},
		},
		{
			name: "Custom configuration",
			envVars: map[string]string{
				"SERVER_ADDR":         ":8080",
				"MESSAGE_RATE_LIMIT":  "10.5",
				"MESSAGE_BURST_LIMIT": "20",
				"ALLOWED_ORIGINS":     "https://example.com,https://app.example.com",
				"SECURITY_LOG_FILE":   "/var/log/security.log",
			},
			expected: &Config{
				ServerAddr:        ":8080",
				MessageRateLimit:  10.5,
				MessageBurstLimit: 20,
				AllowedOrigins:    []string{"https://example.com", "https://app.example.com"},
				SecurityLogFile:   "/var/log/security.log",
			},
		},
		{
			name: "Single allowed origin",
			envVars: map[string]string{
				"ALLOWED_ORIGINS": "https://single.example.com",
			},
			expected: &Config{
				ServerAddr:        ":443",
				MessageRateLimit:  5.0,
				MessageBurstLimit: 10,
				AllowedOrigins:    []string{"https://single.example.com"},
				SecurityLogFile:   "",
			},
		},
		{
			name: "Empty allowed origins",
			envVars: map[string]string{
				"ALLOWED_ORIGINS": "",
			},
			expected: &Config{
				ServerAddr:        ":443",
				MessageRateLimit:  5.0,
				MessageBurstLimit: 10,
				AllowedOrigins:    nil,
			},
		},
		{
			name: "Allowed origins with spaces",
			envVars: map[string]string{
				"ALLOWED_ORIGINS": " https://example1.com , https://example2.com , ",
			},
			expected: &Config{
				ServerAddr:        ":443",
				MessageRateLimit:  5.0,
				MessageBurstLimit: 10,
				AllowedOrigins:    []string{"https://example1.com", "https://example2.com"},
				SecurityLogFile:   "",
			},
		},
		{
			name: "Invalid numeric values should use defaults",
			envVars: map[string]string{
				"MESSAGE_RATE_LIMIT":  "invalid",
				"MESSAGE_BURST_LIMIT": "not_a_number",
			},
			expected: &Config{
				ServerAddr:        ":443",
				MessageRateLimit:  5.0, // Should use default
				MessageBurstLimit: 10,  // Should use default
				AllowedOrigins:    nil,
				SecurityLogFile:   "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all relevant environment variables
			for key := range originalEnv {
				os.Unsetenv(key)
			}

			// Set test environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			config := LoadConfig()

			if config.ServerAddr != tt.expected.ServerAddr {
				t.Errorf("ServerAddr = %v, expected %v", config.ServerAddr, tt.expected.ServerAddr)
			}

			if config.MessageRateLimit != tt.expected.MessageRateLimit {
				t.Errorf("MessageRateLimit = %v, expected %v", config.MessageRateLimit, tt.expected.MessageRateLimit)
			}

			if config.MessageBurstLimit != tt.expected.MessageBurstLimit {
				t.Errorf("MessageBurstLimit = %v, expected %v", config.MessageBurstLimit, tt.expected.MessageBurstLimit)
			}

			if !reflect.DeepEqual(config.AllowedOrigins, tt.expected.AllowedOrigins) {
				t.Errorf("AllowedOrigins = %v, expected %v", config.AllowedOrigins, tt.expected.AllowedOrigins)
			}

			if config.SecurityLogFile != tt.expected.SecurityLogFile {
				t.Errorf("SecurityLogFile = %v, expected %v", config.SecurityLogFile, tt.expected.SecurityLogFile)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	// Test edge cases and validation scenarios
	t.Run("Zero rate limit", func(t *testing.T) {
		os.Setenv("MESSAGE_RATE_LIMIT", "0")
		defer os.Unsetenv("MESSAGE_RATE_LIMIT")

		config := LoadConfig()
		if config.MessageRateLimit != 0 {
			t.Errorf("Expected rate limit 0, got %v", config.MessageRateLimit)
		}
	})

	t.Run("Negative burst limit", func(t *testing.T) {
		os.Setenv("MESSAGE_BURST_LIMIT", "-5")
		defer os.Unsetenv("MESSAGE_BURST_LIMIT")

		config := LoadConfig()
		if config.MessageBurstLimit != -5 {
			t.Errorf("Expected burst limit -5, got %v", config.MessageBurstLimit)
		}
	})

	t.Run("Large values", func(t *testing.T) {
		os.Setenv("MESSAGE_RATE_LIMIT", "1000000.5")
		os.Setenv("MESSAGE_BURST_LIMIT", "999999")
		defer func() {
			os.Unsetenv("MESSAGE_RATE_LIMIT")
			os.Unsetenv("MESSAGE_BURST_LIMIT")
		}()

		config := LoadConfig()
		if config.MessageRateLimit != 1000000.5 {
			t.Errorf("Expected rate limit 1000000.5, got %v", config.MessageRateLimit)
		}
		if config.MessageBurstLimit != 999999 {
			t.Errorf("Expected burst limit 999999, got %v", config.MessageBurstLimit)
		}
	})
}

func TestAllowedOriginsEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Comma only",
			input:    ",",
			expected: nil,
		},
		{
			name:     "Multiple commas",
			input:    ",,,,",
			expected: nil,
		},
		{
			name:     "Spaces only",
			input:    "   ",
			expected: nil,
		},
		{
			name:     "Mixed empty values",
			input:    "https://valid.com, , ,https://another.com, ",
			expected: []string{"https://valid.com", "https://another.com"},
		},
		{
			name:     "URL with port",
			input:    "https://localhost:3000,http://localhost:8080",
			expected: []string{"https://localhost:3000", "http://localhost:8080"},
		},
		{
			name:     "Single comma at end",
			input:    "https://example.com,",
			expected: []string{"https://example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("ALLOWED_ORIGINS", tt.input)
			defer os.Unsetenv("ALLOWED_ORIGINS")

			config := LoadConfig()
			if !reflect.DeepEqual(config.AllowedOrigins, tt.expected) {
				t.Errorf("AllowedOrigins = %v, expected %v", config.AllowedOrigins, tt.expected)
			}
		})
	}
}

// Benchmark tests
func BenchmarkLoadConfig(b *testing.B) {
	os.Setenv("SERVER_ADDR", ":8080")
	os.Setenv("MESSAGE_RATE_LIMIT", "10.0")
	os.Setenv("MESSAGE_BURST_LIMIT", "20")
	os.Setenv("ALLOWED_ORIGINS", "https://example.com,https://test.com")
	defer func() {
		os.Unsetenv("SERVER_ADDR")
		os.Unsetenv("MESSAGE_RATE_LIMIT")
		os.Unsetenv("MESSAGE_BURST_LIMIT")
		os.Unsetenv("ALLOWED_ORIGINS")
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		LoadConfig()
	}
}

func BenchmarkGetEnv(b *testing.B) {
	os.Setenv("BENCH_TEST_VAR", "test_value")
	defer os.Unsetenv("BENCH_TEST_VAR")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetEnv("BENCH_TEST_VAR", "default")
	}
}

func BenchmarkGetEnvFloat(b *testing.B) {
	os.Setenv("BENCH_FLOAT_VAR", "123.456")
	defer os.Unsetenv("BENCH_FLOAT_VAR")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetEnvFloat("BENCH_FLOAT_VAR", 1.0)
	}
}

func BenchmarkGetEnvInt(b *testing.B) {
	os.Setenv("BENCH_INT_VAR", "12345")
	defer os.Unsetenv("BENCH_INT_VAR")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetEnvInt("BENCH_INT_VAR", 1)
	}
}
