package metrics

import (
	"sync"
	"testing"
	"time"
)

// Additional tests to increase coverage

func TestRecordMessageSent_Comprehensive(t *testing.T) {
	// Clear metrics before test
	clearMetrics()

	sessionID := "msg-test-session"
	userID := "msg-test-user"

	// Start session
	RecordSessionStart(sessionID, userID)

	t.Run("DirectMessage", func(t *testing.T) {
		RecordMessageSent(sessionID, false)

		messageCounts.Lock()
		count, exists := messageCounts.m[sessionID]
		messageCounts.Unlock()

		if !exists {
			t.Error("Message count should exist for session")
		}
		if count.Direct != 1 {
			t.Errorf("Expected 1 direct message, got %d", count.Direct)
		}
		if count.Broadcast != 0 {
			t.Errorf("Expected 0 broadcast messages, got %d", count.Broadcast)
		}
	})

	t.Run("BroadcastMessage", func(t *testing.T) {
		RecordMessageSent(sessionID, true)

		messageCounts.Lock()
		count, exists := messageCounts.m[sessionID]
		messageCounts.Unlock()

		if !exists {
			t.Error("Message count should exist for session")
		}
		if count.Direct != 1 {
			t.Errorf("Expected 1 direct message, got %d", count.Direct)
		}
		if count.Broadcast != 1 {
			t.Errorf("Expected 1 broadcast message, got %d", count.Broadcast)
		}
	})

	t.Run("MultipleMessages", func(t *testing.T) {
		// Add more messages
		for i := 0; i < 5; i++ {
			RecordMessageSent(sessionID, false)
			RecordMessageSent(sessionID, true)
		}

		messageCounts.Lock()
		count, exists := messageCounts.m[sessionID]
		messageCounts.Unlock()

		if !exists {
			t.Error("Message count should exist for session")
		}
		if count.Direct != 6 { // 1 + 5
			t.Errorf("Expected 6 direct messages, got %d", count.Direct)
		}
		if count.Broadcast != 6 { // 1 + 5
			t.Errorf("Expected 6 broadcast messages, got %d", count.Broadcast)
		}
	})
}

func TestRecordMessageSent_NonExistentSession(t *testing.T) {
	// Clear metrics before test
	clearMetrics()

	// Try to record message for non-existent session
	RecordMessageSent("non-existent-session", false)

	messageCounts.Lock()
	count, exists := messageCounts.m["non-existent-session"]
	messageCounts.Unlock()

	if exists {
		t.Error("Message count should not exist for non-existent session")
	}
	if count != nil {
		t.Error("Count should be nil for non-existent session")
	}
}

func TestGetDailyActiveUsers_WithFiltering(t *testing.T) {
	// Clear metrics before test
	clearMetrics()

	now := time.Now()
	yesterday := now.Add(-25 * time.Hour)
	lastWeek := now.Add(-8 * 24 * time.Hour)

	// Add users with different activity times
	dailyActiveUsers.Lock()
	dailyActiveUsers.m["user1"] = now
	dailyActiveUsers.m["user2"] = now.Add(-1 * time.Hour)
	dailyActiveUsers.m["user3"] = yesterday
	dailyActiveUsers.m["user4"] = lastWeek
	dailyActiveUsers.Unlock()

	dau := GetDailyActiveUsers()

	// Should only count users active within last 24 hours
	if dau != 2 {
		t.Errorf("Expected DAU of 2, got %d", dau)
	}
}

func TestGetWeeklyActiveUsers_WithFiltering(t *testing.T) {
	// Clear metrics before test
	clearMetrics()

	now := time.Now()
	sixDaysAgo := now.Add(-6 * 24 * time.Hour)
	eightDaysAgo := now.Add(-8 * 24 * time.Hour)
	twoWeeksAgo := now.Add(-14 * 24 * time.Hour)

	// Add users with different activity times
	weeklyActiveUsers.Lock()
	weeklyActiveUsers.m["user1"] = now
	weeklyActiveUsers.m["user2"] = sixDaysAgo
	weeklyActiveUsers.m["user3"] = eightDaysAgo
	weeklyActiveUsers.m["user4"] = twoWeeksAgo
	weeklyActiveUsers.Unlock()

	wau := GetWeeklyActiveUsers()

	// Should only count users active within last 7 days
	if wau != 2 {
		t.Errorf("Expected WAU of 2, got %d", wau)
	}
}

func TestGetPeakUsageHour_Comprehensive(t *testing.T) {
	// Clear metrics before test
	clearMetrics()

	// Set up peak usage data
	peakUsage.Lock()
	peakUsage.m[9] = 10  // 9 AM
	peakUsage.m[14] = 25 // 2 PM - peak
	peakUsage.m[17] = 20 // 5 PM
	peakUsage.m[20] = 15 // 8 PM
	peakUsage.Unlock()

	hour := GetPeakUsageHour()

	if hour != 14 {
		t.Errorf("Expected peak hour 14, got %d", hour)
	}
}

func TestCalculateChurnRate_Comprehensive(t *testing.T) {
	// Clear metrics before test
	clearMetrics()

	now := time.Now()
	sixDaysAgo := now.Add(-6 * 24 * time.Hour)
	eightDaysAgo := now.Add(-8 * 24 * time.Hour)
	twoWeeksAgo := now.Add(-14 * 24 * time.Hour)

	// Set up last seen data
	lastSeen.Lock()
	lastSeen.m["active_user"] = now
	lastSeen.m["recent_user"] = sixDaysAgo
	lastSeen.m["churned_user1"] = eightDaysAgo
	lastSeen.m["churned_user2"] = twoWeeksAgo
	lastSeen.Unlock()

	churnRate := CalculateChurnRate(7 * 24 * time.Hour)

	// 2 users churned out of 4 total = 0.5 (50% as decimal)
	expectedChurnRate := 0.5

	if churnRate != expectedChurnRate {
		t.Errorf("Expected churn rate %.2f, got %.2f", expectedChurnRate, churnRate)
	}
}

func TestCalculateChurnRate_NoUsers(t *testing.T) {
	// Clear metrics before test
	clearMetrics()

	churnRate := CalculateChurnRate(7 * 24 * time.Hour)

	if churnRate != 0.0 {
		t.Errorf("Expected 0%% churn rate for no users, got %.1f%%", churnRate)
	}
}

func TestConcurrentRecordOperations(t *testing.T) {
	// Clear metrics before test
	clearMetrics()

	var wg sync.WaitGroup
	numGoroutines := 100
	numOperations := 10

	// Test concurrent session starts
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				sessionID := string(rune('a'+id)) + string(rune('0'+j))
				userID := "user" + string(rune(id))
				RecordSessionStart(sessionID, userID)
			}
		}(i)
	}
	wg.Wait()

	// Test concurrent session ends
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				sessionID := string(rune('a'+id)) + string(rune('0'+j))
				userID := "user" + string(rune(id))
				RecordSessionEnd(sessionID, userID)
			}
		}(i)
	}
	wg.Wait()

	// Test concurrent message recording
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			sessionID := "session" + string(rune(id))
			RecordSessionStart(sessionID, "user"+string(rune(id)))
			for j := 0; j < numOperations; j++ {
				RecordMessageSent(sessionID, j%2 == 0)
			}
		}(i)
	}
	wg.Wait()

	// If we get here without deadlock or panic, concurrent ops work
	t.Log("Concurrent operations completed successfully")
}

func BenchmarkRecordMessageSent_Enhanced(b *testing.B) {
	// Setup
	sessionID := "bench-session"
	messageCounts.Lock()
	messageCounts.m[sessionID] = &MessageCount{}
	messageCounts.Unlock()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RecordMessageSent(sessionID, i%2 == 0)
	}
}
