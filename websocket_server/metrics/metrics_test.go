package metrics

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRecordSessionStart(t *testing.T) {
	// Clear metrics before test
	clearMetrics()

	sessionID := "test-session-1"
	userID := "test-user-1"

	RecordSessionStart(sessionID, userID)

	// Verify session start was recorded
	sessionStarts.Lock()
	startTime, exists := sessionStarts.m[sessionID]
	sessionStarts.Unlock()

	if !exists {
		t.Error("Session start should be recorded")
	}

	if time.Since(startTime) > 1*time.Second {
		t.Error("Session start time should be recent")
	}

	// Verify user was marked as active
	dailyActiveUsers.Lock()
	_, dailyExists := dailyActiveUsers.m[userID]
	dailyActiveUsers.Unlock()

	weeklyActiveUsers.Lock()
	_, weeklyExists := weeklyActiveUsers.m[userID]
	weeklyActiveUsers.Unlock()

	if !dailyExists {
		t.Error("User should be marked as daily active")
	}

	if !weeklyExists {
		t.Error("User should be marked as weekly active")
	}

	// Verify message count was initialized
	messageCounts.Lock()
	count, countExists := messageCounts.m[sessionID]
	messageCounts.Unlock()

	if !countExists {
		t.Error("Message count should be initialized")
	}

	if count.Direct != 0 || count.Broadcast != 0 {
		t.Error("Message counts should start at zero")
	}

	// Verify peak usage was recorded
	hour := time.Now().Hour()
	peakUsage.Lock()
	usageCount := peakUsage.m[hour]
	peakUsage.Unlock()

	if usageCount < 1 {
		t.Error("Peak usage should be recorded for current hour")
	}
}

func TestRecordSessionEnd(t *testing.T) {
	clearMetrics()

	sessionID := "test-session-end"
	userID := "test-user-end"

	// Start a session first
	RecordSessionStart(sessionID, userID)

	// Wait a bit to ensure measurable duration
	time.Sleep(10 * time.Millisecond)

	// End the session
	RecordSessionEnd(sessionID, userID)

	// Verify session was removed from active sessions
	sessionStarts.Lock()
	_, exists := sessionStarts.m[sessionID]
	sessionStarts.Unlock()

	if exists {
		t.Error("Session should be removed after ending")
	}

	// Verify duration was recorded
	sessionDurations.Lock()
	durations, durationExists := sessionDurations.m[userID]
	sessionDurations.Unlock()

	if !durationExists {
		t.Error("Session duration should be recorded")
	}

	if len(durations) != 1 {
		t.Errorf("Expected 1 duration, got %d", len(durations))
	}

	if durations[0] < 10*time.Millisecond {
		t.Error("Duration should be at least 10ms")
	}

	// Verify last seen was updated
	lastSeen.Lock()
	lastSeenTime, lastSeenExists := lastSeen.m[userID]
	lastSeen.Unlock()

	if !lastSeenExists {
		t.Error("Last seen should be recorded")
	}

	if time.Since(lastSeenTime) > 1*time.Second {
		t.Error("Last seen should be recent")
	}
}

func TestRecordSessionEndNonExistentSession(t *testing.T) {
	clearMetrics()

	userID := "test-user-nonexistent"
	sessionID := "nonexistent-session"

	// Try to end a session that was never started
	RecordSessionEnd(sessionID, userID)

	// Should still update last seen
	lastSeen.Lock()
	_, lastSeenExists := lastSeen.m[userID]
	lastSeen.Unlock()

	if !lastSeenExists {
		t.Error("Last seen should be updated even for non-existent sessions")
	}

	// Should not create any session durations
	sessionDurations.Lock()
	durations, exists := sessionDurations.m[userID]
	sessionDurations.Unlock()

	if exists && len(durations) > 0 {
		t.Error("Should not create durations for non-existent sessions")
	}
}

func TestRecordMessageSent(t *testing.T) {
	clearMetrics()

	sessionID := "test-session-message"
	userID := "test-user-message"

	// Start session first
	RecordSessionStart(sessionID, userID)

	// Record direct message
	RecordMessageSent(sessionID, false)

	// Record broadcast message
	RecordMessageSent(sessionID, true)

	// Record another direct message
	RecordMessageSent(sessionID, false)

	// Verify counts
	messageCounts.Lock()
	count, exists := messageCounts.m[sessionID]
	messageCounts.Unlock()

	if !exists {
		t.Error("Message count should exist")
	}

	if count.Direct != 2 {
		t.Errorf("Expected 2 direct messages, got %d", count.Direct)
	}

	if count.Broadcast != 1 {
		t.Errorf("Expected 1 broadcast message, got %d", count.Broadcast)
	}
}

func TestRecordMessageSentNonExistentSession(t *testing.T) {
	clearMetrics()

	// Try to record message for non-existent session
	RecordMessageSent("nonexistent-session", false)

	// Should not crash, but also should not create any counts
	messageCounts.Lock()
	count, exists := messageCounts.m["nonexistent-session"]
	messageCounts.Unlock()

	if exists {
		t.Error("Should not create count for non-existent session")
	}

	if count != nil {
		t.Error("Count should be nil for non-existent session")
	}
}

func TestGetDailyActiveUsers(t *testing.T) {
	clearMetrics()

	// Record some users as active today
	now := time.Now()
	today := now.Truncate(24 * time.Hour)

	dailyActiveUsers.Lock()
	dailyActiveUsers.m["user1"] = today.Add(1 * time.Hour)   // Active today
	dailyActiveUsers.m["user2"] = today.Add(2 * time.Hour)   // Active today
	dailyActiveUsers.m["user3"] = today.Add(-25 * time.Hour) // Active yesterday (should not count)
	dailyActiveUsers.Unlock()

	count := GetDailyActiveUsers()

	if count != 2 {
		t.Errorf("Expected 2 daily active users, got %d", count)
	}
}

func TestGetWeeklyActiveUsers(t *testing.T) {
	clearMetrics()

	// Record some users as active in the last week
	now := time.Now()
	weekAgo := now.AddDate(0, 0, -7)

	weeklyActiveUsers.Lock()
	weeklyActiveUsers.m["user1"] = now.AddDate(0, 0, -1)  // 1 day ago (should count)
	weeklyActiveUsers.m["user2"] = now.AddDate(0, 0, -6)  // 6 days ago (should count)
	weeklyActiveUsers.m["user3"] = now.AddDate(0, 0, -8)  // 8 days ago (should not count)
	weeklyActiveUsers.m["user4"] = weekAgo.Add(1 * time.Hour) // Just within week (should count)
	weeklyActiveUsers.Unlock()

	count := GetWeeklyActiveUsers()

	if count != 3 {
		t.Errorf("Expected 3 weekly active users, got %d", count)
	}
}

func TestGetPeakUsageHour(t *testing.T) {
	clearMetrics()

	// Set up peak usage data
	peakUsage.Lock()
	peakUsage.m[9] = 5   // 9 AM - 5 sessions
	peakUsage.m[14] = 15 // 2 PM - 15 sessions (peak)
	peakUsage.m[18] = 8  // 6 PM - 8 sessions
	peakUsage.Unlock()

	peak := GetPeakUsageHour()

	if peak != 14 {
		t.Errorf("Expected peak hour 14, got %d", peak)
	}
}

func TestGetPeakUsageHourEmpty(t *testing.T) {
	clearMetrics()

	peak := GetPeakUsageHour()

	if peak != 0 {
		t.Errorf("Expected peak hour 0 for empty data, got %d", peak)
	}
}

func TestCalculateChurnRate(t *testing.T) {
	clearMetrics()

	now := time.Now()
	period := 7 * 24 * time.Hour // 7 days

	// Set up last seen data
	lastSeen.Lock()
	lastSeen.m["user1"] = now.Add(-1 * time.Hour)  // Active recently (not churned)
	lastSeen.m["user2"] = now.Add(-2 * time.Hour)  // Active recently (not churned)
	lastSeen.m["user3"] = now.Add(-8 * 24 * time.Hour) // Churned (8 days ago)
	lastSeen.m["user4"] = now.Add(-10 * 24 * time.Hour) // Churned (10 days ago)
	lastSeen.Unlock()

	churnRate := CalculateChurnRate(period)

	expectedRate := 2.0 / 4.0 // 2 churned out of 4 total
	if churnRate != expectedRate {
		t.Errorf("Expected churn rate %f, got %f", expectedRate, churnRate)
	}
}

func TestCalculateChurnRateNoUsers(t *testing.T) {
	clearMetrics()

	period := 7 * 24 * time.Hour
	churnRate := CalculateChurnRate(period)

	if churnRate != 0.0 {
		t.Errorf("Expected churn rate 0.0 for no users, got %f", churnRate)
	}
}

func TestCalculateChurnRateAllActive(t *testing.T) {
	clearMetrics()

	now := time.Now()
	period := 7 * 24 * time.Hour

	// All users active recently
	lastSeen.Lock()
	lastSeen.m["user1"] = now.Add(-1 * time.Hour)
	lastSeen.m["user2"] = now.Add(-2 * time.Hour)
	lastSeen.m["user3"] = now.Add(-3 * time.Hour)
	lastSeen.Unlock()

	churnRate := CalculateChurnRate(period)

	if churnRate != 0.0 {
		t.Errorf("Expected churn rate 0.0 when all users active, got %f", churnRate)
	}
}

func TestMetricsConcurrency(t *testing.T) {
	clearMetrics()

	const numGoroutines = 50
	const numOperations = 100

	var wg sync.WaitGroup

	// Test concurrent session starts
	t.Run("ConcurrentSessionStarts", func(t *testing.T) {
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					sessionID := fmt.Sprintf("session-%d-%d", id, j)
					userID := fmt.Sprintf("user-%d", id)
					RecordSessionStart(sessionID, userID)
				}
			}(i)
		}
		wg.Wait()

		// Verify some sessions were recorded
		sessionStarts.Lock()
		count := len(sessionStarts.m)
		sessionStarts.Unlock()

		if count != numGoroutines*numOperations {
			t.Errorf("Expected %d sessions, got %d", numGoroutines*numOperations, count)
		}
	})

	// Test concurrent message recordings
	t.Run("ConcurrentMessageRecording", func(t *testing.T) {
		clearMetrics()

		// Create some sessions first
		for i := 0; i < 10; i++ {
			sessionID := fmt.Sprintf("msg-session-%d", i)
			userID := fmt.Sprintf("msg-user-%d", i)
			RecordSessionStart(sessionID, userID)
		}

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					sessionID := fmt.Sprintf("msg-session-%d", id%10)
					RecordMessageSent(sessionID, j%2 == 0) // Alternate between direct and broadcast
				}
			}(i)
		}
		wg.Wait()

		// Verify messages were recorded
		messageCounts.Lock()
		totalMessages := 0
		for _, count := range messageCounts.m {
			totalMessages += count.Direct + count.Broadcast
		}
		messageCounts.Unlock()

		if totalMessages != numGoroutines*numOperations {
			t.Errorf("Expected %d total messages, got %d", numGoroutines*numOperations, totalMessages)
		}
	})
}

func TestMetricsDataRaces(t *testing.T) {
	clearMetrics()

	// This test is designed to catch data races when run with -race flag
	const numGoroutines = 10

	var wg sync.WaitGroup

	// Mix different operations concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(4) // 4 operations per goroutine

		go func(id int) {
			defer wg.Done()
			sessionID := fmt.Sprintf("race-session-%d", id)
			userID := fmt.Sprintf("race-user-%d", id)
			RecordSessionStart(sessionID, userID)
		}(i)

		go func(id int) {
			defer wg.Done()
			sessionID := fmt.Sprintf("race-session-%d", id)
			RecordMessageSent(sessionID, true)
		}(i)

		go func(id int) {
			defer wg.Done()
			GetDailyActiveUsers()
			GetWeeklyActiveUsers()
			GetPeakUsageHour()
		}(i)

		go func(id int) {
			defer wg.Done()
			sessionID := fmt.Sprintf("race-session-%d", id)
			userID := fmt.Sprintf("race-user-%d", id)
			RecordSessionEnd(sessionID, userID)
		}(i)
	}

	wg.Wait()
}

// Benchmark tests
func BenchmarkRecordSessionStart(b *testing.B) {
	clearMetrics()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sessionID := fmt.Sprintf("bench-session-%d", i)
		userID := fmt.Sprintf("bench-user-%d", i%1000) // Reuse user IDs
		RecordSessionStart(sessionID, userID)
	}
}

func BenchmarkRecordMessageSent(b *testing.B) {
	clearMetrics()

	// Pre-create some sessions
	for i := 0; i < 1000; i++ {
		sessionID := fmt.Sprintf("bench-session-%d", i)
		userID := fmt.Sprintf("bench-user-%d", i)
		RecordSessionStart(sessionID, userID)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sessionID := fmt.Sprintf("bench-session-%d", i%1000)
		RecordMessageSent(sessionID, i%2 == 0)
	}
}

func BenchmarkGetDailyActiveUsers(b *testing.B) {
	clearMetrics()

	// Pre-populate with data
	now := time.Now()
	dailyActiveUsers.Lock()
	for i := 0; i < 10000; i++ {
		userID := fmt.Sprintf("bench-user-%d", i)
		dailyActiveUsers.m[userID] = now.Add(-time.Duration(i%48) * time.Hour)
	}
	dailyActiveUsers.Unlock()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetDailyActiveUsers()
	}
}

func BenchmarkCalculateChurnRate(b *testing.B) {
	clearMetrics()

	// Pre-populate with data
	now := time.Now()
	lastSeen.Lock()
	for i := 0; i < 10000; i++ {
		userID := fmt.Sprintf("bench-user-%d", i)
		lastSeen.m[userID] = now.Add(-time.Duration(i%240) * time.Hour) // Spread over 10 days
	}
	lastSeen.Unlock()

	period := 7 * 24 * time.Hour

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CalculateChurnRate(period)
	}
}

// Helper function to clear all metrics for testing
func clearMetrics() {
	sessionStarts.Lock()
	sessionStarts.m = make(map[string]time.Time)
	sessionStarts.Unlock()

	dailyActiveUsers.Lock()
	dailyActiveUsers.m = make(map[string]time.Time)
	dailyActiveUsers.Unlock()

	weeklyActiveUsers.Lock()
	weeklyActiveUsers.m = make(map[string]time.Time)
	weeklyActiveUsers.Unlock()

	messageCounts.Lock()
	messageCounts.m = make(map[string]*MessageCount)
	messageCounts.Unlock()

	peakUsage.Lock()
	peakUsage.m = make(map[int]int)
	peakUsage.Unlock()

	lastSeen.Lock()
	lastSeen.m = make(map[string]time.Time)
	lastSeen.Unlock()

	sessionDurations.Lock()
	sessionDurations.m = make(map[string][]time.Duration)
	sessionDurations.Unlock()
}

