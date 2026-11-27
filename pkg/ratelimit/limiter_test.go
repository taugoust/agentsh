package ratelimit

import (
	"testing"
	"time"
)

func TestNewLimiter(t *testing.T) {
	l := NewLimiter(10, 50)

	if l == nil {
		t.Fatal("NewLimiter returned nil")
	}
	if l.Rate() != 10 {
		t.Errorf("Rate() = %v, want 10", l.Rate())
	}
	if l.Burst() != 50 {
		t.Errorf("Burst() = %v, want 50", l.Burst())
	}
}

func TestLimiter_Allow(t *testing.T) {
	l := NewLimiter(10, 5)

	// Should allow burst
	for i := 0; i < 5; i++ {
		if !l.Allow() {
			t.Errorf("Allow() returned false on attempt %d within burst", i+1)
		}
	}

	// Should deny after burst exhausted
	if l.Allow() {
		t.Error("Allow() should return false after burst exhausted")
	}
}

func TestLimiter_AllowN(t *testing.T) {
	l := NewLimiter(100, 10)

	// Should allow 5 tokens
	if !l.AllowN(5) {
		t.Error("AllowN(5) should return true")
	}

	// Should allow another 5
	if !l.AllowN(5) {
		t.Error("AllowN(5) should return true again")
	}

	// Should deny 5 more (burst exhausted)
	if l.AllowN(5) {
		t.Error("AllowN(5) should return false after burst exhausted")
	}
}

func TestLimiter_TokensReplenish(t *testing.T) {
	l := NewLimiter(100, 10) // 100 tokens/second

	// Exhaust burst
	l.AllowN(10)

	// Should be empty
	if l.Tokens() > 0.5 {
		t.Errorf("Tokens() = %v, expected near 0", l.Tokens())
	}

	// Wait for replenishment
	time.Sleep(50 * time.Millisecond)

	// Should have ~5 tokens (100/sec * 0.05s = 5)
	tokens := l.Tokens()
	if tokens < 3 || tokens > 7 {
		t.Errorf("Tokens() = %v, expected ~5", tokens)
	}
}

func TestLimiter_SetRate(t *testing.T) {
	l := NewLimiter(10, 5)

	l.SetRate(100)
	if l.Rate() != 100 {
		t.Errorf("Rate() = %v, want 100", l.Rate())
	}
}

func TestLimiter_SetBurst(t *testing.T) {
	l := NewLimiter(10, 50)

	l.SetBurst(10)
	if l.Burst() != 10 {
		t.Errorf("Burst() = %v, want 10", l.Burst())
	}

	// Tokens should be capped at new burst
	if l.Tokens() > 10 {
		t.Errorf("Tokens() = %v, should be capped at 10", l.Tokens())
	}
}

func TestLimiter_Wait(t *testing.T) {
	l := NewLimiter(1000, 1) // Fast for testing

	// First should be immediate
	d := l.Wait()
	if d > time.Millisecond {
		t.Errorf("First Wait() = %v, expected immediate", d)
	}

	// Second should require waiting
	start := time.Now()
	l.Wait()
	elapsed := time.Since(start)

	// Should have waited approximately 1ms (1/1000 second)
	if elapsed < 500*time.Microsecond {
		t.Errorf("Second Wait() elapsed = %v, expected some delay", elapsed)
	}
}
