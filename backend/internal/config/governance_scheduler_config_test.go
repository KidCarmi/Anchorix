package config

import (
	"strings"
	"testing"
	"time"
)

// B4 PR-1 config tests: defaults, fail-closed validation, and the
// strict partial_requeue_delay > 0 requirement. The governance
// scheduler is disabled by default, so the bounds are only enforced
// when ANCHORIX_GOVERNANCE_SCHEDULER_ENABLED is true.

func TestGovernanceSchedulerDefaults(t *testing.T) {
	baseEnv(t, EnvDevelopment)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GovernanceSchedulerEnabled {
		t.Fatal("governance scheduler must be disabled by default")
	}
	if cfg.GovernanceSchedulerInterval != 5*time.Minute {
		t.Fatalf("default interval = %s, want 5m", cfg.GovernanceSchedulerInterval)
	}
	if cfg.GovernanceSchedulerMaxItemsPerTick != 50 {
		t.Fatalf("default max items = %d, want 50", cfg.GovernanceSchedulerMaxItemsPerTick)
	}
	if cfg.GovernanceSchedulerMaxPagesPerRun != 20 {
		t.Fatalf("default max pages = %d, want 20", cfg.GovernanceSchedulerMaxPagesPerRun)
	}
	if cfg.GovernanceSchedulerMaxRunDuration != 30*time.Second {
		t.Fatalf("default max run duration = %s, want 30s", cfg.GovernanceSchedulerMaxRunDuration)
	}
	if cfg.GovernanceSchedulerPageLimit != 200 {
		t.Fatalf("default page limit = %d, want 200", cfg.GovernanceSchedulerPageLimit)
	}
	if cfg.GovernanceSchedulerPartialRequeueDelay != time.Second {
		t.Fatalf("default partial requeue delay = %s, want 1s", cfg.GovernanceSchedulerPartialRequeueDelay)
	}
	if cfg.GovernanceSchedulerRetryBase != time.Minute {
		t.Fatalf("default retry base = %s, want 1m", cfg.GovernanceSchedulerRetryBase)
	}
	if cfg.GovernanceSchedulerRetryMax != time.Hour {
		t.Fatalf("default retry max = %s, want 1h", cfg.GovernanceSchedulerRetryMax)
	}
}

// enableGovScheduler turns the scheduler on with otherwise-valid
// values so each case can flip exactly one knob to an invalid value.
func enableGovScheduler(t *testing.T) {
	t.Helper()
	t.Setenv("ANCHORIX_GOVERNANCE_SCHEDULER_ENABLED", "true")
	t.Setenv("ANCHORIX_GOVERNANCE_SCHEDULER_INTERVAL", "5m")
	t.Setenv("ANCHORIX_GOVERNANCE_SCHEDULER_MAX_ITEMS_PER_TICK", "50")
	t.Setenv("ANCHORIX_GOVERNANCE_SCHEDULER_MAX_PAGES_PER_RUN", "20")
	t.Setenv("ANCHORIX_GOVERNANCE_SCHEDULER_MAX_RUN_DURATION", "30s")
	t.Setenv("ANCHORIX_GOVERNANCE_SCHEDULER_PAGE_LIMIT", "200")
	t.Setenv("ANCHORIX_GOVERNANCE_SCHEDULER_PARTIAL_REQUEUE_DELAY", "1s")
	t.Setenv("ANCHORIX_GOVERNANCE_SCHEDULER_RETRY_BASE", "1m")
	t.Setenv("ANCHORIX_GOVERNANCE_SCHEDULER_RETRY_MAX", "1h")
}

func TestGovernanceSchedulerEnabledValidConfigLoads(t *testing.T) {
	baseEnv(t, EnvDevelopment)
	enableGovScheduler(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.GovernanceSchedulerEnabled {
		t.Fatal("expected scheduler enabled")
	}
}

// TestGovernanceSchedulerDisabledSkipsValidation proves the bounds are
// NOT enforced when the scheduler is off: a disabled scheduler with a
// sloppy value must still boot (matches the findings-scheduler
// precedent).
func TestGovernanceSchedulerDisabledSkipsValidation(t *testing.T) {
	baseEnv(t, EnvDevelopment)
	t.Setenv("ANCHORIX_GOVERNANCE_SCHEDULER_ENABLED", "false")
	t.Setenv("ANCHORIX_GOVERNANCE_SCHEDULER_PARTIAL_REQUEUE_DELAY", "0s")
	t.Setenv("ANCHORIX_GOVERNANCE_SCHEDULER_INTERVAL", "1s")
	if _, err := Load(); err != nil {
		t.Fatalf("disabled scheduler should ignore invalid bounds, got: %v", err)
	}
}

func TestGovernanceSchedulerInvalidConfigFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		value   string
		wantSub string
	}{
		{"zero partial requeue delay", "ANCHORIX_GOVERNANCE_SCHEDULER_PARTIAL_REQUEUE_DELAY", "0s", "PARTIAL_REQUEUE_DELAY"},
		{"negative partial requeue delay", "ANCHORIX_GOVERNANCE_SCHEDULER_PARTIAL_REQUEUE_DELAY", "-1s", "PARTIAL_REQUEUE_DELAY"},
		{"partial requeue delay >= interval", "ANCHORIX_GOVERNANCE_SCHEDULER_PARTIAL_REQUEUE_DELAY", "5m", "less than"},
		{"interval below minimum", "ANCHORIX_GOVERNANCE_SCHEDULER_INTERVAL", "5s", "INTERVAL"},
		{"zero max items", "ANCHORIX_GOVERNANCE_SCHEDULER_MAX_ITEMS_PER_TICK", "0", "MAX_ITEMS_PER_TICK"},
		{"zero max pages", "ANCHORIX_GOVERNANCE_SCHEDULER_MAX_PAGES_PER_RUN", "0", "MAX_PAGES_PER_RUN"},
		{"max run duration below floor", "ANCHORIX_GOVERNANCE_SCHEDULER_MAX_RUN_DURATION", "100ms", "MAX_RUN_DURATION"},
		{"page limit zero", "ANCHORIX_GOVERNANCE_SCHEDULER_PAGE_LIMIT", "0", "PAGE_LIMIT"},
		{"page limit over max", "ANCHORIX_GOVERNANCE_SCHEDULER_PAGE_LIMIT", "1001", "PAGE_LIMIT"},
		{"retry base zero", "ANCHORIX_GOVERNANCE_SCHEDULER_RETRY_BASE", "0s", "RETRY_BASE"},
		{"retry max below base", "ANCHORIX_GOVERNANCE_SCHEDULER_RETRY_MAX", "10s", "RETRY_MAX"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseEnv(t, EnvDevelopment)
			enableGovScheduler(t)
			t.Setenv(tc.key, tc.value)
			_, err := Load()
			if err == nil {
				t.Fatalf("Load: want fail-closed error for %s=%s", tc.key, tc.value)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q should mention %q", err.Error(), tc.wantSub)
			}
		})
	}
}
