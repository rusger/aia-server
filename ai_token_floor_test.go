package main

import "testing"

func TestMaxTokensFloorOffChangesNothing(t *testing.T) {
	floors := loadMaxTokensFloor("")
	for _, callType := range []string{"chatgpt", "claim_audit", "barnum_judge"} {
		for _, n := range []int{0, 900, 2200, 5000} {
			if got := applyMaxTokensFloor(floors, callType, "", n); got != n {
				t.Fatalf("%s %d → %d with the setting empty", callType, n, got)
			}
		}
	}
}

func TestMaxTokensFloorRaisesOnlyItsCallType(t *testing.T) {
	floors := loadMaxTokensFloor(" claim_audit = 2500 ")
	cases := []struct {
		callType string
		in, want int
	}{
		{"claim_audit", 900, 2500},
		{"claim_audit", 2500, 2500},
		{"claim_audit", 3000, 3000},
		{"claim_audit", 0, 0}, // client did not set a limit — stays unset
		{"chatgpt", 900, 900},
		{"barnum_judge", 2200, 2200},
	}
	for _, c := range cases {
		if got := applyMaxTokensFloor(floors, c.callType, "", c.in); got != c.want {
			t.Fatalf("%s %d → %d, want %d", c.callType, c.in, got, c.want)
		}
	}
}

func TestMaxTokensFloorIgnoresGarbage(t *testing.T) {
	floors := loadMaxTokensFloor("garbage,=5,claim_audit=,x=abc,y=0,z=-3,big=999999,barnum_judge=3000,,")
	if len(floors) != 1 || floors["barnum_judge"] != 3000 {
		t.Fatalf("parsed floors = %v", floors)
	}
}

// "chatgpt:1000=2000" lifts only the request that asked for exactly 1000:
// translations (500/4000), highlights and the marathon report (900) share
// the "chatgpt" call type and must keep their own limits.
func TestMaxTokensFloorExactValue(t *testing.T) {
	floors := loadMaxTokensFloor("claim_audit=2500, chatgpt:1000=2000 ,chatgpt:1500=2000")
	cases := []struct {
		callType string
		in, want int
	}{
		{"chatgpt", 1000, 2000},
		{"chatgpt", 1500, 2000},
		{"chatgpt", 500, 500},
		{"chatgpt", 900, 900},
		{"chatgpt", 999, 999},
		{"chatgpt", 2500, 2500},
		{"chatgpt", 4000, 4000},
		{"chatgpt", 0, 0},
		{"claim_audit", 900, 2500},
		{"grounding_fix", 1000, 1000},
	}
	for _, c := range cases {
		if got := applyMaxTokensFloor(floors, c.callType, "", c.in); got != c.want {
			t.Fatalf("%s %d → %d, want %d", c.callType, c.in, got, c.want)
		}
	}
}

func TestMaxTokensFloorExactValueGarbage(t *testing.T) {
	floors := loadMaxTokensFloor("chatgpt:=2000,:1000=2000,chatgpt:abc=2000,chatgpt:3000=2000,chatgpt:0=2000,chatgpt:1000=2000")
	if len(floors) != 1 || floors["chatgpt:1000"] != 2000 {
		t.Fatalf("parsed floors = %v", floors)
	}
}

// The marathon report's limit (and any other clamped tag's) is never raised,
// whatever value it carries and whatever the setting says.
func TestMaxTokensFloorNeverTouchesClampedTags(t *testing.T) {
	floors := loadMaxTokensFloor("chatgpt=5000,chatgpt:900=2000,chatgpt:1000=2000,chatgpt:1500=2000")
	for _, raw := range []string{"marathon_report", "highlights"} {
		for _, n := range []int{300, 900, 1000, 1500, 4000} {
			if got := applyMaxTokensFloor(floors, "chatgpt", raw, n); got != n {
				t.Fatalf("%s %d → %d: a clamped tag must keep its limit", raw, n, got)
			}
		}
	}
	// The same setting does lift a plain answer, and an allowlisted overhead
	// tag (raw == normalized) still follows its own floor.
	if got := applyMaxTokensFloor(floors, "chatgpt", "", 1000); got != 2000 {
		t.Fatalf("plain answer 1000 → %d, want 2000", got)
	}
	if got := applyMaxTokensFloor(loadMaxTokensFloor("claim_audit=2500"), "claim_audit", "claim_audit", 900); got != 2500 {
		t.Fatalf("claim_audit 900 → %d, want 2500", got)
	}
}
