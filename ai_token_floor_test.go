package main

import "testing"

func TestMaxTokensFloorOffChangesNothing(t *testing.T) {
	floors := loadMaxTokensFloor("")
	for _, callType := range []string{"chatgpt", "claim_audit", "barnum_judge"} {
		for _, n := range []int{0, 900, 2200, 5000} {
			if got := applyMaxTokensFloor(floors, callType, n); got != n {
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
		if got := applyMaxTokensFloor(floors, c.callType, c.in); got != c.want {
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
