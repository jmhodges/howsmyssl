package main

import (
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestPostQuantumGroups pins exactly which named groups count as post-quantum
// key agreement: every ML-KEM group in the registry, on its own or as a
// hybrid, and not the obsolete pre-standard Kyber drafts.
func TestPostQuantumGroups(t *testing.T) {
	want := []string{
		"MLKEM1024",
		"MLKEM1024X448",
		"MLKEM512",
		"MLKEM512X25519",
		"MLKEM768",
		"SecP256r1MLKEM512",
		"SecP256r1MLKEM768",
		"SecP384r1MLKEM1024",
		"X25519MLKEM768",
		"curveSM2MLKEM768",
	}
	var got []string
	for id := range postQuantumGroups {
		name, ok := allNamedGroups[id]
		if !ok {
			t.Errorf("postQuantumGroups has %#04x, which isn't in allNamedGroups", id)
			continue
		}
		got = append(got, name)
	}
	sort.Strings(got)
	if !cmp.Equal(want, got) {
		t.Errorf("postQuantumGroups: want %v, got %v", want, got)
	}

	// Every ML-KEM group that the table names counts, so a new one added to
	// allNamedGroups without postQuantumGroups fails here.
	for id, name := range allNamedGroups {
		if strings.Contains(name, "MLKEM") && !postQuantumGroups[id] {
			t.Errorf("%s (%#04x) is an ML-KEM group but isn't in postQuantumGroups", name, id)
		}
	}

	for _, id := range []uint16{0x6399, 0x639a} {
		if postQuantumGroups[id] {
			t.Errorf("%s (%#04x) is an obsolete Kyber draft and must not count as post-quantum", allNamedGroups[id], id)
		}
	}
}
