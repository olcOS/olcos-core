package bond

import "testing"

func TestTheServerTakesGroupAndBudgetOnlyFromANewClient(t *testing.T) {
	s := newServer(nil, nil)
	newer := hello{client: [8]byte{1, 2, 3, 4, 5, 6, 7, budgetCode(2 << 20)}, lane: 1, ext: true, group: 1}
	older := hello{client: [8]byte{9, 8, 7, 6, 5, 4, 3, 2}, lane: 1, lanes: 2}
	if g := s.laneStats(newer).failGroup(1); g != 0 {
		t.Fatalf("a new client's lane 2 in group 1 (from 1) reads as group %d", g)
	}
	if g := s.laneStats(older).failGroup(1); g != 1 {
		t.Fatalf("an old client's lane 2 is in group %d, want its own", g)
	}
	b := s.budgetFor(newer)
	if b.limit.Load() != 2<<20 {
		t.Fatalf("a new client asked for 2 MiB toward it, the server keeps %d", b.limit.Load())
	}
	if again := s.budgetFor(newer); again != b {
		t.Fatal("two streams of one client do not share its budget")
	}
	if o := s.budgetFor(older); o.limit.Load() != serverBudget || o == b {
		t.Fatalf("an old client gets %d, want the server's default %d", o.limit.Load(), serverBudget)
	}
	s.releaseBudget(newer)
	s.releaseBudget(newer)
	if len(s.budgets) != 1 {
		t.Fatalf("%d budgets kept after a client's streams ended", len(s.budgets))
	}
	// Its lane stats are kept by the client's random bytes alone, the budget
	// byte aside.
	moved := newer
	moved.client[7] = budgetCode(8 << 20)
	if s.laneStats(moved) != s.laneStats(newer) {
		t.Fatal("a new budget split the client's lane stats")
	}
}
