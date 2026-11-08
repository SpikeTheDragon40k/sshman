package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"

	"github.com/sshman-org/sshman/model"
)

// TestHelperWriterProcess is re-executed by TestMultiProcessUpdates as a
// separate OS process; it is a no-op in a normal test run.
func TestHelperWriterProcess(t *testing.T) {
	path := os.Getenv("SSHMAN_TEST_VAULT")
	if path == "" {
		t.Skip("helper process")
	}
	id := os.Getenv("SSHMAN_TEST_WORKER")
	n, _ := strconv.Atoi(os.Getenv("SSHMAN_TEST_N"))
	for i := range n {
		name := fmt.Sprintf("p%s-%d", id, i)
		if err := Update(path, pw("pw-multiprocess"), func(e []model.Entry) ([]model.Entry, error) {
			return append(e, model.Entry{Name: name, User: "u", Host: "h", Key: "k"}), nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// Q-03: separate sshman processes updating one vault concurrently must not
// corrupt it or lose any update (the original code lost the vault in 1 of
// 200 rounds and dropped updates routinely).
func TestMultiProcessUpdates(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns processes")
	}
	path := newVaultPath(t)
	if err := Create(path, pw("pw-multiprocess")); err != nil {
		t.Fatal(err)
	}
	const procs, per = 4, 8
	var wg sync.WaitGroup
	errs := make([]error, procs)
	outs := make([][]byte, procs)
	for p := range procs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestHelperWriterProcess$", "-test.count=1")
			cmd.Env = append(os.Environ(), "SSHMAN_TEST_VAULT="+path, "SSHMAN_TEST_WORKER="+strconv.Itoa(p), "SSHMAN_TEST_N="+strconv.Itoa(per))
			outs[p], errs[p] = cmd.CombinedOutput()
		}()
	}
	wg.Wait()
	for p := range procs {
		if errs[p] != nil {
			t.Fatalf("worker %d: %v\n%s", p, errs[p], outs[p])
		}
	}
	got, err := Load(path, pw("pw-multiprocess"))
	if err != nil {
		t.Fatalf("vault unreadable: %v", err)
	}
	if len(got) != procs*per {
		t.Fatalf("lost updates: %d entries, want %d", len(got), procs*per)
	}
}
