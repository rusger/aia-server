package main

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// A121: two identical record-purchase requests in the same millisecond, each a
// transaction that reads first and writes second. With a deferred BEGIN the
// second one cannot upgrade to a writer and gets SQLITE_BUSY at once; with
// usersDBDSN (_txlock=immediate) it waits for the first and both succeed.
func readThenWriteRace(t *testing.T, dsn string) []error {
	t.Helper()
	d, err := sql.Open("sqlite", dsn+"&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.Exec(`CREATE TABLE p (id INTEGER PRIMARY KEY, txn TEXT)`); err != nil {
		t.Fatal(err)
	}
	var read sync.WaitGroup
	read.Add(2)
	readDone := make(chan struct{})
	go func() { read.Wait(); close(readDone) }()
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tx, err := d.Begin()
			if err != nil {
				read.Done()
				errs[i] = err
				return
			}
			defer tx.Rollback()
			var n int
			err = tx.QueryRow(`SELECT COUNT(*) FROM p WHERE txn = 'x'`).Scan(&n)
			read.Done()
			if err != nil {
				errs[i] = err
				return
			}
			// Both readers hold their snapshot before either writes (deferred case);
			// with an immediate lock the second Begin is still waiting, so stop
			// waiting for it after a short while and let the first one commit.
			select {
			case <-readDone:
			case <-time.After(300 * time.Millisecond):
			}
			if _, err := tx.Exec(`INSERT INTO p (txn) VALUES ('x')`); err != nil {
				errs[i] = err
				return
			}
			errs[i] = tx.Commit()
		}(i)
	}
	wg.Wait()
	return errs
}

func TestUsersDBTxLockImmediate(t *testing.T) {
	dir := t.TempDir()
	for i, err := range readThenWriteRace(t, usersDBDSN(filepath.Join(dir, "new.db"))) {
		if err != nil {
			t.Errorf("usersDBDSN: transaction %d failed: %v", i, err)
		}
	}
	// Control: the old DSN (deferred BEGIN) reproduces the production error,
	// so the test above really exercises the read→write upgrade.
	old := "file:" + filepath.Join(dir, "old.db") + "?_pragma=busy_timeout(5000)"
	failed := 0
	for _, err := range readThenWriteRace(t, old) {
		if err != nil {
			failed++
		}
	}
	if failed == 0 {
		t.Errorf("control: deferred BEGIN did not reproduce SQLITE_BUSY — the race is not exercised")
	}
}
