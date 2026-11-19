package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestListenerFromSystemdIgnoresForeignOrMissing(t *testing.T) {
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	if ln, err := listenerFromSystemd(); ln != nil || err != nil {
		t.Fatalf("no variables → (nil, nil), got (%v, %v)", ln, err)
	}
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()+1))
	t.Setenv("LISTEN_FDS", "1")
	if ln, err := listenerFromSystemd(); ln != nil || err != nil {
		t.Fatalf("another process's variables → (nil, nil), got (%v, %v)", ln, err)
	}
	if os.Getenv("LISTEN_PID") != "" || os.Getenv("LISTEN_FDS") != "" {
		t.Fatal("variables must be removed from the environment")
	}
}

func TestListenerFromSystemdTakesPassedFd(t *testing.T) {
	ln0, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f, err := ln0.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	ln0.Close()
	const fd = 77 // stands in for systemd's fd 3 (on macOS fd 3 is the runtime's kqueue)
	if err := syscall.Dup2(int(f.Fd()), fd); err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "1")
	ln, err := listenerFromEnv(fd)
	if err != nil || ln == nil {
		t.Fatalf("own pid → listener, got (%v, %v)", ln, err)
	}
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	resp, err := http.Get("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "ok" {
		t.Fatalf("served %q", b)
	}
}

// An in-flight request finishes during the drain; a new connection after Shutdown is not accepted.
func TestDrainLetsInFlightFinish(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(300 * time.Millisecond)
		io.WriteString(w, "done")
	})}
	go srv.Serve(ln)
	got := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String())
		if err != nil {
			got <- "error: " + err.Error()
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		got <- string(b)
	}()
	<-started
	drain(srv, syscall.SIGTERM, 5*time.Second)
	if r := <-got; r != "done" {
		t.Fatalf("in-flight request must finish, got %q", r)
	}
	if c, err := net.DialTimeout("tcp", ln.Addr().String(), 300*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("a new connection after the drain must be refused")
	}
}

// A request that outlives the drain timeout is cut, and drain returns on time.
func TestDrainTimeoutClosesStuck(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})}
	go srv.Serve(ln)
	go http.Get("http://" + ln.Addr().String())
	<-started
	t0 := time.Now()
	drain(srv, syscall.SIGTERM, 200*time.Millisecond)
	if d := time.Since(t0); d > 2*time.Second {
		t.Fatalf("drain must give up after its timeout, took %s", d)
	}
}
