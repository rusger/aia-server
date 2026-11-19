package main

// Restart without 502 (A147, 19.11.2026). Every 5xx in nginx's access.log on 19.11 (31 of 32) fell into the
// three restart windows: the binary used a bare http.ListenAndServe, `kill` cut every request in flight, and the
// unit's RestartSec=10 left port 8081 closed for ten seconds, so nginx answered 502.
//
// Now:
//   - the listening socket may come from systemd socket activation (astrolog-api.socket, LISTEN_PID/LISTEN_FDS,
//     fd 3). systemd keeps the port open while the service restarts and the kernel queues new connections, so
//     nginx waits instead of failing. Without those variables the server listens itself, exactly as before —
//     the code can ship before the unit changes;
//   - SIGTERM/SIGINT drain: stop accepting, let in-flight requests and streams finish for up to drainTimeout,
//     then close what is left and exit 0. systemd starts the next process only after this one exits, so
//     background schedulers never run twice (handing the socket to a second live process was rejected for that
//     reason: duplicate pushes).

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

const drainTimeout = 25 * time.Second // < TimeoutStopSec of the unit (40 s)

// listenerFromSystemd returns the socket systemd passed to this process (sd_listen_fds protocol: the first
// passed fd is 3), or nil when the process was not socket-activated. The variables are removed so that child
// processes never mistake them for their own.
func listenerFromSystemd() (net.Listener, error) { return listenerFromEnv(3) }

// listenerFromEnv — listenerFromSystemd with the first passed descriptor as a parameter (tests cannot use fd 3:
// on macOS the Go runtime's own kqueue lives there).
func listenerFromEnv(firstFd int) (net.Listener, error) {
	pid, fds := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	if pid == "" || fds == "" {
		return nil, nil
	}
	if p, err := strconv.Atoi(pid); err != nil || p != os.Getpid() {
		return nil, nil
	}
	if n, err := strconv.Atoi(fds); err != nil || n < 1 {
		return nil, nil
	}
	syscall.CloseOnExec(firstFd)
	f := os.NewFile(uintptr(firstFd), "systemd-socket")
	ln, err := net.FileListener(f)
	f.Close() // FileListener dups the descriptor
	if err != nil {
		return nil, err
	}
	return ln, nil
}

// serveGraceful serves handler until SIGTERM/SIGINT, then drains. tlsCert/tlsKey empty = plain HTTP.
func serveGraceful(port string, handler http.Handler, tlsCert, tlsKey string) {
	ln, err := listenerFromSystemd()
	if err != nil {
		log.Fatalf("systemd socket: %v", err)
	}
	if ln != nil {
		log.Printf("🔌 listening on the socket from systemd (%s)", ln.Addr())
	} else if ln, err = net.Listen("tcp", ":"+port); err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	done := make(chan struct{})
	go func() {
		sig := <-stop
		drain(srv, sig, drainTimeout)
		close(done)
	}()
	if tlsCert != "" && tlsKey != "" {
		err = srv.ServeTLS(ln, tlsCert, tlsKey)
	} else {
		err = srv.Serve(ln)
	}
	if !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	<-done
	log.Printf("👋 graceful stop finished")
}

// drain stops accepting and waits for in-flight requests up to timeout; whatever is still open after that is
// closed (a stream cut here resumes as 410 → the app regenerates, chatgpt_resume.go).
func drain(srv *http.Server, sig os.Signal, timeout time.Duration) {
	t0 := time.Now()
	log.Printf("🛑 %v: graceful stop, draining up to %s", sig, timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("⚠️ drain timeout after %.1fs: closing remaining connections (%v)", time.Since(t0).Seconds(), err)
		srv.Close()
		return
	}
	log.Printf("✅ drained in %.1fs", time.Since(t0).Seconds())
}
