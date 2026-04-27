package howhttp_test

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	howhttptest "github.com/jmhodges/howsmyssl/howhttp/httptest"
)

const concurrentN = 50

func TestServer_ConcurrentHTTP11(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	srv := howhttptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.URL.Query().Get("token"))
	}))
	t.Cleanup(srv.Close)

	var wg sync.WaitGroup
	errs := make([]error, concurrentN)
	bodies := make([]string, concurrentN)
	protos := make([]int, concurrentN)
	wg.Add(concurrentN)
	for i := range concurrentN {
		go func(i int) {
			defer wg.Done()
			tlsConf := srv.ClientTLSConfig()
			tlsConf.NextProtos = []string{"http/1.1"}
			tr := &http.Transport{TLSClientConfig: tlsConf}
			defer tr.CloseIdleConnections()
			c := &http.Client{Transport: tr, Timeout: 10 * time.Second}

			resp, err := c.Get(srv.URL + "/?token=" + strconv.Itoa(i))
			if err != nil {
				errs[i] = err
				return
			}
			defer resp.Body.Close()
			protos[i] = resp.ProtoMajor
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				errs[i] = err
				return
			}
			bodies[i] = string(b)
		}(i)
	}
	wg.Wait()

	for i := range errs {
		if errs[i] != nil {
			t.Errorf("req %d: %v", i, errs[i])
			continue
		}
		if protos[i] != 1 {
			t.Errorf("req %d ProtoMajor = %d, want 1", i, protos[i])
		}
		if want := strconv.Itoa(i); bodies[i] != want {
			t.Errorf("req %d body = %q, want %q", i, bodies[i], want)
		}
	}
}

func TestServer_ConcurrentHTTP2_Multiplexed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	srv := howhttptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Force temporal overlap so requests actually share the connection
		// rather than serializing.
		time.Sleep(10 * time.Millisecond)
		io.WriteString(w, r.URL.Query().Get("token"))
	}))
	t.Cleanup(srv.Close)
	c := srv.Client() // single shared client => one multiplexed h2 conn

	var wg sync.WaitGroup
	errs := make([]error, concurrentN)
	bodies := make([]string, concurrentN)
	protos := make([]int, concurrentN)
	wg.Add(concurrentN)
	for i := range concurrentN {
		go func(i int) {
			defer wg.Done()
			resp, err := c.Get(srv.URL + "/?token=" + strconv.Itoa(i))
			if err != nil {
				errs[i] = err
				return
			}
			defer resp.Body.Close()
			protos[i] = resp.ProtoMajor
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				errs[i] = err
				return
			}
			bodies[i] = string(b)
		}(i)
	}
	wg.Wait()

	for i := range errs {
		if errs[i] != nil {
			t.Errorf("req %d: %v", i, errs[i])
			continue
		}
		if protos[i] != 2 {
			t.Errorf("req %d ProtoMajor = %d, want 2", i, protos[i])
		}
		if want := strconv.Itoa(i); bodies[i] != want {
			t.Errorf("req %d body = %q, want %q", i, bodies[i], want)
		}
	}
}

func TestServer_ConcurrentHTTP2_ManyConns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	srv := howhttptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.URL.Query().Get("token"))
	}))
	t.Cleanup(srv.Close)

	var wg sync.WaitGroup
	errs := make([]error, concurrentN)
	bodies := make([]string, concurrentN)
	protos := make([]int, concurrentN)
	wg.Add(concurrentN)
	for i := range concurrentN {
		go func(i int) {
			defer wg.Done()
			tr := &http.Transport{
				TLSClientConfig:   srv.ClientTLSConfig(),
				ForceAttemptHTTP2: true,
			}
			defer tr.CloseIdleConnections()
			c := &http.Client{Transport: tr, Timeout: 10 * time.Second}

			resp, err := c.Get(srv.URL + "/?token=" + strconv.Itoa(i))
			if err != nil {
				errs[i] = err
				return
			}
			defer resp.Body.Close()
			protos[i] = resp.ProtoMajor
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				errs[i] = err
				return
			}
			bodies[i] = string(b)
		}(i)
	}
	wg.Wait()

	for i := range errs {
		if errs[i] != nil {
			t.Errorf("req %d: %v", i, errs[i])
			continue
		}
		if protos[i] != 2 {
			t.Errorf("req %d ProtoMajor = %d, want 2", i, protos[i])
		}
		if want := strconv.Itoa(i); bodies[i] != want {
			t.Errorf("req %d body = %q, want %q", i, bodies[i], want)
		}
	}
}

func TestServer_ShutdownDrainsInFlight(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	// Each handler signals it has entered, sleeps long enough that all N
	// are guaranteed to be in-flight when we call Shutdown, then returns
	// 200. A correct Shutdown waits for every one of these to complete.
	const handlerSleep = 200 * time.Millisecond
	// Generous deadline: under `go test -race` with N concurrent in-flight
	// requests, drain has been observed to take well over 5s on a loaded
	// machine. The test verifies that Shutdown drains successfully, not
	// how quickly.
	const shutdownTimeout = 30 * time.Second

	handlerEntered := make(chan struct{}, concurrentN)
	srv := howhttptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerEntered <- struct{}{}
		time.Sleep(handlerSleep)
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)

	var wg sync.WaitGroup
	errs := make([]error, concurrentN)
	bodies := make([]string, concurrentN)

	h2Client := srv.Client() // shared h2 client for odd indices
	wg.Add(concurrentN)
	for i := range concurrentN {
		go func(i int) {
			defer wg.Done()
			var c *http.Client
			if i%2 == 0 {
				tlsConf := srv.ClientTLSConfig()
				tlsConf.NextProtos = []string{"http/1.1"}
				tr := &http.Transport{TLSClientConfig: tlsConf}
				defer tr.CloseIdleConnections()
				c = &http.Client{Transport: tr, Timeout: 10 * time.Second}
			} else {
				c = h2Client
			}
			resp, err := c.Get(srv.URL + "/")
			if err != nil {
				errs[i] = err
				return
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				errs[i] = err
				return
			}
			bodies[i] = string(b)
		}(i)
	}

	for i := range concurrentN {
		select {
		case <-handlerEntered:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d/%d handlers entered before timeout", i, concurrentN)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Config.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown returned %v, want nil (drain should have completed in time)", err)
	}

	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Errorf("req %d: %v", i, errs[i])
			continue
		}
		if bodies[i] != "ok" {
			t.Errorf("req %d body = %q, want %q", i, bodies[i], "ok")
		}
	}
}

func BenchmarkServer_ConcurrentH2(b *testing.B) {
	srv := howhttptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	b.Cleanup(srv.Close)
	c := srv.Client()
	url := srv.URL + "/"

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := c.Get(url)
			if err != nil {
				b.Error(err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}
