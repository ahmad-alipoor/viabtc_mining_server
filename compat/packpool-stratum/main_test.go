package main

import (
	"bufio"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func TestRelayPreservesStratumFrames(t *testing.T) {
	pool, miner := net.Pipe()
	defer pool.Close()
	defer miner.Close()

	done := make(chan struct{})
	go func() {
		var relayWG sync.WaitGroup
		go func() {
			relay(&relayWG, pool, miner, "test")
		}()
		_, _ = pool.Write([]byte(`{"id":1,"method":"mining.notify","params":[]}` + "\n"))
		close(done)
	}()

	_ = done
	miner.SetReadDeadline(time.Now().Add(time.Second))
	line, err := bufio.NewReader(miner).ReadString('\n')
	if err != nil {
		t.Fatalf("read relayed frame: %v", err)
	}
	if line != fmt.Sprintf(`{"id":1,"method":"mining.notify","params":[]}%s`, "\n") {
		t.Fatalf("frame changed: %q", line)
	}
}
