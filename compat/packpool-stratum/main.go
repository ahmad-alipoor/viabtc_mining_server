package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type config struct {
	listen   string
	upstream string
	deadline time.Duration
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.listen, "listen", "127.0.0.1:2235", "downstream listen address")
	flag.StringVar(&cfg.upstream, "upstream", "", "standard Stratum upstream host:port")
	flag.DurationVar(&cfg.deadline, "connect-timeout", 10*time.Second, "upstream connect timeout")
	flag.Parse()
	if cfg.upstream == "" {
		log.Fatal("-upstream is required")
	}

	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.listen, err)
	}
	log.Printf("packpool stratum compatibility adapter listening on %s -> %s", cfg.listen, cfg.upstream)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn, cfg)
	}
}

func handle(downstream net.Conn, cfg config) {
	defer downstream.Close()
	upstream, err := net.DialTimeout("tcp", cfg.upstream, cfg.deadline)
	if err != nil {
		log.Printf("upstream dial %s: %v", cfg.upstream, err)
		return
	}
	defer upstream.Close()

	log.Printf("session %s -> %s", downstream.RemoteAddr(), cfg.upstream)
	var wg sync.WaitGroup
	wg.Add(2)
	go relay(&wg, downstream, upstream, "miner->pool")
	go relay(&wg, upstream, downstream, "pool->miner")
	wg.Wait()
	log.Printf("session closed %s", downstream.RemoteAddr())
}

func relay(wg *sync.WaitGroup, dst net.Conn, src net.Conn, direction string) {
	defer wg.Done()
	reader := bufio.NewReaderSize(src, 64*1024)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) != 0 {
			if _, writeErr := dst.Write(line); writeErr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("%s: %v", direction, err)
			}
			return
		}
	}
}
