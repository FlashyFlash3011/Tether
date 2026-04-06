// Package cloudflared manages a cloudflared quick-tunnel subprocess.
// It starts cloudflared, parses the assigned *.trycloudflare.com URL from
// its output, and exposes a stop function to kill the process.
package cloudflared

import (
	"bufio"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"time"
)

var urlPattern = regexp.MustCompile(`https://[a-zA-Z0-9-]+\.trycloudflare\.com`)

// Start launches `cloudflared tunnel --url http://localhost:<port>` and
// returns the public tunnel URL once cloudflared reports it.
// cloudflared must be installed and in PATH.
func Start(localPort int) (tunnelURL string, stop func(), err error) {
	cmd := exec.Command("cloudflared", "tunnel", "--url",
		fmt.Sprintf("http://localhost:%d", localPort))

	// cloudflared writes its tunnel URL to stderr.
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", nil, fmt.Errorf("cloudflared: pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return "", nil, fmt.Errorf("cloudflared: start: %w (is cloudflared installed?)", err)
	}

	stopFn := func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}

	urlCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if m := urlPattern.FindString(line); m != "" {
				select {
				case urlCh <- m:
				default:
				}
			}
			// Keep draining stderr so the process doesn't block.
		}
	}()

	select {
	case u := <-urlCh:
		log.Printf("cloudflared: relay tunnel at %s", u)
		return u, stopFn, nil
	case <-time.After(45 * time.Second):
		stopFn()
		return "", nil, fmt.Errorf("cloudflared: timed out waiting for tunnel URL (is cloudflared installed?)")
	}
}
