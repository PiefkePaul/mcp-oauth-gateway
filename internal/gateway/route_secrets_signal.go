package gateway

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/secretsfile"
)

// reloadOnHangup reloads the route secrets file right away on SIGHUP,
// without waiting for the next poll.
func reloadOnHangup(store *secretsfile.Store) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	for range signals {
		store.Reload()
	}
}
