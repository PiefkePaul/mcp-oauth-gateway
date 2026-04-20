package main

import (
	"log"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/gateway"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	if err := gateway.Run(cfg); err != nil {
		log.Fatalf("gateway failed: %v", err)
	}
}
