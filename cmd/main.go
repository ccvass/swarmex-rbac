package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	rbac "github.com/ccvass/swarmex/swarmex-rbac"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	configPath := os.Getenv("RBAC_CONFIG")
	if configPath == "" { configPath = "/etc/swarmex/rbac.yaml" }
	proxy, err := rbac.New(configPath, "/var/run/docker.sock", logger)
	if err != nil { logger.Error("failed to create proxy", "error", err); os.Exit(1) }

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	mux.Handle("/", proxy)

	go func() { logger.Info("rbac proxy", "addr", ":2376"); http.ListenAndServe(":2376", mux) }()
	go func() { logger.Info("health endpoint", "addr", ":8080"); http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" { promhttp.Handler().ServeHTTP(w, r); return }
		fmt.Fprint(w, "ok")
	})) }()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	logger.Info("swarmex-rbac starting")
	<-ctx.Done()
	logger.Info("shutdown complete")
}
