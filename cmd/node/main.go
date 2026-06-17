package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"besoeasy/sikka/internal/config"
	"besoeasy/sikka/internal/node"
)

func main() {
	initLogger()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.LoadFromEnv()
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}

	n, err := node.New(cfg)
	if err != nil {
		slog.Error("create node", "err", err)
		os.Exit(1)
	}

	if err := n.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("run node", "err", err)
		os.Exit(1)
	}
}

func initLogger() {
	level := slog.LevelInfo
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LOG_LEVEL"))) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
}