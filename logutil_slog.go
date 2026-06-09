package main

import (
	"log/slog"
	"os"
	"sync/atomic"
)

var debugEnabled atomic.Bool

// logLevel gates log calls without entering slog's machinery.
// 0=debug, 1=info, 2=warn, 3=error.
var logLevel atomic.Int32

var logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
	Level: slog.LevelInfo,
}))

func init() {
	if os.Getenv("DEBUG") != "" {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
		debugEnabled.Store(true)
		logLevel.Store(0)
	} else {
		logLevel.Store(1)
	}
}
func logDebugf(msg string, args ...any) {
	if !debugEnabled.Load() {
		return
	}
	logger.Debug(msg, args...)
}
func logInfof(msg string, args ...any)  { logger.Info(msg, args...) }
func logWarnf(msg string, args ...any)  { logger.Warn(msg, args...) }
func logErrorf(msg string, args ...any) { logger.Error(msg, args...) }

// recoverAndLogPanic recovers from panics and logs the error.
// Package-level function avoids closure heap allocation on hot path.
func recoverAndLogPanic() {
	if r := recover(); r != nil {
		logErrorf("worker panic", "error", r)
	}
}
