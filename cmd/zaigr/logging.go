package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

func configureLogging(levelName string, verboseCount int, explicitLevel bool) error {
	var level slog.Level
	if explicitLevel {
		parsedLevel, err := parseLogLevel(levelName)
		if err != nil {
			return err
		}
		level = parsedLevel
	} else {
		switch {
		case verboseCount <= 0:
			level = slog.LevelWarn
		case verboseCount == 1:
			level = slog.LevelInfo
		default:
			level = slog.LevelDebug
		}
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.TimeKey {
				return slog.Attr{}
			}
			if attr.Key == slog.LevelKey {
				attr.Value = slog.StringValue(strings.ToLower(attr.Value.String()))
			}
			return attr
		},
	})
	slog.SetDefault(slog.New(handler))
	return nil
}

func parseLogLevel(levelName string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(levelName)) {
	case "error":
		return slog.LevelError, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	default:
		return slog.LevelWarn, fmt.Errorf("invalid --log-level %q (expected error, warn, info, or debug)", levelName)
	}
}

func logDebug(msg string, args ...any) {
	slog.Debug(msg, args...)
}

func logInfo(msg string, args ...any) {
	slog.Info(msg, args...)
}

func logWarn(msg string, args ...any) {
	slog.Warn(msg, args...)
}

func logError(msg string, args ...any) {
	slog.Error(msg, args...)
}
