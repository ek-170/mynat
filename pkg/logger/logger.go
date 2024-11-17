// slogを使用したLoggerです。
package logger

import (
	"context"
	"errors"
	"sync"

	"io"
	"log/slog"
	"maps"
	"strings"
)

var (
	logger *slog.Logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	once   sync.Once
)

var (
	errInvalidLogLevel   = errors.New("invalid log level was specified")
	errInvalidLoggerType = errors.New("invalid logger type was specified")
)

type Format string

func (f Format) String() string {
	return string(f)
}

const (
	Text Format = "text"
	JSON Format = "json"
)

type Level string

func (f Level) String() string {
	return string(f)
}

const (
	InfoStr  Level = "info"
	DebugStr Level = "debug"
	WarnStr  Level = "warn"
	ErrorStr Level = "error"
)

func InitLogger(w io.Writer, format Format, level Level, fixedAttrs ...any) error {
	var initErr error = nil

	f := func() {
		l, err := strToSlogLevel(level.String())
		if err != nil {
			initErr = err
			return
		}
		h, err := strToSlogHandler(w, format.String(), l.Level())
		if err != nil {
			initErr = err
			return
		}
		logger = slog.New(h)
		if len(fixedAttrs) > 0 {
			logger = logger.With(fixedAttrs...)
		}
	}
	once.Do(f)
	return initErr
}

func strToSlogLevel(ls string) (*slog.LevelVar, error) {
	var level = new(slog.LevelVar)
	switch strings.ToLower(ls) {
	case "info":
		level.Set(slog.LevelInfo)
	case "debug":
		level.Set(slog.LevelDebug)
	case "warn":
		level.Set(slog.LevelWarn)
	case "error":
		level.Set(slog.LevelError)
	default:
		return nil, errInvalidLogLevel
	}
	return level, nil
}

func strToSlogHandler(w io.Writer, format string, level slog.Level) (slog.Handler, error) {
	switch strings.ToLower(format) {
	case "text":
		return NewHandler(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})), nil
	case "json":
		return NewHandler(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})), nil
	default:
		return nil, errInvalidLoggerType
	}
}

type Fields map[string]any

func (f Fields) Merge(other Fields) Fields {
	if f == nil {
		return other
	}
	clone := maps.Clone(f)
	for key, value := range other {
		clone[key] = value
	}
	return clone
}

type contextKey struct{}

func WithFields(ctx context.Context, fields Fields) context.Context {
	return context.WithValue(ctx, contextKey{}, contextualFields(ctx).Merge(fields))
}

func contextualFields(ctx context.Context) Fields {
	f, _ := ctx.Value(contextKey{}).(Fields)
	return f
}

func Info(msg string, attrs ...any) {
	logger.Info(msg, attrs...)
}

func Debug(msg string, attrs ...any) {
	logger.Debug(msg, attrs...)
}

func Warn(msg string, attrs ...any) {
	logger.Warn(msg, attrs...)
}

func Error(msg string, attrs ...any) {
	logger.Error(msg, attrs...)
}

func Infoc(ctx context.Context, msg string, attrs ...any) {
	logger.InfoContext(ctx, msg, attrs...)
}

func Debugc(ctx context.Context, msg string, attrs ...any) {
	logger.DebugContext(ctx, msg, attrs...)
}

func Warnc(ctx context.Context, msg string, attrs ...any) {
	logger.WarnContext(ctx, msg, attrs...)
}

func Errorc(ctx context.Context, msg string, attrs ...any) {
	logger.ErrorContext(ctx, msg, attrs...)
}
