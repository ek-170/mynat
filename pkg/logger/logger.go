// slogを使用したLoggerです。
package logger

import (
	"context"
	"errors"
	"os"
	"sync"

	"io"
	"log/slog"
	"maps"
	"strings"
)

var (
	// default is stdout & text format
	logger *slog.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	once   sync.Once
)

const (
	InfoStr  = "info"
	DebugStr = "debug"
	WarnStr  = "warn"
	ErrorStr = "error"
)

var (
	errInvalidLogLevel   = errors.New("invalid log level was specified")
	errInvalidLoggerType = errors.New("invalid logger type was specified")
)

var (
	initErr error
)

func InitLogger(w io.Writer, format string, level string, fixedAttrs ...any) error {
	f := func() {
		l, err := strToSlogLevel(level)
		if err != nil {
			initErr = err
		}
		h, err := strToSlogHandler(w, format, l.Level())
		if err != nil {
			initErr = err
		}
		logger = slog.New(h)
		if fixedAttrs != nil {
			logger.With(fixedAttrs...)
		}
		initErr = nil
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
	// 新しいものを作ってマージ
	clone := maps.Clone(f)
	for key, value := range other {
		clone[key] = value
	}
	return clone
}

type contextKey struct{}

// ContextにFieldsを追加する
func WithFields(ctx context.Context, fields Fields) context.Context {
	// nil レシーバのハンドリングをしているのでいきなり Merge を呼び出して OK
	return context.WithValue(ctx, contextKey{}, contextualFields(ctx).Merge(fields))
}

// Fields を取り出すのはこのパッケージだけの責務なので非公開関数で問題なし
func contextualFields(ctx context.Context) Fields {
	// コンテキストに設定されていないときは nil を返す
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
