package logger

import (
	"context"
	"log/slog"
)

// ログ出力を加工するための独自Handler
type Handler struct {
	inner slog.Handler
}

func NewHandler(inner slog.Handler) Handler {
	return Handler{
		inner: inner,
	}
}

// defaultを使用
func (h Handler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

// contextに含まれるFieldsをAttrsに変換して出力する
func (h Handler) Handle(ctx context.Context, r slog.Record) error {
	if fields := contextualFields(ctx); fields != nil {
		r.AddAttrs(fieldsToSlogAttr(fields)...)
	}
	return h.inner.Handle(ctx, r)
}

func fieldsToSlogAttr(data Fields) []slog.Attr {
	attrs := make([]slog.Attr, len(data))
	var i int
	for key, value := range data {
		attrs[i] = slog.Attr{Key: key, Value: slog.AnyValue(value)}
		i++
	}
	return attrs
}

// defaultを使用
func (h Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h.inner.WithAttrs(attrs)
}

// defaultを使用
func (h Handler) WithGroup(name string) slog.Handler {
	return h.inner.WithGroup(name)
}
