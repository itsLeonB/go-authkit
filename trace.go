package authkit

import (
	"context"

	"go.opentelemetry.io/otel/trace"
)

func (kit *AuthKit) startSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	if kit.cfg.Tracer == nil {
		return ctx, nil
	}
	return kit.cfg.Tracer.Start(ctx, name)
}

func endSpan(span trace.Span) {
	if span != nil {
		span.End()
	}
}
