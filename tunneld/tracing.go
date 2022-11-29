package tunneld

import (
	"context"
	"net"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type tracingConnWrapper struct {
	net.Conn

	ctx  context.Context
	span trace.Span
}

func (n *tracingConnWrapper) Read(b []byte) (int, error) {
	_, span := otel.GetTracerProvider().Tracer("").Start(n.ctx, "(net.Conn).Read")
	defer span.End()

	nbytes, err := n.Conn.Read(b)
	span.SetAttributes(attribute.Int("bytes_read", nbytes))
	return nbytes, err
}

func (n *tracingConnWrapper) Write(b []byte) (int, error) {
	_, span := otel.GetTracerProvider().Tracer("").Start(n.ctx, "(net.Conn).Write")
	defer span.End()

	nbytes, err := n.Conn.Write(b)
	span.SetAttributes(attribute.Int("bytes_written", nbytes))
	return nbytes, err
}

func (n *tracingConnWrapper) Close() error {
	n.span.AddEvent("connClose")
	return n.Conn.Close()
}
