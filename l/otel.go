package l

import (
	"context"
	"fmt"
	"math"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type LoggerWithOtel struct {
	*Logger
	ctx      context.Context
	provider trace.TracerProvider
	tracer   trace.Tracer
}

// New returns new zap.Logger
func NewWithOtel(tp trace.TracerProvider, opts ...zap.Option) LoggerWithOtel {
	l := New(opts...)
	return LoggerWithOtel{
		Logger:   &l,
		ctx:      context.Background(),
		provider: tp,
		tracer:   tp.Tracer("git.kafefin.net/backend/kitchen/l"),
	}
}

// Ctx returns a new logger with the context.
func (lc LoggerWithOtel) Ctx(ctx context.Context) LoggerWithOtel {
	return LoggerWithOtel{lc.Logger, ctx, lc.provider, lc.tracer}
}

func (lc LoggerWithOtel) Debug(msg string, fields ...zap.Field) {
	lc.log(zap.DebugLevel, msg, fields...)
}

func (lc LoggerWithOtel) Info(msg string, fields ...zap.Field) {
	lc.log(zap.InfoLevel, msg, fields...)
}

func (lc LoggerWithOtel) Warn(msg string, fields ...zap.Field) {
	lc.log(zap.WarnLevel, msg, fields...)
}

func (lc LoggerWithOtel) Error(msg string, fields ...zap.Field) {
	lc.log(zap.ErrorLevel, msg, fields...)
}

func (lc LoggerWithOtel) DPanic(msg string, fields ...zap.Field) {
	lc.log(zap.DPanicLevel, msg, fields...)
}

func (lc LoggerWithOtel) Panic(msg string, fields ...zap.Field) {
	lc.log(zap.PanicLevel, msg, fields...)
}

func (lc LoggerWithOtel) Fatal(msg string, fields ...zap.Field) {
	lc.log(zap.FatalLevel, msg, fields...)
}

func (logger LoggerWithOtel) Log(ctx context.Context, level logging.Level, msg string, fields ...any) {
	logger.ctx, _ = logger.tracer.Start(ctx, "intercept_log", trace.WithSpanKind(trace.SpanKindClient))
	logger.log(interceptLevel(level), msg, anyFields(fields)...)
}

func (lc *LoggerWithOtel) log(lvl zapcore.Level, msg string, fields ...zap.Field) {
	span := trace.SpanFromContext(lc.ctx)
	defer span.End()
	if !span.IsRecording() {
		lc.Logger.Logger.Log(lvl, msg, fields...)
		return
	}

	traceID := span.SpanContext().TraceID().String()
	if traceID != "" {
		fields = append(fields, String("trace_id", traceID))
	}

	attrs, errAttr := parseFields(fields...)

	span.AddEvent("log", trace.WithAttributes(attrs...))

	if lvl >= zap.ErrorLevel {
		span.SetStatus(codes.Error, msg)
		if errAttr.Key != "" {
			span.RecordError(fmt.Errorf(errAttr.Value.AsString()))
		}
	}

	lc.Logger.Logger.Log(lvl, msg, fields...)
}

func parseFields(fields ...zap.Field) ([]attribute.KeyValue, attribute.KeyValue) {
	attrs := make([]attribute.KeyValue, 0, len(fields))
	errAttr := attribute.KeyValue{}
	for _, f := range fields {
		if f.Key == errKey || f.Key == "grpc.error" {
			errAttr = attribute.String(f.Key, f.String)
			continue
		}

		switch f.Type {
		case zapcore.StringType:
			attrs = append(attrs, attribute.String(f.Key, f.String))
		case zapcore.BoolType:
			attrs = append(attrs, attribute.Bool(f.Key, f.Integer == 1))
		case zapcore.Int8Type, zapcore.Int16Type, zapcore.Int32Type, zapcore.Int64Type:
			attrs = append(attrs, attribute.Int(f.Key, int(f.Integer)))
		case zapcore.Float32Type:
			attrs = append(attrs, attribute.Float64(f.Key, float64(math.Float32frombits(uint32(f.Integer)))))
		case zapcore.Float64Type:
			attrs = append(attrs, attribute.Float64(f.Key, math.Float64frombits(uint64(f.Integer))))
		}
	}
	return attrs, errAttr
}
