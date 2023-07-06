package l

import (
	"context"
	"net/http"
	"os"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	envLogLevel       = "LOG_LEVEL"
	defaultLogLevel   = "DEBUG"
	customEncoderName = ""
)

// defaultEncoderConfig ...
var defaultEncoderConfig = zapcore.EncoderConfig{
	TimeKey:        "time",
	LevelKey:       "level",
	NameKey:        "logger",
	CallerKey:      "caller",
	MessageKey:     "msg",
	FunctionKey:    "func",
	StacktraceKey:  "stacktrace",
	LineEnding:     zapcore.DefaultLineEnding,
	EncodeLevel:    zapcore.CapitalLevelEncoder,
	EncodeTime:     zapcore.ISO8601TimeEncoder,
	EncodeDuration: zapcore.SecondsDurationEncoder,
	EncodeCaller:   zapcore.ShortCallerEncoder,
}

// Logger wraps zap.Logger
type Logger struct {
	*zap.Logger
}

// New returns new zap.Logger
func New(opts ...zap.Option) Logger {
	envLog := os.Getenv(envLogLevel)
	if envLog == "" {
		envLog = defaultLogLevel
	}

	var lv zapcore.Level
	err := lv.UnmarshalText([]byte(envLog))
	if err != nil {
		panic(err)
	}

	encoding := customEncoderName
	if encoding == "" {
		// console-format: <timestamp> <caller_file> <log_level> <func> <message> <body(json)>
		// => regex: ([^\s]+)\s+([A-Z]+)\s+([^\s]+)\s+([^\s]+)\s+([^{}]+?)\s+(\{.+\})
		// json-format: {"timestamp": "", "caller": "", "level": "", "message": "", "fields": ""...}
		encoding = "console"
	}

	loggerConfig := zap.Config{
		Level:       zap.NewAtomicLevelAt(lv),
		Development: false,
		Sampling: &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
		Encoding:         encoding,
		EncoderConfig:    defaultEncoderConfig,
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}
	stacktraceLevel := zap.NewAtomicLevelAt(zapcore.PanicLevel)

	opts = append(opts, zap.AddStacktrace(stacktraceLevel))
	logger, err := loggerConfig.Build(opts...)
	if err != nil {
		panic(err)
	}

	return Logger{logger}
}

var mapLoggingZapLevel = map[logging.Level]zapcore.Level{
	logging.LevelDebug: zapcore.DebugLevel,
	logging.LevelInfo:  zapcore.InfoLevel,
	logging.LevelWarn:  zapcore.WarnLevel,
	logging.LevelError: zapcore.ErrorLevel,
}

func interceptLevel(level logging.Level) zapcore.Level {
	if lvl, ok := mapLoggingZapLevel[level]; ok {
		return lvl
	}

	return zapcore.DebugLevel
}

// Log grpc logging interceptors
func (logger Logger) Log(ctx context.Context, level logging.Level, msg string, fields ...any) {
	logger.Logger.Log(interceptLevel(level), msg, anyFields(fields)...)
}

func anyFields(fields ...any) []zap.Field {
	fz := make([]zap.Field, 0, len(fields)/2)
	for i := 0; i < len(fields); {
		key, hasKey := fields[i].(string)
		var value interface{}
		if hasKey && i+1 < len(fields) {
			value = fields[i+1]
			i += 2
		} else {
			key = "grpc.key"
			value = fields[i]
			i += 1
		}

		switch v := value.(type) {
		case string:
			fz = append(fz, String(key, v))
		case int:
			fz = append(fz, Int(key, v))
		case bool:
			fz = append(fz, Bool(key, v))
		case float32:
			fz = append(fz, Float64(key, float64(v)))
		case float64:
			fz = append(fz, Float64(key, v))
		default:
			fz = append(fz, Object(key, v))
		}
	}

	return fz
}

// Named insert name after <level>
// => format: <timestamp> <caller_file> <named> <log_level> <func> <message> <body(json)>
func (logger Logger) Named(msg string) Logger {
	// if msg != "" {
	// 	logger.Logger = logger.Logger.Named(msg)
	// }

	return logger
}

// PrintError prints all error with all metadata and line number.
// It's preferred to be used at top level function. (with log sugar)
//
//	func DoSomething() (_err error) {
//	    defer ll.PrintError("DoSomething", &_err)
func (logger Logger) PrintError(msg string, err *error) {
	if *err != nil {
		logger.Sugar().Error(msg, Error(*err))
	}
}

// ServeHTTP supports logging level with an HTTP request.
func ServeHTTP(w http.ResponseWriter, r *http.Request) {
}

func init() {
	if customEncoderName != "" {
		err := zap.RegisterEncoder(customEncoderName, func(cfg zapcore.EncoderConfig) (zapcore.Encoder, error) {
			return NewCustomEncoder(cfg), nil
		})
		if err != nil {
			panic(err)
		}
	}
}
