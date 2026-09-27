package tun

import (
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	"go.uber.org/zap"
)

var _ logger.Logger = (*singLogger)(nil)

// singLogger adapts zap to the logger interface of sing-tun, which builds
// messages by concatenating its arguments.
type singLogger struct {
	tag       string
	zapLogger *zap.Logger
}

func (l *singLogger) Trace(args ...any) {
	l.zapLogger.Debug(l.tag, zap.String("args", F.ToString(args...)))
}

func (l *singLogger) Debug(args ...any) {
	l.zapLogger.Debug(l.tag, zap.String("args", F.ToString(args...)))
}

func (l *singLogger) Info(args ...any) {
	l.zapLogger.Info(l.tag, zap.String("args", F.ToString(args...)))
}

func (l *singLogger) Warn(args ...any) {
	l.zapLogger.Warn(l.tag, zap.String("args", F.ToString(args...)))
}

func (l *singLogger) Error(args ...any) {
	l.zapLogger.Error(l.tag, zap.String("args", F.ToString(args...)))
}

func (l *singLogger) Fatal(args ...any) {
	l.zapLogger.Fatal(l.tag, zap.String("args", F.ToString(args...)))
}

func (l *singLogger) Panic(args ...any) {
	l.zapLogger.Panic(l.tag, zap.String("args", F.ToString(args...)))
}
