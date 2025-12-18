//go:build linux

package ping

type Logger interface {
	Debugf(msg string, v ...any)
	Infof(msg string, v ...any)
	Warnf(msg string, v ...any)
	Errorf(msg string, v ...any)
}

type NoopLogger struct{}

func (l NoopLogger) Debugf(msg string, v ...any) {}
func (l NoopLogger) Infof(msg string, v ...any)  {}
func (l NoopLogger) Warnf(msg string, v ...any)  {}
func (l NoopLogger) Errorf(msg string, v ...any) {}
