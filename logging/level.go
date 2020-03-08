package logging

import "fmt"

type level uint8

// loglevels
const (
	_ level = iota
	TRACE
	DEBUG
	INFO
	WARNING
	ERROR
	FATAL
)

// String returns a string value of log level.
func (l level) String() string {
	switch l {
	case TRACE:
		return "TRACE"
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARNING:
		return "WARNING"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	}
	return fmt.Sprintf("level(%d)", l)
}
