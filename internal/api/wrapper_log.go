package api

import (
	"bufio"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const (
	maxWrapperDiagnosticLines = 4
	maxWrapperDiagnosticBytes = 1024
)

var (
	wrapperAuthRE   = regexp.MustCompile(`(?i)(authorization[=: ]+(?:bearer|basic)[ ]+)[^ ]+`)
	wrapperSecretRE = regexp.MustCompile(`(?i)((?:access[_-]?token|api[_-]?key|token|secret|signature|password)[=:])[^	 ,;]+`)
	wrapperQueryRE  = regexp.MustCompile(`(?i)([?&](?:access_token|api[_-]?key|key|token|secret|signature|sig|password)=)[^&# ]*`)
	wrapperPathRE   = regexp.MustCompile(`(^|[ =])/[^	 ,;]+`)
)

// closeWrapperLogPipe releases both wrapper-log pipe ends on exec paths
// that fail before startWrapperHandlers runs (pre-start cancel,
// cmd.Start() failure). Safe to call multiple times and on configs
// without a log pipe.
func (e *extraProcConfig) closeWrapperLogPipe() {
	if e == nil {
		return
	}
	if e.wrapperLogChild != nil {
		_ = e.wrapperLogChild.Close()
		e.wrapperLogChild = nil
	}
	if e.wrapperLogParent != nil {
		_ = e.wrapperLogParent.Close()
		e.wrapperLogParent = nil
	}
}

type wrapperLogCapture struct {
	done chan struct{}

	mu    sync.Mutex
	lines []string
}

func newWrapperLogCapture() *wrapperLogCapture {
	return &wrapperLogCapture{done: make(chan struct{})}
}

func (c *wrapperLogCapture) record(line string) {
	if c == nil || !strings.Contains(strings.ToLower(line), "command jail") {
		return
	}
	line = sanitizeWrapperDiagnostic(line)
	if line == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, line)
	if len(c.lines) > maxWrapperDiagnosticLines {
		c.lines = append([]string(nil), c.lines[len(c.lines)-maxWrapperDiagnosticLines:]...)
	}
	for len(strings.Join(c.lines, " | ")) > maxWrapperDiagnosticBytes && len(c.lines) > 1 {
		c.lines = c.lines[1:]
	}
}

func (c *wrapperLogCapture) tail() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.lines, " | ")
}

func sanitizeWrapperDiagnostic(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\t' {
			return -1
		}
		return r
	}, value)
	value = wrapperAuthRE.ReplaceAllString(value, `${1}[REDACTED]`)
	value = wrapperSecretRE.ReplaceAllString(value, `${1}[REDACTED]`)
	value = wrapperQueryRE.ReplaceAllString(value, `${1}[REDACTED]`)
	value = wrapperPathRE.ReplaceAllString(value, `${1}[path]`)
	value = strings.TrimSpace(value)
	for len(value) > maxWrapperDiagnosticBytes {
		_, size := utf8.DecodeLastRuneInString(value)
		value = value[:len(value)-size]
	}
	return value
}

// startWrapperLogCaptureDrain forwards agentsh-unixwrap diagnostics to the
// operator log and retains only a small sanitized command-jail fatal tail for
// typed pre-GO failure evidence. The capture closes after the pipe reaches EOF.
func startWrapperLogCaptureDrain(r *os.File, logger *slog.Logger, sessionID, command string) *wrapperLogCapture {
	capture := newWrapperLogCapture()
	go func() {
		defer close(capture.done)
		defer r.Close()
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := sc.Text()
			logger.Info("unixwrap", "session_id", sessionID, "command", command, "line", line)
			capture.record(line)
		}
		if err := sc.Err(); err != nil {
			logger.Debug("unixwrap log drain stopped early", "session_id", sessionID, "error", err)
		}
	}()
	return capture
}

// startWrapperLogDrain preserves the original test/helper API.
func startWrapperLogDrain(r *os.File, logger *slog.Logger, sessionID, command string) <-chan struct{} {
	return startWrapperLogCaptureDrain(r, logger, sessionID, command).done
}
