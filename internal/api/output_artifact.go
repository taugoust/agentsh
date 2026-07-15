package api

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

const maxOutputArtifactPresentationThreshold = 2 * 1024 * 1024

// commandOutputArtifactCapture retains a small pre-threshold prefix in memory,
// then lazily spills the combined stdout/stderr stream to a bounded remote
// session artifact. A single mutex preserves the order in which concurrent
// stream writes reach AgentSH.
type commandOutputArtifactCapture struct {
	mu sync.Mutex

	session        *session.Session
	name           string
	thresholdBytes int64
	thresholdLines int64

	pending        bytes.Buffer
	sourceBytes    int64
	completedLines int64
	hasOpenLine    bool
	triggered      bool
	finished       bool

	writer   *session.OutputArtifactWriter
	firstErr error
}

func validateOutputArtifactRequest(req *types.OutputArtifactRequest) error {
	if req == nil {
		return nil
	}
	if req.PersistOverBytes <= 0 {
		return fmt.Errorf("output artifact byte threshold must be positive")
	}
	if req.PersistOverLines < 0 {
		return fmt.Errorf("output artifact line threshold must be non-negative")
	}
	if req.PersistOverBytes > maxOutputArtifactPresentationThreshold {
		return fmt.Errorf("output artifact byte threshold exceeds %d", maxOutputArtifactPresentationThreshold)
	}
	if req.PersistOverLines > 1_000_000 {
		return fmt.Errorf("output artifact line threshold exceeds 1000000")
	}
	return nil
}

func newCommandOutputArtifactCapture(s *session.Session, commandID string, req *types.OutputArtifactRequest) *commandOutputArtifactCapture {
	if s == nil || req == nil || (req.PersistOverBytes == 0 && req.PersistOverLines == 0) {
		return nil
	}
	return &commandOutputArtifactCapture{
		session:        s,
		name:           "bash-" + commandID + ".log",
		thresholdBytes: req.PersistOverBytes,
		thresholdLines: req.PersistOverLines,
	}
}

func (c *commandOutputArtifactCapture) Append(p []byte) error {
	if c == nil || len(p) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finished {
		return nil
	}

	c.sourceBytes += int64(len(p))
	for _, b := range p {
		if b == '\n' {
			c.completedLines++
			c.hasOpenLine = false
		} else {
			c.hasOpenLine = true
		}
	}
	lineCount := c.completedLines
	if c.hasOpenLine {
		lineCount++
	}
	if !c.triggered {
		c.triggered = (c.thresholdBytes > 0 && c.sourceBytes > c.thresholdBytes) ||
			(c.thresholdLines > 0 && lineCount > c.thresholdLines)
		if c.triggered {
			writer, err := c.session.NewOutputArtifactWriter(c.name)
			if err != nil {
				c.firstErr = err
				c.pending.Reset()
				return nil
			}
			c.writer = writer
			if c.pending.Len() > 0 {
				if _, err := c.writer.Write(c.pending.Bytes()); err != nil {
					c.firstErr = err
				}
				c.pending.Reset()
			}
		}
	}

	if !c.triggered {
		_, _ = c.pending.Write(p)
		return nil
	}
	if c.writer == nil || c.firstErr != nil {
		return nil
	}
	if _, err := c.writer.Write(p); err != nil {
		c.firstErr = err
	}
	return nil
}

func (c *commandOutputArtifactCapture) Finish() *types.OutputArtifactResult {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finished {
		return nil
	}
	c.finished = true
	c.pending.Reset()
	if !c.triggered {
		return nil
	}
	if c.writer == nil {
		return &types.OutputArtifactResult{
			TotalBytes:   c.sourceBytes,
			Complete:     false,
			ErrorMessage: boundedOutputArtifactError(c.firstErr),
		}
	}
	artifact, err := c.writer.Finish()
	if c.firstErr == nil {
		c.firstErr = err
	}
	if c.firstErr != nil {
		return &types.OutputArtifactResult{
			TotalBytes:   c.sourceBytes,
			Complete:     false,
			ErrorMessage: boundedOutputArtifactError(c.firstErr),
		}
	}
	return &types.OutputArtifactResult{
		Path:       artifact.Path,
		Bytes:      artifact.BytesWritten,
		TotalBytes: c.sourceBytes,
		Complete:   artifact.BytesWritten == c.sourceBytes,
	}
}

func boundedOutputArtifactError(err error) string {
	if err == nil {
		return "output artifact unavailable"
	}
	value := strings.TrimSpace(err.Error())
	const maxBytes = 1024
	if len(value) <= maxBytes {
		return value
	}
	return value[:maxBytes] + "…"
}
