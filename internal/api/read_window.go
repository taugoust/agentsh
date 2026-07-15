package api

import (
	"bufio"
	"errors"
	"io"
)

type textLineWindow struct {
	Content       []byte
	StartLine     int
	EndLine       int
	NextOffset    int
	Truncated     bool
	ByteTruncated bool
}

// readTextLineWindow reads a one-indexed line window without loading the whole
// file. It bounds retained bytes even for a single very long line. A byte-trunc-
// ated line cannot be resumed by line offset, so callers should recommend a
// supervised shell byte-range command in that exceptional case.
func readTextLineWindow(src io.Reader, offset, limit int, maxBytes int64) (textLineWindow, error) {
	if offset <= 0 {
		offset = 1
	}
	if limit <= 0 {
		limit = 2000
	}
	if maxBytes <= 0 {
		maxBytes = defaultToolReadLimitBytes
	}
	window := textLineWindow{StartLine: offset, EndLine: offset - 1}
	reader := bufio.NewReader(src)
	lineNumber := 1
	selectedLines := 0

	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) == 0 && errors.Is(err, io.EOF) {
			break
		}
		lineComplete := err == nil || errors.Is(err, io.EOF)
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) && !errors.Is(err, io.EOF) {
			return textLineWindow{}, err
		}

		if lineNumber >= offset {
			if selectedLines >= limit {
				window.Truncated = true
				window.NextOffset = lineNumber
				break
			}
			remaining := maxBytes - int64(len(window.Content))
			if remaining <= 0 {
				window.Truncated = true
				if window.EndLine < lineNumber {
					window.NextOffset = lineNumber
				} else {
					window.ByteTruncated = true
				}
				break
			}
			if int64(len(fragment)) > remaining {
				window.Content = append(window.Content, fragment[:remaining]...)
				window.Truncated = true
				window.ByteTruncated = true
				window.EndLine = lineNumber
				break
			}
			window.Content = append(window.Content, fragment...)
			window.EndLine = lineNumber
		}

		if lineComplete {
			if lineNumber >= offset {
				selectedLines++
			}
			lineNumber++
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return window, nil
}
