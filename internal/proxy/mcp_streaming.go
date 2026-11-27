package proxy

import (
	"strings"
)

// sseMaxLineSize is the maximum size of a single SSE line. The default
// bufio.Scanner limit is 64KB which could truncate very large SSE data
// lines (e.g., tool calls with large arguments). We use 256KB.
const sseMaxLineSize = 256 * 1024

// extractSSEData extracts the JSON payload from an SSE data line.
// Handles both "data: {...}" (with space) and "data:{...}" (without space)
// per the SSE specification. Returns empty string for non-data lines.
func extractSSEData(line string) (string, bool) {
	if strings.HasPrefix(line, "data: ") {
		return line[len("data: "):], true
	}
	if strings.HasPrefix(line, "data:") {
		return line[len("data:"):], true
	}
	return "", false
}
