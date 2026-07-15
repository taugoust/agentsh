package api

import (
	"strings"
	"testing"
)

func TestReadTextLineWindow_PaginatesWithoutLoadingPrefix(t *testing.T) {
	window, err := readTextLineWindow(strings.NewReader("one\ntwo\nthree\nfour\n"), 2, 2, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(window.Content); got != "two\nthree\n" {
		t.Fatalf("content = %q", got)
	}
	if !window.Truncated || window.NextOffset != 4 || window.ByteTruncated {
		t.Fatalf("window metadata = %+v", window)
	}
	if window.StartLine != 2 || window.EndLine != 3 {
		t.Fatalf("line metadata = %+v", window)
	}
}

func TestReadTextLineWindow_ByteBoundAndLongLine(t *testing.T) {
	window, err := readTextLineWindow(strings.NewReader(strings.Repeat("x", 100)+"\ntail\n"), 1, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(window.Content) != 16 || !window.Truncated || !window.ByteTruncated || window.NextOffset != 0 {
		t.Fatalf("long-line window = %+v", window)
	}
}

func TestReadTextLineWindow_ContinuesAtNextLineAfterByteBoundary(t *testing.T) {
	window, err := readTextLineWindow(strings.NewReader("1234\nnext\n"), 1, 10, 5)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(window.Content); got != "1234\n" {
		t.Fatalf("content = %q", got)
	}
	if !window.Truncated || window.ByteTruncated || window.NextOffset != 2 {
		t.Fatalf("window metadata = %+v", window)
	}
}
