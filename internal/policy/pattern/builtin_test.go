package pattern

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinClasses_Defined(t *testing.T) {
	// Verify essential classes are defined
	essentialClasses := []string{
		"shell",
		"editor",
		"agent",
		"build",
		"language-server",
		"runtime",
	}

	for _, class := range essentialClasses {
		t.Run(class, func(t *testing.T) {
			patterns, ok := BuiltinClasses[class]
			assert.True(t, ok, "class @%s should be defined", class)
			assert.NotEmpty(t, patterns, "class @%s should have patterns", class)
		})
	}
}

func TestIsBuiltinClass(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"shell", true},
		{"@shell", true},
		{"editor", true},
		{"@editor", true},
		{"nonexistent", false},
		{"@nonexistent", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsBuiltinClass(tt.name))
		})
	}
}

func TestClassRegistry_Get(t *testing.T) {
	r := NewClassRegistry()

	// Get existing class
	patterns, err := r.Get("shell")
	require.NoError(t, err)
	assert.Contains(t, patterns, "bash")

	// Get nonexistent class
	_, err = r.Get("nonexistent")
	assert.Error(t, err)
}

func TestClassRegistry_Has(t *testing.T) {
	r := NewClassRegistry()

	assert.True(t, r.Has("shell"))
	assert.True(t, r.Has("editor"))
	assert.False(t, r.Has("nonexistent"))
}

func TestClassRegistry_Matches(t *testing.T) {
	r := NewClassRegistry()

	tests := []struct {
		class string
		input string
		want  bool
	}{
		{"shell", "bash", true},
		{"shell", "zsh", true},
		{"shell", "vim", false},
		{"editor", "vim", true},
		{"editor", "nvim", true},
		{"editor", "bash", false},
		{"build", "npm", true},
		{"build", "cargo", true},
		{"build", "vim", false},
	}

	for _, tt := range tests {
		t.Run(tt.class+"/"+tt.input, func(t *testing.T) {
			match, err := r.Matches(tt.class, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, match)
		})
	}
}

func TestClassRegistry_Matches_WithGlob(t *testing.T) {
	r := NewClassRegistry()

	// language-server class has glob patterns like "*-language-server"
	tests := []struct {
		input string
		want  bool
	}{
		{"typescript-language-server", true},
		{"rust-language-server", true},
		{"gopls", true},
		{"bash", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			match, err := r.Matches("language-server", tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, match)
		})
	}
}

func TestClassRegistry_Matches_NonexistentClass(t *testing.T) {
	r := NewClassRegistry()

	_, err := r.Matches("nonexistent", "anything")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown class")
}

func TestClassRegistry_GetResolver(t *testing.T) {
	r := NewClassRegistry()

	resolver := r.GetResolver()

	// Test with Pattern using the resolver
	p, err := Compile("@shell")
	require.NoError(t, err)

	match, err := p.MatchWithResolver("bash", resolver)
	require.NoError(t, err)
	assert.True(t, match)

	match, err = p.MatchWithResolver("vim", resolver)
	require.NoError(t, err)
	assert.False(t, match)
}

func TestClassRegistry_Isolation(t *testing.T) {
	// Ensure modifications to returned slices don't affect the registry
	r := NewClassRegistry()

	patterns, _ := r.Get("shell")
	originalLen := len(patterns)

	// Modify the returned slice
	patterns[0] = "modified"

	// Get again and verify it's unchanged
	patterns2, _ := r.Get("shell")
	assert.Len(t, patterns2, originalLen)
	assert.Contains(t, patterns2, "bash") // Original value still there
}

func TestDefaultRegistry(t *testing.T) {
	// DefaultRegistry should be initialized with built-in classes
	assert.True(t, DefaultRegistry.Has("shell"))
	assert.True(t, DefaultRegistry.Has("editor"))

	patterns, err := DefaultRegistry.Get("shell")
	require.NoError(t, err)
	assert.Contains(t, patterns, "bash")
}
