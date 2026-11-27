package ancestry

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifier_Classify(t *testing.T) {
	c := NewClassifier()

	tests := []struct {
		comm string
		want ProcessClass
	}{
		// Shells
		{"bash", ClassShell},
		{"zsh", ClassShell},
		{"fish", ClassShell},
		{"sh", ClassShell},

		// Editors
		{"vim", ClassEditor},
		{"nvim", ClassEditor},
		{"code", ClassEditor},
		{"cursor", ClassEditor},

		// Build tools
		{"npm", ClassBuildTool},
		{"cargo", ClassBuildTool},
		{"go", ClassBuildTool},
		{"make", ClassBuildTool},

		// Language servers
		{"gopls", ClassLanguageServer},
		{"tsserver", ClassLanguageServer},
		{"rust-analyzer", ClassLanguageServer},

		// Language runtimes
		{"node", ClassLanguageRuntime},
		{"python", ClassLanguageRuntime},
		{"python3", ClassLanguageRuntime},
		{"ruby", ClassLanguageRuntime},

		// Unknown
		{"myprocess", ClassUnknown},
		{"unknown-thing", ClassUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.comm, func(t *testing.T) {
			got := c.Classify(tt.comm)
			assert.Equal(t, tt.want, got, "Classify(%q)", tt.comm)
		})
	}
}

func TestClassifier_ClassifyWithGlob(t *testing.T) {
	c := NewClassifier()

	// Language server patterns include "*-language-server"
	tests := []struct {
		comm string
		want ProcessClass
	}{
		{"typescript-language-server", ClassLanguageServer},
		{"rust-language-server", ClassLanguageServer},
		{"yaml-language-server", ClassLanguageServer},
	}

	for _, tt := range tests {
		t.Run(tt.comm, func(t *testing.T) {
			got := c.Classify(tt.comm)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClassifier_CustomRules(t *testing.T) {
	c := NewClassifier()

	// Add custom rule
	c.AddCustomRule("my-agent", ClassAgent)
	assert.Equal(t, ClassAgent, c.Classify("my-agent"))

	// Custom rule takes precedence
	c.AddCustomRule("bash", ClassAgent) // Override built-in
	assert.Equal(t, ClassAgent, c.Classify("bash"))

	// Remove custom rule
	c.RemoveCustomRule("bash")
	assert.Equal(t, ClassShell, c.Classify("bash"))
}

func TestClassifyProcess_Default(t *testing.T) {
	// Test the convenience function
	assert.Equal(t, ClassShell, ClassifyProcess("bash"))
	assert.Equal(t, ClassEditor, ClassifyProcess("vim"))
}

func TestCountConsecutive(t *testing.T) {
	tests := []struct {
		name    string
		classes []ProcessClass
		target  ProcessClass
		want    int
	}{
		{
			name:    "none",
			classes: []ProcessClass{ClassEditor, ClassBuildTool},
			target:  ClassShell,
			want:    0,
		},
		{
			name:    "scattered",
			classes: []ProcessClass{ClassShell, ClassEditor, ClassShell},
			target:  ClassShell,
			want:    1,
		},
		{
			name:    "consecutive",
			classes: []ProcessClass{ClassShell, ClassShell, ClassShell},
			target:  ClassShell,
			want:    3,
		},
		{
			name:    "max at end",
			classes: []ProcessClass{ClassShell, ClassEditor, ClassShell, ClassShell},
			target:  ClassShell,
			want:    2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, CountConsecutive(tt.classes, tt.target))
		})
	}
}

func TestCountConsecutiveComm(t *testing.T) {
	via := []string{"bash", "bash", "npm", "bash", "bash", "bash"}

	assert.Equal(t, 3, CountConsecutiveComm(via, []string{"bash"}))
	assert.Equal(t, 1, CountConsecutiveComm(via, []string{"npm"}))
	assert.Equal(t, 0, CountConsecutiveComm(via, []string{"python"}))
}
