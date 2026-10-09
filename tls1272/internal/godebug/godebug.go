// Package godebug is a minimal stand-in for the standard library's
// internal/godebug package. All knobs report the empty string and
// IncNonDefault is a no-op, so every caller takes its default behavior.
package godebug

type Setting struct{ name string }

func New(name string) *Setting { return &Setting{name: name} }

func (s *Setting) Name() string { return s.name }

func (s *Setting) Value() string { return "" }

func (*Setting) IncNonDefault() {}
