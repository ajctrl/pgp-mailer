package config

import (
	"errors"
	"regexp"
	"strings"
	"text/template"
	"unicode"
)

// Spaces are optional around the field and the pipe.
var subjectPlaceholder = regexp.MustCompile(`^ *(\.Title|\.Level( *\| *(upper|lower))?) *$`)

func parseSubjectTemplate(format string) (*template.Template, error) {
	if strings.TrimSpace(format) == "" || strings.IndexFunc(format, unicode.IsControl) >= 0 || strings.ContainsAny(format, "\u2028\u2029") {
		return nil, errors.New("expected nonblank single-line text without control characters")
	}
	for rest := format; ; {
		literal, action, found := strings.Cut(rest, "{{")
		if strings.Contains(literal, "}}") {
			return nil, errors.New("unexpected closing delimiter")
		}
		if !found {
			break
		}
		field, tail, closed := strings.Cut(action, "}}")
		if !closed || !subjectPlaceholder.MatchString(field) {
			return nil, errors.New("expected {{.Title}}, {{.Level}}, {{.Level | upper}}, or {{.Level | lower}}")
		}
		rest = tail
	}
	return template.New("subject").Funcs(template.FuncMap{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
	}).Parse(format)
}
