package rewrite

import (
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// Limits of the JSON editor.
const (
	maxJSONDepth    = 128
	maxJSONNodes    = 1 << 18
	maxPathSegments = 64
	maxPathUnion    = 64
)

type segKind uint8

const (
	segName       segKind = iota + 1 // .name or ['name']
	segIndex                         // [n]
	segWild                          // [*] or .*
	segUnionNames                    // ['a','b']
	segUnionIndex                    // [0,1]
	segDescend                       // ..name
)

type pathSeg struct {
	kind    segKind
	name    string
	index   int
	names   []string
	indexes []int
}

// jsonPath is a parsed JSONPath subset: $, .name, ['name'], [n] (negative from the end),
// [*], ..name and unions of names or indexes. Filters and slices are not supported.
type jsonPath struct {
	segs []pathSeg
}

const pathNameForbidden = ".[]'\"*,()?@<>=! \t\r\n:"

func parseJSONPath(s string) (*jsonPath, error) {
	if len(s) > maxPattern {
		return nil, E.New("path too long")
	}
	if s == "" || s[0] != '$' {
		return nil, E.New("path must start with $")
	}
	p := &jsonPath{}
	i := 1
	for i < len(s) {
		if len(p.segs) >= maxPathSegments {
			return nil, E.New("path has too many segments")
		}
		switch s[i] {
		case '.':
			if strings.HasPrefix(s[i:], "..") {
				i += 2
				if i < len(s) && s[i] == '[' {
					seg, next, err := parseBracket(s, i)
					if err != nil {
						return nil, err
					}
					if seg.kind != segName {
						return nil, E.New("recursive descent needs a name")
					}
					seg.kind = segDescend
					p.segs = append(p.segs, seg)
					i = next
					continue
				}
				name, next, err := readBareName(s, i)
				if err != nil {
					return nil, err
				}
				p.segs = append(p.segs, pathSeg{kind: segDescend, name: name})
				i = next
				continue
			}
			i++
			if i < len(s) && s[i] == '*' {
				p.segs = append(p.segs, pathSeg{kind: segWild})
				i++
				continue
			}
			name, next, err := readBareName(s, i)
			if err != nil {
				return nil, err
			}
			p.segs = append(p.segs, pathSeg{kind: segName, name: name})
			i = next
		case '[':
			seg, next, err := parseBracket(s, i)
			if err != nil {
				return nil, err
			}
			p.segs = append(p.segs, seg)
			i = next
		default:
			return nil, E.New("unexpected character ", strconv.Quote(string(s[i])), " at position ", i)
		}
	}
	return p, nil
}

func readBareName(s string, i int) (string, int, error) {
	start := i
	for i < len(s) && s[i] != '.' && s[i] != '[' {
		if strings.IndexByte(pathNameForbidden, s[i]) >= 0 || s[i] < ' ' || s[i] == 0x7f {
			return "", 0, E.New("unsupported character ", strconv.Quote(string(s[i])), " at position ", i)
		}
		i++
	}
	if i == start {
		return "", 0, E.New("empty name at position ", start)
	}
	return s[start:i], i, nil
}

// parseBracket parses [...] starting at s[i] == '['.
func parseBracket(s string, i int) (pathSeg, int, error) {
	i++
	skip := func() {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
	}
	var names []string
	var indexes []int
	wild := false
	count := 0
	for {
		skip()
		if i >= len(s) {
			return pathSeg{}, 0, E.New("unterminated [")
		}
		count++
		if count > maxPathUnion {
			return pathSeg{}, 0, E.New("union is too large")
		}
		switch c := s[i]; {
		case c == '*':
			wild = true
			i++
		case c == '\'' || c == '"':
			name, next, err := readQuoted(s, i)
			if err != nil {
				return pathSeg{}, 0, err
			}
			names = append(names, name)
			i = next
		case c == '-' || c >= '0' && c <= '9':
			start := i
			i++
			for i < len(s) && s[i] >= '0' && s[i] <= '9' {
				i++
			}
			n, err := strconv.Atoi(s[start:i])
			if err != nil {
				return pathSeg{}, 0, E.New("invalid index ", s[start:i])
			}
			indexes = append(indexes, n)
		case c == '?' || c == '(' || c == '@':
			return pathSeg{}, 0, E.New("filter expressions are not supported")
		default:
			return pathSeg{}, 0, E.New("unexpected character ", strconv.Quote(string(c)), " at position ", i)
		}
		skip()
		if i >= len(s) {
			return pathSeg{}, 0, E.New("unterminated [")
		}
		if s[i] == ':' {
			return pathSeg{}, 0, E.New("slices are not supported")
		}
		if s[i] == ',' {
			i++
			continue
		}
		if s[i] == ']' {
			i++
			break
		}
		return pathSeg{}, 0, E.New("unexpected character ", strconv.Quote(string(s[i])), " at position ", i)
	}
	kinds := 0
	for _, present := range []bool{wild, len(names) > 0, len(indexes) > 0} {
		if present {
			kinds++
		}
	}
	switch {
	case kinds != 1:
		return pathSeg{}, 0, E.New("a bracket holds either names or indexes")
	case wild:
		if count != 1 {
			return pathSeg{}, 0, E.New("* cannot be combined in a union")
		}
		return pathSeg{kind: segWild}, i, nil
	case len(names) == 1:
		return pathSeg{kind: segName, name: names[0]}, i, nil
	case len(names) > 1:
		return pathSeg{kind: segUnionNames, names: names}, i, nil
	case len(indexes) == 1:
		return pathSeg{kind: segIndex, index: indexes[0]}, i, nil
	default:
		return pathSeg{kind: segUnionIndex, indexes: indexes}, i, nil
	}
}

func readQuoted(s string, i int) (string, int, error) {
	quote := s[i]
	i++
	var b strings.Builder
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\\':
			i++
			if i >= len(s) {
				return "", 0, E.New("unterminated string")
			}
			b.WriteByte(s[i])
			i++
		case c == quote:
			return b.String(), i + 1, nil
		default:
			b.WriteByte(c)
			i++
		}
	}
	return "", 0, E.New("unterminated string")
}
