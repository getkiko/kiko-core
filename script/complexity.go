package script

import (
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// SourceLimits bound the shape of script source before it is parsed. The parser and compiler
// of goja recurse per nesting level (a deep source overflows the Go stack, which kills the
// process) and some constructs compile in quadratic time (a chain of 50000 "1+" takes
// seconds), so sources are measured first.
type SourceLimits struct {
	// Length is the longest source in bytes.
	Length int
	// Depth is the deepest bracket nesting.
	Depth int
	// Chain is the most operators (and call, index and template openings) in one operand
	// sequence: between commas, semicolons and braces at one bracket level.
	Chain int
	// Openers is the most "(", "[" and "{" bytes anywhere in the source, strings, comments
	// and regular expressions included. The nesting depth of any reading of the source is at
	// most this, so it bounds the parser's stack even if the scan misreads the source.
	Openers int
	// Operators is the most operator bytes anywhere in the source, counted the same way. It
	// bounds the compile time of a chain the scan did not see.
	Operators int
}

var (
	// ScriptLimits apply to the source of a script.
	ScriptLimits = SourceLimits{Length: MaxSourceSize, Depth: MaxSourceDepth, Chain: 5000, Openers: 100000, Operators: 500000}
	// EvalLimits apply to what eval and the Function constructors are given. Their compile
	// cannot be abandoned, so the totals are small.
	EvalLimits = SourceLimits{Length: 64 << 10, Depth: 300, Chain: 1000, Openers: 10000, Operators: 12000}
)

// exprWords are the keywords after which an expression follows, so a "/" starts a regular
// expression.
var exprWords = map[string]bool{
	"typeof": true, "void": true, "new": true, "delete": true,
	"in": true, "instanceof": true, "return": true, "case": true, "throw": true,
}

// controlWords are followed by a parenthesised head and then a statement.
var controlWords = map[string]bool{"if": true, "while": true, "for": true, "with": true, "catch": true, "switch": true}

// blockWords are followed by a statement or block.
var blockWords = map[string]bool{"else": true, "do": true, "try": true, "finally": true}

// softWords can be a keyword or a name: a "/" after them may be either.
var softWords = map[string]bool{"of": true, "yield": true, "await": true}

// token classes remembered between tokens; they decide what a "/" and a "{" mean.
const (
	tokStart    byte = 'S' // statement start: file start, ";", "{", the "}" of a block
	tokExpr     byte = 'E' // an expression is expected: operator, "(", "[", ",", keyword
	tokColon    byte = ':' // a label, a case, a property or the else of a conditional
	tokArrow    byte = 'A' // "=>"
	tokControl  byte = 'C' // the ")" of an if, while, for, with, catch or switch head
	tokFnExpr   byte = 'F' // the ")" of the parameters of a function expression
	tokFnDecl   byte = 'D' // the ")" of the parameters of a function declaration
	tokParen    byte = 'P' // any other ")"
	tokOperand  byte = 'V' // identifier, number, string, regular expression, "]", the "}" of an expression
	tokBlockKw  byte = 'B' // else, do, try, finally
	tokAmbigous byte = 'X' // a soft keyword, or a "}" whose kind is unknown
)

// slashAfter reports how a "/" reads after a token of class prev.
func slashAfter(prev byte) slashMode {
	switch prev {
	case tokOperand, tokFnExpr, tokFnDecl, tokParen:
		return slashDivision
	case tokAmbigous:
		return slashAmbiguous
	}
	return slashRegex
}

// slashMode is what a "/" means at this point of the source.
type slashMode uint8

const (
	slashDivision  slashMode = iota // after an operand
	slashRegex                      // after an operator, "(" or a keyword
	slashAmbiguous                  // after a soft keyword or a "}" of unknown kind
)

type level struct {
	kind  byte // 0 base, '(' '[' '{', '$' for a ${ } of a template literal
	chain int
	// fn is set on a "(" : tokControl, tokFnExpr or tokFnDecl for the heads that decide what
	// follows the ")".
	fn byte
	// after is the class a "}" gets when it closes this "{".
	after byte
}

// scanState is one reading of the source. The meaning of a "/" is decided by the tokens
// before it; where they leave it open, the scan follows both readings.
type scanState struct {
	pos       int
	prev      byte
	prevDot   bool
	pendingFn byte // tokFnExpr or tokFnDecl between the function keyword and its "("
	control   bool // the previous word was if, while, for, with, catch or switch
	classHdr  bool // between the class keyword and its "{"
	classStmt bool // that class is a declaration
	asyncStmt bool // the async keyword stood at a statement start
	wasAsync  bool // the previous word was async
	levels    []level
}

func (s *scanState) clone() *scanState {
	c := *s
	c.levels = append(make([]level, 0, len(s.levels)+8), s.levels...)
	return &c
}

func (s *scanState) key() string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(s.pos))
	b.WriteByte(s.prev)
	b.WriteByte(s.pendingFn)
	for _, v := range []bool{s.prevDot, s.control, s.classHdr, s.classStmt, s.asyncStmt, s.wasAsync} {
		if v {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
	}
	for _, lv := range s.levels {
		b.WriteByte(lv.kind)
		b.WriteByte(lv.fn)
		b.WriteByte(lv.after)
		b.WriteString(strconv.Itoa(lv.chain))
		b.WriteByte(',')
	}
	return b.String()
}

// CheckSource reports why src is too large or too deeply built to be parsed safely. It is a
// scan, not a parse: strings, comments, templates and regular expression literals are
// skipped, brackets are matched, and operators are counted. The tokens before a "/" decide
// whether it divides or starts a regular expression; where they leave it open, every reading
// is followed and the worst one counts. A reading that does not form a program (unmatched
// brackets, an unterminated string or regular expression) is dropped, and a source with no
// reading left is refused. rawGuard backs the scan with totals that do not depend on how the
// source reads.
func CheckSource(src string, l SourceLimits) error {
	if len(src) > l.Length {
		return E.New("source larger than ", l.Length, " bytes")
	}
	if err := rawGuard(src, l); err != nil {
		return err
	}
	budget := 16*len(src) + 4096
	first := &scanState{levels: []level{{}}, prev: tokStart}
	work := []*scanState{first}
	seen := map[string]bool{first.key(): true}
	finished := false
	var firstDeath error
	for len(work) > 0 {
		st := work[len(work)-1]
		work = work[:len(work)-1]
		err, dead := runState(src, l, st, &budget, seen, &work)
		if err != nil {
			return err
		}
		if dead != nil {
			if firstDeath == nil {
				firstDeath = dead
			}
			continue
		}
		finished = true
	}
	if !finished {
		return firstDeath
	}
	return nil
}

// runState scans one reading to the end of the source. The readings it splits off are added
// to work. It returns a limit violation (err), or why this reading is not a program (dead).
func runState(src string, l SourceLimits, st *scanState, budget *int, seen map[string]bool, work *[]*scanState) (err error, dead error) {
	line := func(i int) int { return 1 + strings.Count(src[:min(i, len(src))], "\n") }
	die := func(i int, why string) error {
		return E.New("source line ", line(i), ": ", why)
	}
	top := func() *level { return &st.levels[len(st.levels)-1] }
	bump := func() error {
		t := top()
		t.chain++
		if t.chain > l.Chain {
			return E.New("source has an expression chain longer than ", l.Chain)
		}
		return nil
	}
	push := func(lv level) error {
		if len(st.levels) > l.Depth {
			return E.New("source is nested more deeply than ", l.Depth)
		}
		st.levels = append(st.levels, lv)
		return nil
	}
	pop := func(closer byte) (level, bool) {
		if len(st.levels) <= 1 {
			return level{}, false
		}
		lv := st.levels[len(st.levels)-1]
		ok := lv.kind == '(' && closer == ')' || lv.kind == '[' && closer == ']' || (lv.kind == '{' || lv.kind == '$') && closer == '}'
		if !ok {
			return level{}, false
		}
		st.levels = st.levels[:len(st.levels)-1]
		return lv, true
	}
	// scanTemplate skips template text from i up to the closing backtick (returns its index)
	// or to a "${" (returns the index of "{" and true).
	scanTemplate := func(i int) (int, bool, bool) {
		for ; i < len(src); i++ {
			switch src[i] {
			case '\\':
				i++
			case '`':
				return i, false, true
			case '$':
				if i+1 < len(src) && src[i+1] == '{' {
					return i + 1, true, true
				}
			}
		}
		return i, false, false
	}
	afterTemplate := func(expr bool) error {
		if expr {
			st.prev = tokExpr
			return push(level{kind: '$'})
		}
		st.prev = tokOperand
		return nil
	}
	isWord := func(c byte) bool {
		return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
	}
	// braceAfter is the class the "}" of a "{" gets, from the token before the "{".
	braceAfter := func() byte {
		switch st.prev {
		case tokStart, tokControl, tokBlockKw, tokFnDecl:
			return tokStart // a block or a declaration body: a statement follows
		case tokFnExpr, tokArrow, tokExpr, tokParen:
			return tokOperand // an expression: the body of a function expression, an object
		case tokOperand:
			if st.classHdr {
				if st.classStmt {
					return tokStart
				}
				return tokOperand
			}
		}
		return tokAmbigous
	}
	for i := st.pos; i < len(src); i++ {
		*budget--
		if *budget < 0 {
			return E.New("source is too ambiguous to check"), nil
		}
		c := src[i]
		prevDot := st.prevDot
		control := st.control
		wasAsync := st.wasAsync
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			continue
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return nil, die(i, "unterminated comment")
			}
			i += end + 3
			continue
		}
		st.prevDot, st.control, st.wasAsync = false, false, false
		switch {
		case c == '"' || c == '\'':
			start := i
			closed := false
			for i++; i < len(src) && src[i] != '\n'; i++ {
				if src[i] == '\\' {
					i++
					continue
				}
				if src[i] == c {
					closed = true
					break
				}
			}
			if !closed {
				return nil, die(start, "unterminated string")
			}
			st.prev = tokOperand
		case c == '`':
			if err := bump(); err != nil {
				return err, nil
			}
			start := i
			end, expr, ok := scanTemplate(i + 1)
			if !ok {
				return nil, die(start, "unterminated template")
			}
			i = end
			if err := afterTemplate(expr); err != nil {
				return err, nil
			}
		case c == '/':
			mode := slashAfter(st.prev)
			if mode == slashRegex {
				end, ok := scanRegex(src, i)
				if !ok {
					return nil, die(i, "unterminated regular expression")
				}
				*budget -= end - i
				i = end
				st.prev = tokOperand
				break
			}
			if mode == slashAmbiguous {
				if end, ok := scanRegex(src, i); ok {
					alt := st.clone()
					alt.pos, alt.prev = end+1, tokOperand
					if k := alt.key(); !seen[k] {
						seen[k] = true
						*work = append(*work, alt)
					}
				}
			}
			if err := bump(); err != nil {
				return err, nil
			}
			st.prev = tokExpr
		case c == '(' || c == '[':
			if err := bump(); err != nil {
				return err, nil
			}
			lv := level{kind: c}
			if c == '(' {
				switch {
				case st.pendingFn != 0:
					lv.fn, st.pendingFn = st.pendingFn, 0
				case control:
					lv.fn = tokControl
				}
			}
			if err := push(lv); err != nil {
				return err, nil
			}
			st.prev = tokExpr
		case c == '{':
			if err := push(level{kind: '{', after: braceAfter()}); err != nil {
				return err, nil
			}
			st.prev, st.classHdr, st.pendingFn = tokStart, false, 0
		case c == ')' || c == ']':
			lv, ok := pop(c)
			if !ok {
				return nil, die(i, "unmatched bracket")
			}
			st.prev = tokOperand
			if c == ')' {
				st.prev = tokParen
				if lv.fn != 0 {
					st.prev = lv.fn
				}
			}
		case c == '}':
			wasTemplate := len(st.levels) > 1 && top().kind == '$'
			lv, ok := pop(c)
			if !ok {
				return nil, die(i, "unmatched bracket")
			}
			st.prev = lv.after
			if wasTemplate {
				start := i
				end, expr, ok := scanTemplate(i + 1)
				if !ok {
					return nil, die(start, "unterminated template")
				}
				i = end
				if err := afterTemplate(expr); err != nil {
					return err, nil
				}
			} else if st.prev == 0 {
				st.prev = tokAmbigous
			}
		case c == ',':
			top().chain = 0
			st.prev = tokExpr
		case c == ';':
			top().chain = 0
			st.prev, st.pendingFn = tokStart, 0
		case c == '.':
			if err := bump(); err != nil {
				return err, nil
			}
			if i+1 < len(src) && src[i+1] >= '0' && src[i+1] <= '9' {
				// A number such as .5.
				st.prev = tokOperand
			} else {
				st.prev = tokExpr
				st.prevDot = true
			}
		case (c == '+' || c == '-') && i+1 < len(src) && src[i+1] == c:
			if err := bump(); err != nil {
				return err, nil
			}
			i++
			// A postfix operator follows an operand and leaves one; a prefix one wants one.
			if st.prev != tokOperand && st.prev != tokParen {
				st.prev = tokExpr
			} else {
				st.prev = tokOperand
			}
		case strings.IndexByte("+-*%&|^<>=?:!~", c) >= 0:
			if err := bump(); err != nil {
				return err, nil
			}
			st.prev = tokExpr
			if c == '>' && i > 0 && src[i-1] == '=' {
				st.prev = tokArrow
			} else if c == ':' {
				st.prev = tokColon
			}
		case isWord(c):
			j := i
			for j < len(src) && isWord(src[j]) {
				j++
			}
			word := src[i:j]
			i = j - 1
			if prevDot {
				// A property name: never a keyword.
				st.prev = tokOperand
				break
			}
			statement := st.prev == tokStart
			switch {
			case exprWords[word]:
				if err := bump(); err != nil {
					return err, nil
				}
				st.prev = tokExpr
			case controlWords[word]:
				if err := bump(); err != nil {
					return err, nil
				}
				st.prev, st.control = tokExpr, true
			case blockWords[word]:
				st.prev = tokBlockKw
			case softWords[word]:
				if err := bump(); err != nil {
					return err, nil
				}
				st.prev = tokAmbigous
			case word == "function":
				if wasAsync {
					statement = st.asyncStmt
				}
				st.pendingFn = tokFnExpr
				if statement {
					st.pendingFn = tokFnDecl
				}
				st.prev = tokOperand
			case word == "class":
				st.classHdr, st.classStmt = true, statement
				st.prev = tokOperand
			case word == "async":
				st.asyncStmt, st.wasAsync = statement, true
				st.prev = tokOperand
			default:
				st.prev = tokOperand
			}
		}
	}
	if len(st.levels) != 1 {
		return nil, die(len(src), "unclosed bracket")
	}
	return nil, nil
}

// scanRegex returns the index of the last byte of the regular expression literal (flags
// included) that starts at src[i] == '/'. It fails at a line end or the end of the source.
func scanRegex(src string, i int) (int, bool) {
	inClass := false
	for j := i + 1; j < len(src); j++ {
		switch src[j] {
		case '\\':
			j++
		case '\n', '\r':
			return 0, false
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if inClass {
				continue
			}
			j++
			for j < len(src) && (src[j] == '_' || src[j] == '$' || src[j] >= 'a' && src[j] <= 'z' || src[j] >= 'A' && src[j] <= 'Z' || src[j] >= '0' && src[j] <= '9') {
				j++
			}
			return j - 1, true
		}
	}
	return 0, false
}

// rawGuard is the part of the check that does not depend on how the source tokenizes: it
// counts every opening bracket and operator byte, strings and regular expressions included,
// so a source that fools the scan above still cannot nest deeply or chain without bound.
func rawGuard(src string, l SourceLimits) error {
	openers, operators := 0, 0
	for i := 0; i < len(src); i++ {
		switch src[i] {
		case '(', '[', '{':
			openers++
			if openers > l.Openers {
				return E.New("source has more than ", l.Openers, " opening brackets")
			}
		case '+', '-', '*', '/', '%', '&', '|', '^', '<', '>', '=', '?', ':', '!', '~':
			operators++
			if operators > l.Operators {
				return E.New("source has more than ", l.Operators, " operators")
			}
		}
	}
	return nil
}
