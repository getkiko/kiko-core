package rewrite

import (
	"bytes"
	"encoding/json"
	"sort"
)

// jnode is a JSON value that remembers its source bytes. Untouched subtrees are written
// back verbatim, so numbers, string escapes and key order survive an edit exactly.
type jnode struct {
	kind  byte // 'o' object, 'a' array, 'v' scalar
	raw   []byte
	keys  [][]byte // raw key tokens, with quotes (objects)
	kids  []*jnode
	dirty bool
}

type jsonParser struct {
	src   []byte
	pos   int
	nodes *int
}

// parseJSON parses a complete JSON text. nodes counts values across calls and fails the
// parse past maxJSONNodes.
func parseJSON(src []byte, nodes *int) (*jnode, bool) {
	p := &jsonParser{src: src, nodes: nodes}
	p.skipSpace()
	n, ok := p.value(0)
	if !ok {
		return nil, false
	}
	p.skipSpace()
	if p.pos != len(p.src) {
		return nil, false
	}
	return n, true
}

func (p *jsonParser) skipSpace() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}

func (p *jsonParser) value(depth int) (*jnode, bool) {
	if p.pos >= len(p.src) {
		return nil, false
	}
	*p.nodes++
	if *p.nodes > maxJSONNodes {
		return nil, false
	}
	start := p.pos
	n := &jnode{kind: 'v'}
	switch c := p.src[p.pos]; {
	case c == '{':
		if depth >= maxJSONDepth {
			return nil, false
		}
		n.kind = 'o'
		p.pos++
		p.skipSpace()
		if p.pos < len(p.src) && p.src[p.pos] == '}' {
			p.pos++
			break
		}
		for {
			p.skipSpace()
			keyStart := p.pos
			if !p.str() {
				return nil, false
			}
			key := p.src[keyStart:p.pos]
			p.skipSpace()
			if p.pos >= len(p.src) || p.src[p.pos] != ':' {
				return nil, false
			}
			p.pos++
			p.skipSpace()
			kid, ok := p.value(depth + 1)
			if !ok {
				return nil, false
			}
			n.keys = append(n.keys, key)
			n.kids = append(n.kids, kid)
			p.skipSpace()
			if p.pos >= len(p.src) {
				return nil, false
			}
			if p.src[p.pos] == ',' {
				p.pos++
				continue
			}
			if p.src[p.pos] == '}' {
				p.pos++
				break
			}
			return nil, false
		}
	case c == '[':
		if depth >= maxJSONDepth {
			return nil, false
		}
		n.kind = 'a'
		p.pos++
		p.skipSpace()
		if p.pos < len(p.src) && p.src[p.pos] == ']' {
			p.pos++
			break
		}
		for {
			p.skipSpace()
			kid, ok := p.value(depth + 1)
			if !ok {
				return nil, false
			}
			n.kids = append(n.kids, kid)
			p.skipSpace()
			if p.pos >= len(p.src) {
				return nil, false
			}
			if p.src[p.pos] == ',' {
				p.pos++
				continue
			}
			if p.src[p.pos] == ']' {
				p.pos++
				break
			}
			return nil, false
		}
	case c == '"':
		if !p.str() {
			return nil, false
		}
	case c == '-' || c >= '0' && c <= '9':
		if !p.number() {
			return nil, false
		}
	case c == 't':
		if !p.literal("true") {
			return nil, false
		}
	case c == 'f':
		if !p.literal("false") {
			return nil, false
		}
	case c == 'n':
		if !p.literal("null") {
			return nil, false
		}
	default:
		return nil, false
	}
	n.raw = p.src[start:p.pos]
	return n, true
}

func (p *jsonParser) literal(word string) bool {
	if len(p.src)-p.pos < len(word) || string(p.src[p.pos:p.pos+len(word)]) != word {
		return false
	}
	p.pos += len(word)
	return true
}

func (p *jsonParser) str() bool {
	if p.pos >= len(p.src) || p.src[p.pos] != '"' {
		return false
	}
	p.pos++
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == '"':
			p.pos++
			return true
		case c < 0x20:
			return false
		case c == '\\':
			p.pos++
			if p.pos >= len(p.src) {
				return false
			}
			switch p.src[p.pos] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				p.pos++
			case 'u':
				if len(p.src)-p.pos < 5 {
					return false
				}
				for _, h := range p.src[p.pos+1 : p.pos+5] {
					if !(h >= '0' && h <= '9' || h >= 'a' && h <= 'f' || h >= 'A' && h <= 'F') {
						return false
					}
				}
				p.pos += 5
			default:
				return false
			}
		default:
			p.pos++
		}
	}
	return false
}

func (p *jsonParser) digits() bool {
	start := p.pos
	for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
		p.pos++
	}
	return p.pos > start
}

func (p *jsonParser) number() bool {
	if p.src[p.pos] == '-' {
		p.pos++
	}
	if p.pos >= len(p.src) {
		return false
	}
	if p.src[p.pos] == '0' {
		p.pos++
	} else if !p.digits() {
		return false
	}
	if p.pos < len(p.src) && p.src[p.pos] == '.' {
		p.pos++
		if !p.digits() {
			return false
		}
	}
	if p.pos < len(p.src) && (p.src[p.pos] == 'e' || p.src[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.src) && (p.src[p.pos] == '+' || p.src[p.pos] == '-') {
			p.pos++
		}
		if !p.digits() {
			return false
		}
	}
	return true
}

// validJSONValue reports whether text is one complete JSON value within the limits.
func validJSONValue(text []byte) bool {
	nodes := 0
	_, ok := parseJSON(text, &nodes)
	return ok
}

func keyMatches(raw []byte, name string) bool {
	inner := raw[1 : len(raw)-1]
	if bytes.IndexByte(inner, '\\') < 0 {
		return string(inner) == name
	}
	var decoded string
	if json.Unmarshal(raw, &decoded) != nil {
		return false
	}
	return decoded == name
}

// jloc addresses a node by its parent and position; the root has a nil parent.
type jloc struct {
	parent *jnode
	index  int
}

type jsonDoc struct {
	root        *jnode
	lead, trail []byte
	nodes       int
	// limit bounds the document: source plus everything inserted, and the serialized output
	// (0: unbounded). overflow is set when an insertion went past it; the edit is abandoned.
	limit    int
	size     int
	overflow bool
}

func newJSONDoc(src []byte) (*jsonDoc, bool) {
	d := &jsonDoc{}
	start, end := 0, len(src)
	for start < end && isJSONSpace(src[start]) {
		start++
	}
	for end > start && isJSONSpace(src[end-1]) {
		end--
	}
	d.lead, d.trail = src[:start], src[end:]
	root, ok := parseJSON(src[start:end], &d.nodes)
	if !ok {
		return nil, false
	}
	d.root = root
	d.size = len(src)
	return d, true
}

func isJSONSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

func (d *jsonDoc) node(l jloc) *jnode {
	if l.parent == nil {
		return d.root
	}
	return l.parent.kids[l.index]
}

func namesOf(seg *pathSeg) []string {
	switch seg.kind {
	case segName, segDescend:
		return []string{seg.name}
	case segUnionNames:
		return seg.names
	}
	return nil
}

// step applies one segment to every location.
func (d *jsonDoc) step(locs []jloc, seg *pathSeg) []jloc {
	var out []jloc
	for _, l := range locs {
		n := d.node(l)
		switch seg.kind {
		case segName, segUnionNames:
			if n.kind != 'o' {
				continue
			}
			for _, name := range namesOf(seg) {
				for i, key := range n.keys {
					if keyMatches(key, name) {
						out = append(out, jloc{n, i})
					}
				}
			}
		case segIndex, segUnionIndex:
			if n.kind != 'a' {
				continue
			}
			indexes := seg.indexes
			if seg.kind == segIndex {
				indexes = []int{seg.index}
			}
			for _, idx := range indexes {
				if idx < 0 {
					idx += len(n.kids)
				}
				if idx >= 0 && idx < len(n.kids) {
					out = append(out, jloc{n, idx})
				}
			}
		case segWild:
			if n.kind == 'o' || n.kind == 'a' {
				for i := range n.kids {
					out = append(out, jloc{n, i})
				}
			}
		case segDescend:
			out = descend(out, n, seg.name)
		}
	}
	if len(out) > 1 && (seg.kind == segUnionNames || seg.kind == segUnionIndex || seg.kind == segDescend) {
		out = dedupe(out)
	}
	return out
}

func descend(out []jloc, n *jnode, name string) []jloc {
	switch n.kind {
	case 'o':
		for i, key := range n.keys {
			if keyMatches(key, name) {
				out = append(out, jloc{n, i})
			}
		}
		for _, kid := range n.kids {
			out = descend(out, kid, name)
		}
	case 'a':
		for _, kid := range n.kids {
			out = descend(out, kid, name)
		}
	}
	return out
}

func dedupe(locs []jloc) []jloc {
	seen := make(map[jloc]struct{}, len(locs))
	out := locs[:0]
	for _, l := range locs {
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		out = append(out, l)
	}
	return out
}

func (d *jsonDoc) eval(path *jsonPath, count int) []jloc {
	locs := []jloc{{}}
	for i := 0; i < count && len(locs) > 0; i++ {
		locs = d.step(locs, &path.segs[i])
	}
	return locs
}

// fresh parses a value for insertion; every insertion gets its own nodes, so later edits
// never alias.
func (d *jsonDoc) fresh(value []byte) *jnode {
	if d.overflow {
		return nil
	}
	d.size += len(value)
	if d.limit > 0 && d.size > d.limit {
		d.overflow = true
		return nil
	}
	n, ok := parseJSON(value, &d.nodes)
	if !ok {
		return nil
	}
	return n
}

func (d *jsonDoc) replace(l jloc, value []byte) bool {
	old := d.node(l)
	if old.kind == 'v' && !old.dirty && bytes.Equal(old.raw, value) {
		return false
	}
	n := d.fresh(value)
	if n == nil {
		return false
	}
	if l.parent == nil {
		d.root = n
	} else {
		l.parent.kids[l.index] = n
		l.parent.dirty = true
	}
	return true
}

// set replaces the matches of path with value; a missing last object key is added to every
// parent object that lacks it. It returns the number of changes.
func (d *jsonDoc) set(path *jsonPath, value []byte) int {
	count := 0
	if len(path.segs) == 0 {
		if d.replace(jloc{}, value) {
			count++
		}
		return count
	}
	last := &path.segs[len(path.segs)-1]
	parents := d.eval(path, len(path.segs)-1)
	switch last.kind {
	case segName, segUnionNames:
		for _, name := range namesOf(last) {
			for _, parent := range parents {
				obj := d.node(parent)
				if obj.kind != 'o' {
					continue
				}
				found := false
				for i, key := range obj.keys {
					if keyMatches(key, name) {
						found = true
						if d.replace(jloc{obj, i}, value) {
							count++
						}
					}
				}
				if found {
					continue
				}
				n := d.fresh(value)
				if n == nil {
					continue
				}
				key, err := json.Marshal(name)
				if err != nil {
					continue
				}
				obj.keys = append(obj.keys, key)
				obj.kids = append(obj.kids, n)
				obj.dirty = true
				count++
			}
		}
	default:
		for _, l := range d.step(parents, last) {
			if d.replace(l, value) {
				count++
			}
		}
	}
	return count
}

func (d *jsonDoc) remove(path *jsonPath) int {
	if len(path.segs) == 0 {
		return 0
	}
	locs := d.eval(path, len(path.segs))
	groups := make(map[*jnode][]int)
	var order []*jnode
	for _, l := range locs {
		if l.parent == nil {
			continue
		}
		if _, ok := groups[l.parent]; !ok {
			order = append(order, l.parent)
		}
		groups[l.parent] = append(groups[l.parent], l.index)
	}
	count := 0
	for _, parent := range order {
		indexes := groups[parent]
		sort.Sort(sort.Reverse(sort.IntSlice(indexes)))
		prev := -1
		for _, idx := range indexes {
			if idx == prev {
				continue
			}
			prev = idx
			parent.kids = append(parent.kids[:idx], parent.kids[idx+1:]...)
			if parent.kind == 'o' {
				parent.keys = append(parent.keys[:idx], parent.keys[idx+1:]...)
			}
			count++
		}
		parent.dirty = true
	}
	return count
}

func (d *jsonDoc) appendTo(path *jsonPath, value []byte) int {
	count := 0
	for _, l := range d.eval(path, len(path.segs)) {
		n := d.node(l)
		if n.kind != 'a' {
			continue
		}
		fresh := d.fresh(value)
		if fresh == nil {
			continue
		}
		n.kids = append(n.kids, fresh)
		n.dirty = true
		count++
	}
	return count
}

func markDirty(n *jnode) bool {
	dirty := n.dirty
	for _, kid := range n.kids {
		if markDirty(kid) {
			dirty = true
		}
	}
	n.dirty = dirty
	return dirty
}

// writeNode appends n to buf; it stops early once buf outgrows limit (limit 0: unbounded), so
// a document cannot be expanded without bound.
func writeNode(buf []byte, n *jnode, limit int) []byte {
	if limit > 0 && len(buf) > limit {
		return buf
	}
	if !n.dirty {
		return append(buf, n.raw...)
	}
	if n.kind == 'o' {
		buf = append(buf, '{')
		for i, kid := range n.kids {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = append(buf, n.keys[i]...)
			buf = append(buf, ':')
			buf = writeNode(buf, kid, limit)
			if limit > 0 && len(buf) > limit {
				return buf
			}
		}
		return append(buf, '}')
	}
	buf = append(buf, '[')
	for i, kid := range n.kids {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = writeNode(buf, kid, limit)
		if limit > 0 && len(buf) > limit {
			return buf
		}
	}
	return append(buf, ']')
}

// bytes serializes the document; limit bounds the output size (false when exceeded).
func (d *jsonDoc) bytes(limit int) ([]byte, bool) {
	markDirty(d.root)
	out := make([]byte, 0, len(d.lead)+len(d.trail)+len(d.root.raw)+64)
	out = append(out, d.lead...)
	out = writeNode(out, d.root, limit)
	out = append(out, d.trail...)
	return out, len(out) <= limit
}
