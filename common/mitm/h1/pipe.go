package h1

import (
	"io"
	"sync"

	"github.com/sagernet/sing/common/buf"
)

const (
	// pipeBufferSize is the size of each of the two body pipe buffers.
	pipeBufferSize = 64 << 10
	// pipeThreshold is the body length from which a fixed-length body goes through the pipe;
	// shorter bodies are copied on the reading goroutine, with the head in the same write.
	pipeThreshold = 64 << 10
)

// bodyPipe overlaps reading a body with writing it: the reading goroutine fills one of two
// buffers while a writer goroutine sends everything committed so far in one write. Data is
// handed over as soon as it is read, so a pausing source (a stream, slow chunks) is forwarded
// at once; reads that complete while a write is in progress coalesce into the next write,
// which over TLS turns many record-sized reads into few large writes.
//
// The writer goroutine starts with the first body and lives as long as the session; copy is
// called by one goroutine at a time.
type bodyPipe struct {
	mu      sync.Mutex
	cond    sync.Cond
	started bool
	closed  bool

	dst     io.Writer
	buffers [2][]byte
	end     [2]int // committed bytes per buffer
	sent    [2]int // written bytes per buffer
	fill    int    // buffer the reader fills
	send    int    // buffer the writer sends from
	err     error  // first write error of the current body
	writing bool   // the writer is in dst.Write, outside the lock
}

func (p *bodyPipe) start() {
	p.cond.L = &p.mu
	p.buffers[0] = buf.Get(pipeBufferSize)
	p.buffers[1] = buf.Get(pipeBufferSize)
	p.started = true
	go p.run()
}

func (p *bodyPipe) run() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		s := p.send
		switch {
		case p.sent[s] < p.end[s]:
			segment := p.buffers[s][p.sent[s]:p.end[s]]
			dst := p.dst
			p.writing = true
			p.mu.Unlock()
			_, err := dst.Write(segment)
			p.mu.Lock()
			p.writing = false
			p.sent[s] += len(segment)
			if err != nil && p.err == nil {
				p.err = err
			}
			p.cond.Broadcast()
		case s != p.fill:
			// The reader moved on: this buffer is free again.
			p.end[s], p.sent[s] = 0, 0
			p.send = p.fill
			p.cond.Broadcast()
		case p.closed:
			// Nothing reads the buffers any more: the reader finished with them before close.
			buf.Put(p.buffers[0])
			buf.Put(p.buffers[1])
			return
		default:
			p.cond.Wait()
		}
	}
}

// close ends the writer goroutine once it finished its current write.
func (p *bodyPipe) close() {
	if !p.started {
		return
	}
	p.mu.Lock()
	p.closed = true
	p.cond.Broadcast()
	p.mu.Unlock()
}

// space returns the free part of the fill buffer, at least min bytes, switching to the other
// buffer once the writer freed it. It fails with the write error.
func (p *bodyPipe) space(min int) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		if p.err != nil {
			return nil, p.err
		}
		if len(p.buffers[p.fill])-p.end[p.fill] >= min {
			return p.buffers[p.fill][p.end[p.fill]:], nil
		}
		other := 1 - p.fill
		if p.send != other && p.end[other] == 0 {
			p.fill = other
			p.cond.Broadcast()
			continue
		}
		p.cond.Wait()
	}
}

// commit hands n more bytes of the fill buffer to the writer.
func (p *bodyPipe) commit(n int) {
	if n == 0 {
		return
	}
	p.mu.Lock()
	p.end[p.fill] += n
	p.cond.Broadcast()
	p.mu.Unlock()
}

// drain waits until everything committed was written and returns the write error, which it
// clears with the buffers for the next body.
func (p *bodyPipe) drain() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.err == nil && (p.send != p.fill || p.sent[p.fill] < p.end[p.fill]) {
		p.cond.Wait()
	}
	err := p.err
	if err == nil {
		p.end[p.fill], p.sent[p.fill] = 0, 0
		return nil
	}
	// Reset for the next body once the writer is out of its write.
	for p.writing {
		p.cond.Wait()
	}
	p.end, p.sent = [2]int{}, [2]int{}
	p.fill, p.send = 0, 0
	p.err = nil
	return err
}

// copy reads src until io.EOF (or limit bytes when limit >= 0) and writes it to dst through the
// pipe, returning once everything was written. With chunked, each read becomes one chunk of
// the chunked coding; the last chunk is left to the caller.
func (p *bodyPipe) copy(dst io.Writer, src io.Reader, limit int64, chunked bool) (int64, error) {
	if !p.started {
		p.start()
	}
	p.mu.Lock()
	p.dst = dst
	p.mu.Unlock()
	var (
		total   int64
		readErr error
	)
	for limit < 0 || total < limit {
		minimum := 1
		if chunked {
			minimum = chunkHeaderRoom + 3
		}
		space, err := p.space(minimum)
		if err != nil {
			p.drain()
			return total, err
		}
		data := space
		if chunked {
			data = space[chunkHeaderRoom : len(space)-2]
		}
		if limit >= 0 && int64(len(data)) > limit-total {
			data = data[:limit-total]
		}
		n, err := src.Read(data)
		if n > 0 {
			total += int64(n)
			if chunked {
				n = encodeChunk(space, n)
			}
			p.commit(n)
		}
		if err != nil {
			readErr = err
			break
		}
	}
	if writeErr := p.drain(); writeErr != nil {
		return total, writeErr
	}
	if readErr == io.EOF {
		readErr = nil
	}
	return total, readErr
}

// encodeChunk turns the n data bytes at chunk[chunkHeaderRoom:] into one chunk at the start of
// chunk (size line, data, CRLF) and returns its length.
func encodeChunk(chunk []byte, n int) int {
	var header [chunkHeaderRoom]byte
	start := len(header) - 2
	header[start] = '\r'
	header[start+1] = '\n'
	for size := uint64(n); ; size >>= 4 {
		start--
		header[start] = hexDigits[size&0xf]
		if size < 16 {
			break
		}
	}
	headerLength := copy(chunk, header[start:])
	copy(chunk[headerLength:], chunk[chunkHeaderRoom:chunkHeaderRoom+n])
	chunk[headerLength+n] = '\r'
	chunk[headerLength+n+1] = '\n'
	return headerLength + n + 2
}
