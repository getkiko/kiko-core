package capture

import (
	"encoding/json"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/mitm/flow"
)

const (
	persistQueueLen   = 512
	persistQueueBytes = 32 << 20
	syncInterval      = time.Second
	sweepInterval     = time.Minute
	// persistHistoryShare is the part of the memory budget the stored
	// history may take when it is loaded into the viewer.
	persistHistoryShare = 2
)

// PersistStats reports the on-disk copy.
type PersistStats struct {
	Enabled bool
	// Failed means the directory could not be opened; nothing is written.
	Failed  bool
	Records int
	Bytes   int64
	// Written, Dropped and Errors count records since the process started:
	// Dropped found the queue full, Errors failed to write.
	Written uint64
	Dropped uint64
	Errors  uint64
}

// diskConn is the stored part of flow.ConnectionInfo.
type diskConn struct {
	ID           string
	Source       string
	Destination  string
	Host         string
	Inbound      string
	InboundType  string
	Outbound     string
	OutboundType string
	Rule         string
	ProcessName  string
	ProcessPath  string
	ProcessID    uint32
	User         string
	Unverified   bool
}

// diskRecord is the payload of a frame. The embedded Record is flattened;
// Connection replaces its pointer to the live connection.
type diskRecord struct {
	Record
	Connection *diskConn
	ReqBody    []byte `json:",omitempty"`
	RespBody   []byte `json:",omitempty"`
}

type persistJob struct {
	pid       uint64
	rec       Record
	req, resp [][]byte
	size      int64
	cancelled atomic.Bool
	gen       uint64
}

// persister writes finished records on its own goroutine. The exchange path
// only copies headers' slice headers and chunk lists into a job and offers it
// to a bounded queue.
type persister struct {
	opts  PersistOptions
	store *diskStore
	red   *redactor

	queue  chan *persistJob
	queued atomic.Int64
	gen    atomic.Uint64 // bumped by purge; older queued jobs are dropped
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once

	written, dropped, errors atomic.Uint64
	diskRecords              atomic.Int64
	diskBytes                atomic.Int64
}

func newPersister(opts PersistOptions) (*persister, error) {
	store, err := openDiskStore(opts)
	if err != nil {
		return nil, err
	}
	p := &persister{
		opts:  opts,
		store: store,
		red:   newRedactor(opts.RedactHeaders),
		queue: make(chan *persistJob, persistQueueLen),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	p.refresh()
	return p, nil
}

func (p *persister) refresh() {
	stats := p.store.Stats()
	p.diskRecords.Store(int64(stats.Records))
	p.diskBytes.Store(stats.Bytes)
}

func (p *persister) start() { go p.run() }

// close drains the queue and releases the files.
func (p *persister) close() {
	p.once.Do(func() { close(p.stop) })
	<-p.done
}

func (p *persister) stats() PersistStats {
	return PersistStats{
		Enabled: true,
		Records: int(p.diskRecords.Load()),
		Bytes:   p.diskBytes.Load(),
		Written: p.written.Load(),
		Dropped: p.dropped.Load(),
		Errors:  p.errors.Load(),
	}
}

// offer queues a job without blocking; it reports whether it was accepted.
func (p *persister) offer(job *persistJob) bool {
	if p.queued.Load()+job.size > persistQueueBytes {
		p.dropped.Add(1)
		return false
	}
	p.queued.Add(job.size)
	select {
	case p.queue <- job:
		return true
	default:
		p.queued.Add(-job.size)
		p.dropped.Add(1)
		return false
	}
}

func (p *persister) run() {
	defer close(p.done)
	syncTick := time.NewTicker(syncInterval)
	sweepTick := time.NewTicker(sweepInterval)
	defer syncTick.Stop()
	defer sweepTick.Stop()
	dirty := false
	for {
		select {
		case job := <-p.queue:
			p.write(job)
			dirty = true
		case <-syncTick.C:
			if dirty {
				p.store.Sync()
				dirty = false
			}
		case <-sweepTick.C:
			p.store.Sweep(time.Now())
			p.refresh()
		case <-p.stop:
			for {
				select {
				case job := <-p.queue:
					p.write(job)
				default:
					p.store.Close()
					return
				}
			}
		}
	}
}

func joinChunks(chunks [][]byte) []byte {
	var n int
	for _, c := range chunks {
		n += len(c)
	}
	if n == 0 {
		return nil
	}
	out := make([]byte, 0, n)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

func toDiskConn(c *flow.ConnectionInfo) *diskConn {
	if c == nil {
		return nil
	}
	return &diskConn{
		ID: c.ID, Source: c.Source, Destination: c.Destination, Host: c.Host,
		Inbound: c.Inbound, InboundType: c.InboundType, Outbound: c.Outbound, OutboundType: c.OutboundType,
		Rule: c.Rule, ProcessName: c.ProcessName, ProcessPath: c.ProcessPath, ProcessID: c.ProcessID,
		User: c.User, Unverified: c.Unverified,
	}
}

func (c *diskConn) info() *flow.ConnectionInfo {
	if c == nil {
		return nil
	}
	return &flow.ConnectionInfo{
		ID: c.ID, Source: c.Source, Destination: c.Destination, Host: c.Host,
		Inbound: c.Inbound, InboundType: c.InboundType, Outbound: c.Outbound, OutboundType: c.OutboundType,
		Rule: c.Rule, ProcessName: c.ProcessName, ProcessPath: c.ProcessPath, ProcessID: c.ProcessID,
		User: c.User, Unverified: c.Unverified,
	}
}

func (p *persister) encode(job *persistJob, withBody bool) ([]byte, error) {
	rec := p.red.record(job.rec)
	d := diskRecord{Record: rec, Connection: toDiskConn(job.rec.Connection)}
	d.Record.Connection = nil
	if withBody && p.opts.Body {
		d.ReqBody, d.RespBody = joinChunks(job.req), joinChunks(job.resp)
	}
	if !withBody || !p.opts.Body {
		d.Record.RequestBodySaved, d.Record.ResponseBodySaved = false, false
		d.Record.RequestBodyStored, d.Record.ResponseBodyStored = 0, 0
	}
	return json.Marshal(&d)
}

func (p *persister) write(job *persistJob) {
	defer p.queued.Add(-job.size)
	if job.cancelled.Load() {
		return
	}
	payload, err := p.encode(job, true)
	if err == nil {
		err = p.appendJob(job, payload)
		if err != nil && p.opts.Body && len(payload) > 1<<20 {
			// The record may be too large for the budget with its bodies.
			if payload, err = p.encode(job, false); err == nil {
				err = p.appendJob(job, payload)
			}
		}
	}
	if err != nil {
		p.errors.Add(1)
		job.req, job.resp = nil, nil
		return
	}
	p.refresh()
	p.written.Add(1)
	job.req, job.resp = nil, nil
}

func (p *persister) appendJob(job *persistJob, payload []byte) error {
	// Cancelled records must not land after a delete or purge: Append and
	// those operations serialize on the store lock, and the flag is set
	// before they run.
	return p.store.AppendUnless(job.pid, time.Now(), payload, func() bool {
		return job.cancelled.Load() || job.gen != p.gen.Load()
	})
}

func (p *persister) deleteRecord(pid uint64) error {
	err := p.store.Delete(pid)
	p.refresh()
	return err
}

func (p *persister) purge() error {
	p.gen.Add(1)
	err := p.store.Purge()
	p.refresh()
	return err
}

// decodeStored parses a frame payload.
func decodeStored(payload []byte) (diskRecord, error) {
	var d diskRecord
	err := json.Unmarshal(payload, &d)
	return d, err
}

// snapshotJobLocked copies what a persisted record needs; the manager lock
// is held. Chunk bytes below their length never change, so they are shared.
func snapshotJobLocked(e *entry, body bool) *persistJob {
	job := &persistJob{rec: e.rec, size: 2048}
	if body {
		job.req = append([][]byte(nil), e.req.chunks...)
		job.resp = append([][]byte(nil), e.resp.chunks...)
		job.size += e.req.stored + e.resp.stored
	}
	return job
}

// persistFinishedLocked queues a finished entry for writing.
func (m *Manager) persistFinishedLocked(e *entry) {
	p := m.persist
	if p == nil || e.pid != 0 {
		return
	}
	job := snapshotJobLocked(e, p.opts.Body)
	m.pidNext++
	job.pid = m.pidNext
	job.gen = p.gen.Load()
	if p.offer(job) {
		e.pid = job.pid
		e.job = job
	}
}

// applyPersist switches the on-disk copy. Disabling stops writing and keeps
// the files; Purge removes them.
func (m *Manager) applyPersist(opt PersistOptions) {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	opt = opt.normalize()
	m.mu.Lock()
	if m.persistApplied && m.persistOpts.same(opt) {
		m.mu.Unlock()
		return
	}
	old := m.persist
	m.persist = nil
	m.persistFailed = false
	m.persistApplied = true
	m.persistOpts = opt
	if opt.Path != "" {
		m.persistDir = opt.Path
	}
	memory, records := m.opts.MaxMemory, m.opts.MaxRecords
	m.mu.Unlock()
	if old != nil {
		old.close()
	}
	if !opt.Enabled {
		return
	}
	p, err := newPersister(opt)
	if err != nil {
		m.mu.Lock()
		m.persistFailed = true
		m.mu.Unlock()
		return
	}
	var history []diskRecord
	var pids []uint64
	m.mu.Lock()
	load := m.historyDir != opt.Path
	m.mu.Unlock()
	if load {
		for _, item := range p.store.Newest(records, memory/persistHistoryShare) {
			d, derr := decodeStored(item.Payload)
			if derr != nil {
				continue
			}
			history = append(history, d)
			pids = append(pids, item.PID)
		}
	}
	m.mu.Lock()
	if highest := p.store.MaxPID(); m.pidNext < highest {
		m.pidNext = highest
	}
	for i := range history {
		m.insertHistoryLocked(&history[i], pids[i])
	}
	if load {
		m.historyDir = opt.Path
	}
	m.persist = p
	m.mu.Unlock()
	p.start()
}

// Close stops the on-disk copy after it has written what is queued.
func (m *Manager) Close() {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	m.mu.Lock()
	old := m.persist
	m.persist = nil
	m.persistApplied = false
	m.mu.Unlock()
	if old != nil {
		old.close()
	}
}

// insertHistoryLocked adds a stored record to the ring as a finished one.
func (m *Manager) insertHistoryLocked(d *diskRecord, pid uint64) {
	m.ordinal++
	e := &entry{ordinal: m.ordinal, pid: pid, finished: true}
	rec := d.Record
	rec.Connection = d.Connection.info()
	rec.ID = formatOrdinal(m.ordinal)
	rec.Instance = m.instance
	switch rec.State {
	case StateInProgress:
		rec.State = StateFailed
	}
	e.rec = rec
	e.size = recordMemSize(&e.rec)
	if len(d.ReqBody) > 0 {
		e.req.chunks = [][]byte{d.ReqBody}
		e.req.stored = int64(len(d.ReqBody))
		e.size += int64(cap(d.ReqBody))
		e.rec.RequestBodySaved = true
		e.rec.RequestBodyStored = e.req.stored
	}
	if len(d.RespBody) > 0 {
		e.resp.chunks = [][]byte{d.RespBody}
		e.resp.stored = int64(len(d.RespBody))
		e.size += int64(cap(d.RespBody))
		e.rec.ResponseBodySaved = true
		e.rec.ResponseBodyStored = e.resp.stored
	}
	m.bytes += e.size
	m.count++
	m.byID[e.ordinal] = e
	e.prev = m.tail
	if m.tail != nil {
		m.tail.next = e
	} else {
		m.head = e
	}
	m.tail = e
	m.touchLocked(e)
	e.rec.CreatedSeq = e.rec.Seq
	m.finishedQueue = append(m.finishedQueue, e)
	m.enforceLocked()
}

// Delete removes a finished record from the viewer and from disk.
func (m *Manager) Delete(id string) error {
	ordinal, ok := parseOrdinal(id)
	if !ok {
		return ErrNotFound
	}
	m.mu.Lock()
	e := m.byID[ordinal]
	if e == nil {
		m.mu.Unlock()
		return ErrNotFound
	}
	if !e.finished {
		m.mu.Unlock()
		return ErrInProgress
	}
	pid, job, p := e.pid, e.job, m.persist
	m.removeLocked(e)
	m.seq++
	m.floor = m.seq
	m.notifyLocked()
	m.mu.Unlock()
	if job != nil {
		job.cancelled.Store(true)
	}
	if pid == 0 {
		return nil
	}
	if p != nil {
		if err := p.deleteRecord(pid); err != nil && err != ErrNotPersisted {
			return err
		}
		return nil
	}
	return m.deleteClosedCopy(pid)
}

// deleteClosedCopy removes a record from the on-disk copy while persistence is
// off, by opening the directory for the duration of the delete.
func (m *Manager) deleteClosedCopy(pid uint64) error {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	m.mu.Lock()
	p, opts, dir := m.persist, m.persistOpts, m.persistDir
	m.mu.Unlock()
	if p != nil {
		if err := p.deleteRecord(pid); err != nil && err != ErrNotPersisted {
			return err
		}
		return nil
	}
	if dir == "" {
		return nil
	}
	opts.Path = dir
	store, err := openDiskStore(opts)
	if err != nil {
		return err
	}
	defer store.Close()
	if err = store.Delete(pid); err != nil && err != ErrNotPersisted {
		return err
	}
	return nil
}

// PurgePersisted deletes every file of the on-disk copy and the viewer rows
// that came from or went to it. Other rows stay.
func (m *Manager) PurgePersisted() error {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	m.mu.Lock()
	for e := m.head; e != nil; {
		next := e.next
		if e.job != nil {
			e.job.cancelled.Store(true)
		}
		if e.pid != 0 && e.finished {
			m.removeLocked(e)
		}
		e = next
	}
	m.seq++
	m.floor = m.seq
	m.notifyLocked()
	p, dir := m.persist, m.persistDir
	m.mu.Unlock()
	if p != nil {
		return p.purge()
	}
	return PurgeDir(dir)
}

// PersistStats returns the state of the on-disk copy.
func (m *Manager) PersistStats() PersistStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.persistStatsLocked()
}

func (m *Manager) persistStatsLocked() PersistStats {
	if p := m.persist; p != nil {
		return p.stats()
	}
	return PersistStats{Failed: m.persistFailed}
}

func parseOrdinal(id string) (uint64, bool) {
	n, err := strconv.ParseUint(id, 10, 64)
	return n, err == nil
}

func formatOrdinal(n uint64) string { return strconv.FormatUint(n, 10) }

// recordMemSize estimates the memory of a record without bodies, with the
// same terms the exchange hooks add up.
func recordMemSize(r *Record) int64 {
	size := int64(recordBaseSize)
	size += int64(len(r.Method) + len(r.Scheme) + len(r.Authority) + len(r.Host) + len(r.Path) + len(r.URL) +
		len(r.Proto) + len(r.RequestEncoding) + len(r.ResponseEncoding) + len(r.Error) + 8*len(r.Interim))
	size += headersSize(r.RequestHeaders) + headersSize(r.ResponseHeaders) + headersSize(r.RequestTrailers) + headersSize(r.ResponseTrailers)
	return size + hitsSize(r.Rewrites)
}
