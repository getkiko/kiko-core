package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// On-disk layout: a directory of segment files seg-<number>.cap. A segment
// is a sequence of frames:
//
//	magic(1) kind(1) reserved(2) length(4) crc(4) pid(8) saved(8) payload
//
// All integers are little endian. crc is CRC-32C over the header without the
// crc field, then the payload. A frame is appended with one write, so a crash
// leaves at most one cut-off frame at the end of the newest segment; reading
// stops at the first frame that does not verify and the file is cut there.
const (
	frameMagic      = 0xC7
	frameKindRecord = 1
	frameHeaderSize = 28
	// maxFramePayload guards allocations when a length field is damaged.
	maxFramePayload = 192 << 20

	segmentPrefix = "seg-"
	segmentSuffix = ".cap"
	tempSuffix    = ".tmp"

	minSegmentSize = 128 << 10
	maxSegmentSize = 8 << 20

	dirMode  = 0o700
	fileMode = 0o600
)

var (
	crcTable = crc32.MakeTable(crc32.Castagnoli)

	// ErrNotPersisted means no stored record has the id.
	ErrNotPersisted = errors.New("record is not stored")
)

// PersistOptions configure the on-disk copy. The zero value is off.
type PersistOptions struct {
	Enabled bool
	// Path is the directory; relative paths resolve against the working
	// directory of the process.
	Path       string
	MaxBytes   int64
	MaxRecords int
	Retention  time.Duration
	// Body also writes the bodies kept in memory.
	Body bool
	// RedactHeaders are masked besides the built-in list.
	RedactHeaders []string
}

func (o PersistOptions) normalize() PersistOptions {
	if o.MaxBytes <= 0 {
		o.MaxBytes = 256 << 20
	}
	if o.MaxRecords <= 0 {
		o.MaxRecords = 20000
	}
	if o.Retention <= 0 {
		o.Retention = 7 * 24 * time.Hour
	}
	return o
}

func (o PersistOptions) same(p PersistOptions) bool {
	if o.Enabled != p.Enabled || o.Path != p.Path || o.MaxBytes != p.MaxBytes || o.MaxRecords != p.MaxRecords ||
		o.Retention != p.Retention || o.Body != p.Body || len(o.RedactHeaders) != len(p.RedactHeaders) {
		return false
	}
	for i := range o.RedactHeaders {
		if o.RedactHeaders[i] != p.RedactHeaders[i] {
			return false
		}
	}
	return true
}

// DiskStats describes the files.
type DiskStats struct {
	Records int
	Bytes   int64
}

type frameHeader struct {
	kind   byte
	length uint32
	crc    uint32
	pid    uint64
	saved  int64
}

func encodeFrame(pid uint64, saved int64, payload []byte) []byte {
	buf := make([]byte, frameHeaderSize+len(payload))
	buf[0] = frameMagic
	buf[1] = frameKindRecord
	binary.LittleEndian.PutUint32(buf[4:], uint32(len(payload)))
	binary.LittleEndian.PutUint64(buf[12:], pid)
	binary.LittleEndian.PutUint64(buf[20:], uint64(saved))
	copy(buf[frameHeaderSize:], payload)
	crc := crc32.Update(0, crcTable, buf[:8])
	crc = crc32.Update(crc, crcTable, buf[12:])
	binary.LittleEndian.PutUint32(buf[8:], crc)
	return buf
}

func parseHeader(b []byte) (frameHeader, bool) {
	if b[0] != frameMagic || b[1] != frameKindRecord {
		return frameHeader{}, false
	}
	h := frameHeader{
		kind:   b[1],
		length: binary.LittleEndian.Uint32(b[4:]),
		crc:    binary.LittleEndian.Uint32(b[8:]),
		pid:    binary.LittleEndian.Uint64(b[12:]),
		saved:  int64(binary.LittleEndian.Uint64(b[20:])),
	}
	return h, h.length <= maxFramePayload && h.pid != 0
}

func frameChecksum(header []byte, payload []byte) uint32 {
	crc := crc32.Update(0, crcTable, header[:8])
	crc = crc32.Update(crc, crcTable, header[12:frameHeaderSize])
	return crc32.Update(crc, crcTable, payload)
}

// readFrames walks a segment and calls fn for each verified frame; payload is
// only valid during the call. It returns the offset after the last good
// frame and whether bytes follow it that do not verify.
func readFrames(r io.Reader, fn func(h frameHeader, offset int64, payload []byte)) (good int64, damaged bool) {
	br := bufio.NewReaderSize(r, 256<<10)
	header := make([]byte, frameHeaderSize)
	var payload []byte
	for {
		n, err := io.ReadFull(br, header)
		if err != nil {
			return good, n > 0
		}
		h, ok := parseHeader(header)
		if !ok {
			return good, true
		}
		if cap(payload) < int(h.length) {
			payload = make([]byte, h.length)
		}
		payload = payload[:h.length]
		if _, err = io.ReadFull(br, payload); err != nil || frameChecksum(header, payload) != h.crc {
			return good, true
		}
		fn(h, good, payload)
		good += frameHeaderSize + int64(h.length)
	}
}

type indexEntry struct {
	seg    *segment
	offset int64
	size   int64
	saved  int64
}

type segment struct {
	number int
	name   string
	size   int64
	// pids lists the records written to the segment, oldest first; those no
	// longer in the index are dead.
	pids []uint64
	live int
	// newest is the latest save time in the segment.
	newest int64
}

// diskStore is the segment directory. Every method locks mu; none is called
// on the exchange path.
type diskStore struct {
	dir  string
	opts PersistOptions

	mu      sync.Mutex
	segs    []*segment
	index   map[uint64]*indexEntry
	bytes   int64
	nextNum int
	maxPID  uint64
	active  *os.File
	segMax  int64
	closed  bool
}

func segmentName(number int) string {
	return segmentPrefix + leftPad(strconv.Itoa(number), 12) + segmentSuffix
}

func leftPad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return strings.Repeat("0", width-len(s)) + s
}

func parseSegmentNumber(name string) (int, bool) {
	if !strings.HasPrefix(name, segmentPrefix) || !strings.HasSuffix(name, segmentSuffix) {
		return 0, false
	}
	n, err := strconv.Atoi(name[len(segmentPrefix) : len(name)-len(segmentSuffix)])
	return n, err == nil && n >= 0
}

func ensureDir(dir string) error {
	if info, err := os.Lstat(dir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("persist path is a symbolic link")
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	return os.Chmod(dir, dirMode)
}

// openDiskStore scans dir, cuts damaged tails and applies the limits.
func openDiskStore(opts PersistOptions) (*diskStore, error) {
	opts = opts.normalize()
	if opts.Path == "" {
		return nil, errors.New("persist path is empty")
	}
	if err := ensureDir(opts.Path); err != nil {
		return nil, err
	}
	s := &diskStore{dir: opts.Path, opts: opts, index: make(map[uint64]*indexEntry)}
	s.segMax = min(max(opts.MaxBytes/8, minSegmentSize), maxSegmentSize)
	entries, err := os.ReadDir(opts.Path)
	if err != nil {
		return nil, err
	}
	var numbers []int
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, tempSuffix) && strings.HasPrefix(name, segmentPrefix) {
			_ = os.Remove(filepath.Join(opts.Path, name))
			continue
		}
		if n, ok := parseSegmentNumber(name); ok && entry.Type().IsRegular() {
			numbers = append(numbers, n)
		}
	}
	sort.Ints(numbers)
	cutoff := time.Now().Add(-opts.Retention).UnixNano()
	for _, n := range numbers {
		if err = s.scanSegment(n, cutoff); err != nil {
			return nil, err
		}
		s.nextNum = n + 1
	}
	s.enforceLocked(time.Now())
	return s, nil
}

func (s *diskStore) path(seg *segment) string { return filepath.Join(s.dir, seg.name) }

func (s *diskStore) scanSegment(number int, cutoff int64) error {
	seg := &segment{number: number, name: segmentName(number)}
	file, err := os.OpenFile(s.path(seg), os.O_RDWR, fileMode)
	if err != nil {
		return err
	}
	defer file.Close()
	_ = file.Chmod(fileMode)
	good, damaged := readFrames(file, func(h frameHeader, offset int64, _ []byte) {
		seg.pids = append(seg.pids, h.pid)
		seg.newest = max(seg.newest, h.saved)
		if h.pid > s.maxPID {
			s.maxPID = h.pid
		}
		if h.saved < cutoff {
			return
		}
		s.index[h.pid] = &indexEntry{seg: seg, offset: offset, size: frameHeaderSize + int64(h.length), saved: h.saved}
		seg.live++
	})
	if damaged {
		if err = file.Truncate(good); err != nil {
			return err
		}
	}
	seg.size = good
	if len(seg.pids) == 0 {
		_ = os.Remove(s.path(seg))
		return nil
	}
	s.segs = append(s.segs, seg)
	s.bytes += good
	return nil
}

// MaxPID is the highest id seen on disk.
func (s *diskStore) MaxPID() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxPID
}

func (s *diskStore) Stats() DiskStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return DiskStats{Records: len(s.index), Bytes: s.bytes}
}

// Append writes one record. A failed write leaves the files as they were.
func (s *diskStore) Append(pid uint64, saved time.Time, payload []byte) error {
	return s.AppendUnless(pid, saved, payload, nil)
}

// AppendUnless is Append that skips the write when cancelled reports true;
// the check runs under the store lock, so it orders against Delete and Purge.
func (s *diskStore) AppendUnless(pid uint64, saved time.Time, payload []byte, cancelled func() bool) error {
	frame := encodeFrame(pid, saved.UnixNano(), payload)
	s.mu.Lock()
	defer s.mu.Unlock()
	if cancelled != nil && cancelled() {
		return nil
	}
	if s.closed {
		return os.ErrClosed
	}
	if int64(len(frame)) > s.opts.MaxBytes/2 {
		return errors.New("record exceeds the disk budget")
	}
	if err := s.prepareActiveLocked(int64(len(frame))); err != nil {
		return err
	}
	seg := s.segs[len(s.segs)-1]
	if _, err := s.active.Write(frame); err != nil {
		// Cut a partial frame so that later frames stay readable; if that
		// fails, start a new segment.
		if s.active.Truncate(seg.size) != nil {
			s.closeActiveLocked()
		}
		return err
	}
	s.index[pid] = &indexEntry{seg: seg, offset: seg.size, size: int64(len(frame)), saved: saved.UnixNano()}
	seg.pids = append(seg.pids, pid)
	seg.live++
	seg.newest = max(seg.newest, saved.UnixNano())
	seg.size += int64(len(frame))
	s.bytes += int64(len(frame))
	if pid > s.maxPID {
		s.maxPID = pid
	}
	s.enforceLimitsLocked()
	return nil
}

// prepareActiveLocked makes sure the active segment can take size more bytes.
func (s *diskStore) prepareActiveLocked(size int64) error {
	if s.active != nil && len(s.segs) > 0 {
		if cur := s.segs[len(s.segs)-1]; cur.size > 0 && cur.size+size > s.segMax {
			s.closeActiveLocked()
		}
	}
	if s.active != nil {
		return nil
	}
	// Reuse the newest segment when it has room, else start a new one.
	if len(s.segs) > 0 {
		cur := s.segs[len(s.segs)-1]
		if cur.size+size <= s.segMax {
			file, err := os.OpenFile(s.path(cur), os.O_WRONLY|os.O_APPEND, fileMode)
			if err == nil {
				s.active = file
				return nil
			}
		}
	}
	seg := &segment{number: s.nextNum, name: segmentName(s.nextNum)}
	file, err := os.OpenFile(s.path(seg), os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return err
	}
	_ = file.Chmod(fileMode)
	s.nextNum++
	s.segs = append(s.segs, seg)
	s.active = file
	return nil
}

func (s *diskStore) closeActiveLocked() {
	if s.active != nil {
		_ = s.active.Sync()
		_ = s.active.Close()
		s.active = nil
	}
}

// Sync flushes the active segment.
func (s *diskStore) Sync() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != nil {
		_ = s.active.Sync()
	}
}

// Sweep applies retention and the limits.
func (s *diskStore) Sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enforceLocked(now)
}

// enforceLocked drops what is past retention and the limits, oldest first.
// Whole segments go; records of a partly stale segment leave the index and
// vanish from disk with the segment.
func (s *diskStore) enforceLocked(now time.Time) {
	cutoff := now.Add(-s.opts.Retention).UnixNano()
	for _, seg := range s.segs {
		if seg.live == 0 {
			continue
		}
		for _, pid := range seg.pids {
			if e := s.index[pid]; e != nil && e.seg == seg && e.saved < cutoff {
				s.dropLocked(pid, e)
			}
		}
	}
	s.enforceLimitsLocked()
}

// enforceLimitsLocked applies the count and byte limits.
func (s *diskStore) enforceLimitsLocked() {
	// Records over the count limit leave the index oldest first.
	for len(s.index) > s.opts.MaxRecords {
		if !s.dropOldestLocked() {
			break
		}
	}
	s.removeDeadSegmentsLocked()
	for s.bytes > s.opts.MaxBytes && len(s.segs) > 1 {
		s.removeSegmentLocked(0)
	}
}

func (s *diskStore) dropLocked(pid uint64, e *indexEntry) {
	delete(s.index, pid)
	e.seg.live--
}

func (s *diskStore) dropOldestLocked() bool {
	for _, seg := range s.segs {
		if seg.live == 0 {
			continue
		}
		for _, pid := range seg.pids {
			if e := s.index[pid]; e != nil && e.seg == seg {
				s.dropLocked(pid, e)
				return true
			}
		}
	}
	return false
}

// removeDeadSegmentsLocked deletes segments without live records, except the
// one being written.
func (s *diskStore) removeDeadSegmentsLocked() {
	for i := 0; i < len(s.segs); i++ {
		if s.segs[i].live == 0 && !(i == len(s.segs)-1 && s.active != nil) {
			s.removeSegmentLocked(i)
			i--
		}
	}
}

func (s *diskStore) removeSegmentLocked(i int) {
	seg := s.segs[i]
	if i == len(s.segs)-1 {
		s.closeActiveLocked()
	}
	for _, pid := range seg.pids {
		if e := s.index[pid]; e != nil && e.seg == seg {
			delete(s.index, pid)
		}
	}
	_ = os.Remove(s.path(seg))
	s.bytes -= seg.size
	s.segs = append(s.segs[:i], s.segs[i+1:]...)
}

// Read returns the payload of a stored record.
func (s *diskStore) Read(pid uint64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.index[pid]
	if e == nil {
		return nil, ErrNotPersisted
	}
	return s.readLocked(e)
}

func (s *diskStore) readLocked(e *indexEntry) ([]byte, error) {
	file, err := os.Open(s.path(e.seg))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	buf := make([]byte, e.size)
	if _, err = file.ReadAt(buf, e.offset); err != nil {
		return nil, err
	}
	h, ok := parseHeader(buf[:frameHeaderSize])
	if !ok || int64(h.length)+frameHeaderSize != e.size || frameChecksum(buf[:frameHeaderSize], buf[frameHeaderSize:]) != h.crc {
		return nil, errors.New("stored record is damaged")
	}
	return buf[frameHeaderSize:], nil
}

// Newest returns payloads from the newest record backwards until limit
// records or budget frame bytes are reached, then reverses them so that the
// oldest comes first.
func (s *diskStore) Newest(limit int, budget int64) []StoredPayload {
	s.mu.Lock()
	defer s.mu.Unlock()
	type item struct {
		pid uint64
		e   *indexEntry
	}
	var items []item
	for i := len(s.segs) - 1; i >= 0; i-- {
		seg := s.segs[i]
		for j := len(seg.pids) - 1; j >= 0; j-- {
			pid := seg.pids[j]
			if e := s.index[pid]; e != nil && e.seg == seg {
				items = append(items, item{pid, e})
			}
		}
	}
	// Segment order is write order, which is pid order.
	var out []StoredPayload
	var used int64
	for _, it := range items {
		if len(out) >= limit || (len(out) > 0 && used+it.e.size > budget) {
			break
		}
		payload, err := s.readLocked(it.e)
		if err != nil {
			continue
		}
		used += it.e.size
		out = append(out, StoredPayload{PID: it.pid, Saved: time.Unix(0, it.e.saved), Payload: payload})
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// StoredPayload is a record read back from disk.
type StoredPayload struct {
	PID     uint64
	Saved   time.Time
	Payload []byte
}

// Delete removes one record from disk by rewriting its segment without it.
func (s *diskStore) Delete(pid uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.index[pid]
	if e == nil {
		return ErrNotPersisted
	}
	seg := e.seg
	isActive := s.active != nil && seg == s.segs[len(s.segs)-1]
	if isActive {
		s.closeActiveLocked()
	}
	src, err := os.Open(s.path(seg))
	if err != nil {
		return err
	}
	defer src.Close()
	tmpPath := s.path(seg) + tempSuffix
	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return err
	}
	var written int64
	var pids []uint64
	var copyErr error
	moved := map[uint64]int64{}
	readFrames(src, func(h frameHeader, offset int64, payload []byte) {
		if copyErr != nil || h.pid == pid {
			return
		}
		frame := encodeFrame(h.pid, h.saved, payload)
		if _, copyErr = tmp.Write(frame); copyErr != nil {
			return
		}
		moved[h.pid] = written
		written += int64(len(frame))
		pids = append(pids, h.pid)
	})
	if copyErr == nil {
		copyErr = tmp.Sync()
	}
	_ = tmp.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return copyErr
	}
	if err = os.Rename(tmpPath, s.path(seg)); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	delete(s.index, pid)
	for _, p := range pids {
		if ie := s.index[p]; ie != nil && ie.seg == seg {
			ie.offset = moved[p]
		}
	}
	s.bytes += written - seg.size
	seg.size = written
	seg.pids = pids
	seg.live = 0
	for _, p := range pids {
		if ie := s.index[p]; ie != nil && ie.seg == seg {
			seg.live++
		}
	}
	if len(pids) == 0 {
		for i, candidate := range s.segs {
			if candidate == seg {
				s.removeSegmentLocked(i)
				break
			}
		}
	}
	return nil
}

// Purge deletes every file and forgets all records.
func (s *diskStore) Purge() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeActiveLocked()
	s.segs = nil
	s.index = make(map[uint64]*indexEntry)
	s.bytes = 0
	return purgeFiles(s.dir)
}

func (s *diskStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeActiveLocked()
	s.closed = true
}

// PurgeDir deletes the capture files in dir. Other files stay.
func PurgeDir(dir string) error {
	if dir == "" {
		return nil
	}
	return purgeFiles(dir)
}

func purgeFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var first error
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, segmentPrefix) || !(strings.HasSuffix(name, segmentSuffix) || strings.HasSuffix(name, tempSuffix)) {
			continue
		}
		if err = os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	return first
}
