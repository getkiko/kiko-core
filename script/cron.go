package script

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// MaxCronLength is the longest cron expression accepted.
const MaxCronLength = 128

// CronSchedule is a parsed cron expression: five fields (minute, hour, day-of-month, month,
// day-of-week) or one of the macros, evaluated in the local time of the time it is asked
// about. The grammar is the one the app model mirrors:
//
//	field := item {"," item}
//	item  := "*" | n | a "-" b | "*" "/" step | a "-" b "/" step
//
// Month and day-of-week accept three-letter names (jan..dec, sun..sat, any case) wherever a
// number is allowed; day-of-week 7 is Sunday. "n/step" is not allowed. Macros: @hourly,
// @daily, @midnight, @weekly, @monthly, @yearly, @annually. When both day-of-month and
// day-of-week are restricted (neither field starts with "*") a day matches when either
// matches; otherwise both must match.
type CronSchedule struct {
	minute uint64 // bits 0..59
	hour   uint32 // bits 0..23
	dom    uint32 // bits 1..31
	month  uint16 // bits 1..12
	dow    uint8  // bits 0..6
	// either is set when both day fields are restricted.
	either bool
}

var cronMacros = map[string]string{
	"@hourly":   "0 * * * *",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@weekly":   "0 0 * * 0",
	"@monthly":  "0 0 1 * *",
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
}

var (
	monthNames = []string{"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"}
	dowNames   = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}
)

type cronField struct {
	name   string
	lo, hi int
	names  []string
	// nameBase is the value of names[0].
	nameBase int
}

var cronFields = [5]cronField{
	{name: "minute", lo: 0, hi: 59},
	{name: "hour", lo: 0, hi: 23},
	{name: "day-of-month", lo: 1, hi: 31},
	{name: "month", lo: 1, hi: 12, names: monthNames, nameBase: 1},
	{name: "day-of-week", lo: 0, hi: 7, names: dowNames, nameBase: 0},
}

// ParseCron parses expr. The error text is for logs and the config checker.
func ParseCron(expr string) (*CronSchedule, error) {
	if len(expr) > MaxCronLength {
		return nil, errors.New("cron expression too long")
	}
	for i := 0; i < len(expr); i++ {
		if expr[i] >= 0x80 || (expr[i] < 0x20 && expr[i] != '\t') || expr[i] == 0x7f {
			return nil, errors.New("cron expression has invalid characters")
		}
	}
	text := strings.Trim(expr, " \t")
	if text == "" {
		return nil, errors.New("cron expression is empty")
	}
	if text[0] == '@' {
		macro, ok := cronMacros[strings.ToLower(text)]
		if !ok {
			return nil, errors.New("unknown cron macro " + text)
		}
		text = macro
	}
	fields := strings.FieldsFunc(text, func(r rune) bool { return r == ' ' || r == '\t' })
	if len(fields) != 5 {
		return nil, errors.New("cron expression needs 5 fields (minute hour day-of-month month day-of-week)")
	}
	var bits [5]uint64
	for i, f := range fields {
		b, err := parseCronField(f, cronFields[i])
		if err != nil {
			return nil, errors.New(cronFields[i].name + ": " + err.Error())
		}
		bits[i] = b
	}
	s := &CronSchedule{minute: bits[0], hour: uint32(bits[1]), dom: uint32(bits[2]), month: uint16(bits[3])}
	// 7 is Sunday.
	dow := bits[4]
	if dow&(1<<7) != 0 {
		dow |= 1
	}
	s.dow = uint8(dow & 0x7f)
	s.either = fields[2][0] != '*' && fields[4][0] != '*'
	return s, nil
}

// ValidCron reports whether expr is a valid cron expression.
func ValidCron(expr string) error {
	_, err := ParseCron(expr)
	return err
}

func parseCronField(text string, f cronField) (uint64, error) {
	var bits uint64
	for _, item := range strings.Split(text, ",") {
		b, err := parseCronItem(item, f)
		if err != nil {
			return 0, err
		}
		bits |= b
	}
	return bits, nil
}

func parseCronItem(item string, f cronField) (uint64, error) {
	if item == "" {
		return 0, errors.New("empty list item")
	}
	rangePart, stepPart, hasStep := strings.Cut(item, "/")
	step := 1
	if hasStep {
		n, ok := cronNumber(stepPart)
		if !ok || n < 1 || n > f.hi-f.lo+1 {
			return 0, errors.New("invalid step " + strconv.Quote(stepPart))
		}
		step = n
	}
	var lo, hi int
	switch {
	case rangePart == "*":
		lo, hi = f.lo, f.hi
		if f.name == "day-of-week" {
			hi = 6
		}
	case strings.Contains(rangePart, "-"):
		a, b, _ := strings.Cut(rangePart, "-")
		var ok bool
		if lo, ok = cronValue(a, f); !ok {
			return 0, errors.New("invalid value " + strconv.Quote(a))
		}
		if hi, ok = cronValue(b, f); !ok {
			return 0, errors.New("invalid value " + strconv.Quote(b))
		}
		if lo > hi {
			return 0, errors.New("range " + strconv.Quote(rangePart) + " is backwards")
		}
	default:
		if hasStep {
			return 0, errors.New("a step needs * or a range")
		}
		v, ok := cronValue(rangePart, f)
		if !ok {
			return 0, errors.New("invalid value " + strconv.Quote(rangePart))
		}
		lo, hi = v, v
	}
	var bits uint64
	for v := lo; v <= hi; v += step {
		bits |= 1 << uint(v)
	}
	return bits, nil
}

// cronNumber reads a plain decimal number of at most three digits.
func cronNumber(s string) (int, bool) {
	if s == "" || len(s) > 3 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

func cronValue(s string, f cronField) (int, bool) {
	if n, ok := cronNumber(s); ok {
		return n, n >= f.lo && n <= f.hi
	}
	if f.names != nil && len(s) == 3 {
		lower := strings.ToLower(s)
		for i, name := range f.names {
			if name == lower {
				return f.nameBase + i, true
			}
		}
	}
	return 0, false
}

// matchesDay reports whether the day of w is selected.
func (s *CronSchedule) matchesDay(w time.Time) bool {
	dom := s.dom&(1<<uint(w.Day())) != 0
	dow := s.dow&(1<<uint(w.Weekday())) != 0
	if s.either {
		return dom || dow
	}
	return dom && dow
}

// cronHorizon bounds the search for a matching day (an expression like "0 0 30 2 *" never
// matches).
const cronHorizon = 10

// nextNaive returns the first calendar time >= w (treated as UTC, so no DST applies) that
// the schedule selects, or the zero time when none exists within cronHorizon years.
func (s *CronSchedule) nextNaive(w time.Time) time.Time {
	limit := w.Year() + cronHorizon
	for w.Year() <= limit {
		if s.month&(1<<uint(w.Month())) == 0 {
			w = time.Date(w.Year(), w.Month()+1, 1, 0, 0, 0, 0, time.UTC)
			continue
		}
		if !s.matchesDay(w) {
			w = time.Date(w.Year(), w.Month(), w.Day()+1, 0, 0, 0, 0, time.UTC)
			continue
		}
		if s.hour&(1<<uint(w.Hour())) == 0 {
			w = time.Date(w.Year(), w.Month(), w.Day(), w.Hour()+1, 0, 0, 0, time.UTC)
			continue
		}
		if s.minute&(1<<uint(w.Minute())) == 0 {
			w = w.Add(time.Minute)
			continue
		}
		return w
	}
	return time.Time{}
}

// Next returns the first time strictly after `after` at which the schedule fires, in the
// location of `after`, or the zero time when there is none. Times are wall-clock times of
// that location: a time that does not exist (spring forward) is skipped, and a time that
// occurs twice (fall back) fires once, at its first occurrence.
func (s *CronSchedule) Next(after time.Time) time.Time {
	loc := after.Location()
	y, mo, d := after.Date()
	w := time.Date(y, mo, d, after.Hour(), after.Minute()+1, 0, 0, time.UTC)
	for i := 0; i < 100000; i++ {
		n := s.nextNaive(w)
		if n.IsZero() {
			return time.Time{}
		}
		if t, ok := firstInstant(n, loc); ok && t.After(after) {
			return t
		}
		w = n.Add(time.Minute)
	}
	return time.Time{}
}

// firstInstant maps the wall-clock time n (a UTC-labelled calendar time) in loc to the
// earliest instant showing that wall time; ok is false when loc has no such time.
func firstInstant(n time.Time, loc *time.Location) (time.Time, bool) {
	guess := time.Date(n.Year(), n.Month(), n.Day(), n.Hour(), n.Minute(), 0, 0, loc)
	naive := n.Unix()
	var best time.Time
	found := false
	seen := [3]int{}
	for i, probe := range []time.Time{guess, guess.Add(-24 * time.Hour), guess.Add(24 * time.Hour)} {
		_, off := probe.Zone()
		dup := false
		for j := 0; j < i; j++ {
			if seen[j] == off {
				dup = true
			}
		}
		seen[i] = off
		if dup {
			continue
		}
		cand := time.Unix(naive-int64(off), 0).In(loc)
		if cand.Year() != n.Year() || cand.Month() != n.Month() || cand.Day() != n.Day() || cand.Hour() != n.Hour() || cand.Minute() != n.Minute() {
			continue
		}
		if !found || cand.Before(best) {
			best, found = cand, true
		}
	}
	return best, found
}
