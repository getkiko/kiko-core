package script

import (
	"strings"
	"testing"
	"time"
)

func TestCronGrammar(t *testing.T) {
	valid := []string{
		"* * * * *", "*/5 * * * *", "0 0 1 1 *", "0-59/15 * * * *", "1,2,3 * * * *", "0 0 * * mon-fri",
		"0 0 * JAN,feb *", "0 0 * * 7", "0 0 * * 0-7", "0 0 * * Sun", "  0 0 * * *  ", "0\t0\t*\t*\t*",
		"@hourly", "@daily", "@midnight", "@weekly", "@monthly", "@yearly", "@annually", "@DAILY", " @hourly ",
		"05 08 * * *", "*/60 * * * *", "* */24 * * *", "* * */31 * *", "* * * */12 *", "* * * * */8",
		"0 0 29 2 *", "0 0 31 2 *", "1-5,10-20/2,30 * * * *", "0 0 * * 5-7", "0 0 * mar-may *", "*,5 * * * *",
		"0 0 * * SAT,sun", "59 23 31 12 *", "0 0 1,15 * *", "0 0 * * */2",
	}
	for _, expr := range valid {
		if _, err := ParseCron(expr); err != nil {
			t.Errorf("%q: %v", expr, err)
		}
	}
	invalid := []string{
		"", " ", "\t", "* * * *", "* * * * * *", "0 0 0 * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * 32 * *",
		"* * * 0 *", "* * * 13 *", "* * * * 8", "5/10 * * * *", "0 0 ? * *", "0 0 * * ?", "L * * * *", "0 0 L * *",
		"0 0 15W * *", "0 0 * * 5#2", "0 0 * * 5L", "@every 5m", "@reboot", "@", "@hourly extra", "*/0 * * * *",
		"*/ * * * *", "1-5-7 * * * *", "5-1 * * * *", ",1 * * * *", "1,,2 * * * *", "1, * * * *", "-1 * * * *",
		"+1 * * * *", "1.5 * * * *", "jan * * * *", "* mon * * *", "* * * foo *", "* * * * sunday", "* * * * sun-",
		"* * * jan- *", "0 0 * * * # c", "*/61 * * * *", "* */25 * * *", "* * */32 * *", "* * * */13 *", "* * * * */9",
		"1/5 * * * *", "1-10/ * * * *", "0 0 * * 0-8", "0 0 * * 1000", "99999 * * * *", "0 0 * * *\n0",
		"0 0 * * * \x00", "0 0 * * é", "*/-1 * * * *", "*-5 * * * *", "0 0 1-2-3 * *", "0 0 * * mon/2",
		strings.Repeat("*", 129), "* * * * " + strings.Repeat(" ", 130),
	}
	for _, expr := range invalid {
		if _, err := ParseCron(expr); err == nil {
			t.Errorf("%q accepted", expr)
		}
	}
	long := "*/5 " + strings.Repeat(" ", MaxCronLength-len("*/5 * * * *")) + "* * * *"
	if len(long) != MaxCronLength {
		t.Fatalf("test expression is %d long", len(long))
	}
	if _, err := ParseCron(long); err != nil {
		t.Errorf("128 characters: %v", err)
	}
	if _, err := ParseCron(long + " "); err == nil {
		t.Error("129 characters accepted")
	}
}

func mustCron(t *testing.T, expr string) *CronSchedule {
	t.Helper()
	s, err := ParseCron(expr)
	if err != nil {
		t.Fatalf("%q: %v", expr, err)
	}
	return s
}

func ymd(loc *time.Location, y int, mo time.Month, d, h, mi, s int) time.Time {
	return time.Date(y, mo, d, h, mi, s, 0, loc)
}

func TestCronNext(t *testing.T) {
	utc := time.UTC
	cases := []struct {
		expr  string
		after time.Time
		want  time.Time
	}{
		{"*/15 * * * *", ymd(utc, 2026, 11, 4, 10, 7, 30), ymd(utc, 2026, 11, 4, 10, 15, 0)},
		{"*/15 * * * *", ymd(utc, 2026, 11, 4, 10, 15, 0), ymd(utc, 2026, 11, 4, 10, 30, 0)},
		{"*/15 * * * *", ymd(utc, 2026, 11, 4, 10, 59, 59), ymd(utc, 2026, 11, 4, 11, 0, 0)},
		{"* * * * *", ymd(utc, 2026, 11, 4, 23, 59, 0), ymd(utc, 2026, 11, 5, 0, 0, 0)},
		{"0 0 1 * *", ymd(utc, 2026, 1, 31, 12, 0, 0), ymd(utc, 2026, 2, 1, 0, 0, 0)},
		{"0 0 1 * *", ymd(utc, 2026, 12, 31, 23, 59, 0), ymd(utc, 2027, 1, 1, 0, 0, 0)},
		{"0 0 31 * *", ymd(utc, 2026, 4, 1, 0, 0, 0), ymd(utc, 2026, 5, 31, 0, 0, 0)},
		{"0 12 * * mon-fri", ymd(utc, 2026, 11, 6, 12, 0, 0), ymd(utc, 2026, 11, 9, 12, 0, 0)},
		{"30 8 * * 7", ymd(utc, 2026, 11, 4, 0, 0, 0), ymd(utc, 2026, 11, 8, 8, 30, 0)},
		{"30 8 * * 0", ymd(utc, 2026, 11, 4, 0, 0, 0), ymd(utc, 2026, 11, 8, 8, 30, 0)},
		{"@weekly", ymd(utc, 2026, 11, 4, 0, 0, 0), ymd(utc, 2026, 11, 8, 0, 0, 0)},
		{"@monthly", ymd(utc, 2026, 11, 4, 0, 0, 0), ymd(utc, 2026, 12, 1, 0, 0, 0)},
		{"@yearly", ymd(utc, 2026, 11, 4, 0, 0, 0), ymd(utc, 2027, 1, 1, 0, 0, 0)},
		{"@hourly", ymd(utc, 2026, 11, 4, 0, 0, 0), ymd(utc, 2026, 11, 4, 1, 0, 0)},
		{"0 0 * jan,jul *", ymd(utc, 2026, 11, 4, 0, 0, 0), ymd(utc, 2027, 1, 1, 0, 0, 0)},
		// Day of month and day of week both restricted: either matches. 2026-11-06 is a
		// Friday, 2026-12-13 a Sunday.
		{"0 0 13 * fri", ymd(utc, 2026, 11, 1, 0, 0, 0), ymd(utc, 2026, 11, 6, 0, 0, 0)},
		{"0 0 13 * fri", ymd(utc, 2026, 11, 6, 0, 0, 0), ymd(utc, 2026, 11, 13, 0, 0, 0)},
		{"0 0 13 * fri", ymd(utc, 2026, 12, 11, 0, 0, 0), ymd(utc, 2026, 12, 13, 0, 0, 0)},
		// A field that starts with * does not count as restricted: both must match.
		{"0 0 13 * */2", ymd(utc, 2026, 11, 1, 0, 0, 0), ymd(utc, 2026, 12, 13, 0, 0, 0)},
		{"0 0 * * *", ymd(utc, 2026, 11, 4, 0, 0, 0), ymd(utc, 2026, 11, 5, 0, 0, 0)},
		// Leap days.
		{"0 0 29 2 *", ymd(utc, 2026, 3, 1, 0, 0, 0), ymd(utc, 2028, 2, 29, 0, 0, 0)},
		{"0 0 29 2 *", ymd(utc, 2096, 3, 1, 0, 0, 0), ymd(utc, 2104, 2, 29, 0, 0, 0)},
		{"0 0 29 2 *", ymd(utc, 2028, 2, 29, 0, 0, 0), ymd(utc, 2032, 2, 29, 0, 0, 0)},
		// Sub-minute parts of after are dropped.
		{"* * * * *", ymd(utc, 2026, 11, 4, 10, 0, 59), ymd(utc, 2026, 11, 4, 10, 1, 0)},
	}
	for _, c := range cases {
		got := mustCron(t, c.expr).Next(c.after)
		if !got.Equal(c.want) {
			t.Errorf("%q after %s: got %s, want %s", c.expr, c.after, got, c.want)
		}
	}
	if got := mustCron(t, "0 0 30 2 *").Next(ymd(utc, 2026, 1, 1, 0, 0, 0)); !got.IsZero() {
		t.Errorf("never-matching expression fired at %s", got)
	}
	if got := mustCron(t, "0 0 31 4,6,9,11 *").Next(ymd(utc, 2026, 1, 1, 0, 0, 0)); !got.IsZero() {
		t.Errorf("never-matching expression fired at %s", got)
	}
}

func TestCronDST(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no tz database:", err)
	}
	at := func(y int, mo time.Month, d, h, mi int) time.Time { return time.Date(y, mo, d, h, mi, 0, 0, ny) }
	utcIn := func(y int, mo time.Month, d, h, mi int) time.Time {
		return time.Date(y, mo, d, h, mi, 0, 0, time.UTC).In(ny)
	}
	// Spring forward 2026-03-08: 02:00-03:00 does not exist.
	if got, want := mustCron(t, "30 2 * * *").Next(at(2026, 3, 7, 3, 0)), at(2026, 3, 9, 2, 30); !got.Equal(want) {
		t.Errorf("nonexistent time: got %s, want %s", got, want)
	}
	if got, want := mustCron(t, "30 1 * * *").Next(at(2026, 3, 7, 3, 0)), at(2026, 3, 8, 1, 30); !got.Equal(want) {
		t.Errorf("before the gap: got %s, want %s", got, want)
	}
	if got, want := mustCron(t, "0 3 * * *").Next(at(2026, 3, 7, 4, 0)), at(2026, 3, 8, 3, 0); !got.Equal(want) {
		t.Errorf("after the gap: got %s, want %s", got, want)
	}
	// Every 15 minutes across the gap: 01:45 is followed by 03:00.
	if got, want := mustCron(t, "*/15 * * * *").Next(at(2026, 3, 8, 1, 45)), at(2026, 3, 8, 3, 0); !got.Equal(want) {
		t.Errorf("minutes across the gap: got %s, want %s", got, want)
	}
	// Fall back 2026-11-01: 01:00-02:00 happens twice (EDT first). A repeated time runs once,
	// at its first occurrence.
	first := utcIn(2026, 11, 1, 5, 30) // 01:30 EDT
	if got := mustCron(t, "30 1 * * *").Next(at(2026, 10, 31, 12, 0)); !got.Equal(first) {
		t.Errorf("repeated time: got %s, want %s", got, first)
	}
	if got, want := mustCron(t, "30 1 * * *").Next(first), at(2026, 11, 2, 1, 30); !got.Equal(want) {
		t.Errorf("after the first occurrence: got %s, want %s", got, want)
	}
	// During the second pass (01:10 EST) the 01:30 tick has already run.
	second := utcIn(2026, 11, 1, 6, 10)
	if got, want := mustCron(t, "30 1 * * *").Next(second), at(2026, 11, 2, 1, 30); !got.Equal(want) {
		t.Errorf("second pass: got %s, want %s", got, want)
	}
	// Hourly: the repeated 01:00 does not run twice.
	if got, want := mustCron(t, "0 * * * *").Next(utcIn(2026, 11, 1, 5, 0)), utcIn(2026, 11, 1, 7, 0); !got.Equal(want) {
		t.Errorf("hourly in the repeated hour: got %s, want %s", got, want)
	}
	// 02:30 exists once on that day.
	if got, want := mustCron(t, "30 2 * * *").Next(at(2026, 10, 31, 12, 0)), utcIn(2026, 11, 1, 7, 30); !got.Equal(want) {
		t.Errorf("after the repeated hour: got %s, want %s", got, want)
	}
	// Half-hour shift (Lord Howe): 02:00-02:30 does not exist on 2026-10-04.
	if lh, err := time.LoadLocation("Australia/Lord_Howe"); err == nil {
		got := mustCron(t, "15 2 * * *").Next(time.Date(2026, 10, 3, 12, 0, 0, 0, lh))
		want := time.Date(2026, 10, 5, 2, 15, 0, 0, lh)
		if !got.Equal(want) {
			t.Errorf("Lord Howe: got %s, want %s", got, want)
		}
	}
}

func TestCronNextIsStrictlyIncreasing(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no tz database:", err)
	}
	for _, expr := range []string{"* * * * *", "*/7 * * * *", "30 1 * * *", "0 * * * *", "15 2 * * *", "0 0 * * *"} {
		s := mustCron(t, expr)
		cur := time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC).In(ny)
		end := cur.AddDate(0, 0, 3)
		for n := 0; cur.Before(end); n++ {
			next := s.Next(cur)
			if !next.After(cur) {
				t.Fatalf("%q: Next(%s) = %s", expr, cur, next)
			}
			cur = next
			if n > 5000 {
				break
			}
		}
		cur = time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC).In(ny)
		end = cur.AddDate(0, 0, 3)
		for n := 0; cur.Before(end) && n < 5000; n++ {
			next := s.Next(cur)
			if !next.After(cur) {
				t.Fatalf("%q: Next(%s) = %s", expr, cur, next)
			}
			cur = next
		}
	}
}

func FuzzParseCron(f *testing.F) {
	for _, seed := range []string{"* * * * *", "*/5 0-6 1,15 jan-mar mon-fri", "@daily", "0 0 29 2 *", "", "5/10 * * * *", "1-5/2 * * * *"} {
		f.Add(seed)
	}
	base := time.Date(2026, 11, 4, 10, 7, 30, 0, time.UTC)
	f.Fuzz(func(t *testing.T, expr string) {
		s, err := ParseCron(expr)
		if err != nil {
			return
		}
		if len(expr) > MaxCronLength {
			t.Fatalf("accepted %d bytes", len(expr))
		}
		next := s.Next(base)
		if next.IsZero() {
			return
		}
		if !next.After(base) || next.Second() != 0 || next.Nanosecond() != 0 {
			t.Fatalf("%q: Next = %s", expr, next)
		}
		if next2 := s.Next(next); !next2.After(next) {
			t.Fatalf("%q: not increasing: %s then %s", expr, next, next2)
		}
	})
}
