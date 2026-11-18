package hostmatch

import (
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// Categories of built-in exclusion entries.
const (
	CategoryApple     = "apple"
	CategoryGoogle    = "google"
	CategoryMicrosoft = "microsoft"
	CategoryBrowser   = "browser"
	CategoryMessaging = "messaging"
	CategorySocial    = "social"
	CategoryStorage   = "storage"
	CategoryPKI       = "pki"
	CategorySecurity  = "security"
	CategoryBanking   = "banking"
)

// BuiltinEntry is one built-in exclusion: hosts that pin certificates or
// break under decryption, which the default configuration passes through.
type BuiltinEntry struct {
	// ID names the entry in hostnames.disabled_builtin.
	ID       string
	Category string
	// Patterns use the host entry syntax of New, without ports: a built-in
	// entry applies to every port.
	Patterns []string
}

// Precedence of the built-in table (see Matcher.Verdict):
//
//  1. A user exclude entry always excludes.
//  2. A host that no include entry matches is not decrypted.
//  3. An included host that matches a built-in pattern is not decrypted,
//     unless an include entry names that host exactly ("push.apple.com",
//     not "*.apple.com"), or the entry (or the matching pattern) is listed
//     in disabled_builtin.
//
// A wildcard include such as "*.apple.com" therefore never overrides the
// table; route-options `mitm: force` bypasses it, like the skip table.
var builtinEntries = buildBuiltinTable()

func buildBuiltinTable() []BuiltinEntry {
	var entries []BuiltinEntry
	// domain adds the apex and every subdomain of each domain.
	domain := func(id, category string, domains ...string) {
		patterns := make([]string, 0, len(domains)*2)
		for _, name := range domains {
			patterns = append(patterns, name, "*."+name)
		}
		entries = append(entries, BuiltinEntry{ID: id, Category: category, Patterns: patterns})
	}
	// host adds the listed names only.
	host := func(id, category string, hosts ...string) {
		entries = append(entries, BuiltinEntry{ID: id, Category: category, Patterns: hosts})
	}

	domain("apple-push", CategoryApple, "push.apple.com", "push-apple.com.akadns.net")
	domain("apple-icloud", CategoryApple, "icloud.com", "icloud-content.com", "apple-cloudkit.com", "me.com")
	domain("apple-ess", CategoryApple, "ess.apple.com")
	domain("apple-store", CategoryApple, "itunes.apple.com", "mzstatic.com", "apps.apple.com", "phobos.apple.com", "appstore.com")
	host("apple-update", CategoryApple,
		"swscan.apple.com", "swdist.apple.com", "swcdn.apple.com", "mesu.apple.com", "gdmf.apple.com",
		"osrecovery.apple.com", "oscdn.apple.com", "updates.cdn-apple.com", "updates-http.cdn-apple.com",
		"configuration.apple.com", "xp.apple.com", "init.ess.apple.com")
	host("apple-identity", CategoryApple,
		"gsa.apple.com", "appleid.apple.com", "idmsa.apple.com", "albert.apple.com", "ppq.apple.com",
		"valid.apple.com", "gs-loc.apple.com", "iphone-ld.apple.com", "gspe1-ssl.ls.apple.com",
		"gspe35-ssl.ls.apple.com", "api.apple-cloudkit.com", "identity.apple.com")
	host("apple-pki", CategoryApple, "ocsp.apple.com", "crl.apple.com", "ocsp2.apple.com", "certs.apple.com")

	host("google-mtalk", CategoryGoogle,
		"mtalk.google.com", "mtalk4.google.com", "alt1-mtalk.google.com", "alt2-mtalk.google.com",
		"alt3-mtalk.google.com", "alt4-mtalk.google.com", "alt5-mtalk.google.com", "alt6-mtalk.google.com",
		"alt7-mtalk.google.com", "alt8-mtalk.google.com")
	host("google-gms", CategoryGoogle,
		"android.googleapis.com", "androidcheckin.googleapis.com", "device-provisioning.googleapis.com",
		"fcm.googleapis.com", "firebaseinstallations.googleapis.com", "android.clients.google.com",
		"android.apis.google.com", "mobilesdk-pa.googleapis.com", "growth-pa.googleapis.com")
	host("google-play", CategoryGoogle,
		"play.googleapis.com", "play-fe.googleapis.com", "play-games.googleusercontent.com",
		"androidmanagement.googleapis.com", "playatoms-pa.googleapis.com")
	host("google-update", CategoryGoogle,
		"update.googleapis.com", "clients2.google.com", "clients4.google.com", "dl.google.com",
		"tools.google.com", "redirector.gvt1.com", "sb-ssl.google.com", "safebrowsing.googleapis.com")
	domain("google-gvt", CategoryGoogle, "gvt1.com", "gvt2.com")
	host("google-youtube", CategoryGoogle, "youtubei.googleapis.com", "s.youtube.com")

	host("microsoft-update", CategoryMicrosoft,
		"update.microsoft.com", "download.microsoft.com", "dl.delivery.mp.microsoft.com", "delivery.mp.microsoft.com",
		"fe2.update.microsoft.com", "sls.update.microsoft.com", "tsfe.trafficshaping.dsp.mp.microsoft.com")
	domain("microsoft-windowsupdate", CategoryMicrosoft, "windowsupdate.com", "update.microsoft.com", "wns.windows.com")
	host("microsoft-login", CategoryMicrosoft,
		"login.live.com", "login.microsoftonline.com", "login.windows.net", "device.login.microsoftonline.com",
		"enterpriseregistration.windows.net", "activity.windows.com")
	host("microsoft-telemetry", CategoryMicrosoft,
		"settings-win.data.microsoft.com", "vortex-win.data.microsoft.com", "watson.telemetry.microsoft.com")
	domain("microsoft-connectivity", CategoryMicrosoft, "msftconnecttest.com")

	host("mozilla", CategoryBrowser,
		"aus5.mozilla.org", "download.mozilla.org", "firefox.settings.services.mozilla.com",
		"content-signature-2.cdn.mozilla.net", "push.services.mozilla.com", "shavar.services.mozilla.com")
	domain("mozilla-cdn", CategoryBrowser, "cdn.mozilla.net")

	domain("signal", CategoryMessaging, "signal.org", "whispersystems.org")
	domain("whatsapp", CategoryMessaging, "whatsapp.net")
	domain("telegram", CategoryMessaging, "telegram.org", "telegram.me")
	host("line", CategoryMessaging, "line-apps.com", "legy-jp.line-apps.com", "gd2.line.naver.jp")

	host("facebook-apps", CategorySocial,
		"graph.facebook.com", "b-graph.facebook.com", "edge-mqtt.facebook.com", "mqtt-mini.facebook.com",
		"graph.instagram.com", "i.instagram.com", "b.i.instagram.com")

	domain("dropbox", CategoryStorage, "dropbox.com", "dropboxapi.com", "dropboxstatic.com")

	host("pki-digicert", CategoryPKI,
		"ocsp.digicert.com", "crl3.digicert.com", "crl4.digicert.com", "cacerts.digicert.com")
	host("pki-sectigo", CategoryPKI,
		"ocsp.sectigo.com", "crl.sectigo.com", "ocsp.comodoca.com", "crl.comodoca.com", "ocsp.usertrust.com",
		"crl.usertrust.com")
	host("pki-globalsign", CategoryPKI,
		"ocsp.globalsign.com", "ocsp2.globalsign.com", "crl.globalsign.com", "crl.globalsign.net")
	host("pki-misc", CategoryPKI,
		"ocsp.entrust.net", "crl.entrust.net", "ocsp.godaddy.com", "crl.godaddy.com", "ocsp.starfieldtech.com",
		"ocsp.msocsp.com", "crl.microsoft.com", "ocsp.rootca1.amazontrust.com", "ocsp.r2m01.amazontrust.com",
		"ocsp.int-x3.letsencrypt.org", "ocsp.pki.goog", "crl.pki.goog")
	domain("pki-lets-encrypt", CategoryPKI, "o.lencr.org", "c.lencr.org")
	host("pki-microsoft", CategoryPKI, "ctldl.windowsupdate.com")

	domain("password-managers", CategorySecurity, "1password.com", "1password.eu", "bitwarden.com", "lastpass.com", "keepersecurity.com")

	domain("banking-us", CategoryBanking, "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com")
	domain("banking-cn", CategoryBanking, "alipay.com", "icbc.com.cn", "ccb.com", "boc.cn", "abchina.com", "cmbchina.com")

	return entries
}

// BuiltinCount is the number of built-in exclusion entries.
func BuiltinCount() int {
	return len(builtinEntries)
}

// Builtin lists the built-in exclusion entries. The result is a copy.
func Builtin() []BuiltinEntry {
	entries := make([]BuiltinEntry, len(builtinEntries))
	for i, entry := range builtinEntries {
		entry.Patterns = append([]string(nil), entry.Patterns...)
		entries[i] = entry
	}
	return entries
}

// compileBuiltin builds the set of enabled built-in patterns. disabled names
// entries by id or single patterns; a name that is neither is an error.
func compileBuiltin(disabled []string) (set, error) {
	var disabledEntries, disabledPatterns map[string]struct{}
	found := make(map[string]bool, len(disabled))
	for _, name := range disabled {
		name = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(name, ".")))
		if name == "" {
			return set{}, E.New("empty built-in entry")
		}
		found[name] = false
	}
	if len(found) > 0 {
		disabledEntries = make(map[string]struct{})
		disabledPatterns = make(map[string]struct{})
		for name := range found {
			for _, entry := range builtinEntries {
				if entry.ID == name {
					disabledEntries[name] = struct{}{}
					found[name] = true
				}
				for _, pattern := range entry.Patterns {
					if pattern == name {
						disabledPatterns[name] = struct{}{}
						found[name] = true
					}
				}
			}
		}
		for name, ok := range found {
			if !ok {
				return set{}, E.New("unknown built-in entry ", name)
			}
		}
	}
	var enabled set
	for _, entry := range builtinEntries {
		if _, skip := disabledEntries[entry.ID]; skip {
			continue
		}
		for _, pattern := range entry.Patterns {
			if _, skip := disabledPatterns[pattern]; skip {
				continue
			}
			if err := enabled.add(pattern); err != nil {
				return set{}, E.Cause(err, "built-in ", entry.ID, " ", pattern)
			}
		}
	}
	return enabled, nil
}

// EnabledBuiltinCount is the number of built-in entries that keep at least
// one pattern when disabled entries (by id or pattern) are removed. Unknown
// names are ignored.
func EnabledBuiltinCount(disabled []string) int {
	disabledNames := make(map[string]struct{}, len(disabled))
	for _, name := range disabled {
		disabledNames[strings.ToLower(strings.TrimSpace(strings.TrimSuffix(name, ".")))] = struct{}{}
	}
	count := 0
	for _, entry := range builtinEntries {
		if _, off := disabledNames[entry.ID]; off {
			continue
		}
		for _, pattern := range entry.Patterns {
			if _, off := disabledNames[pattern]; !off {
				count++
				break
			}
		}
	}
	return count
}
