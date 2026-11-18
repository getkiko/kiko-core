package mitm

import "github.com/sagernet/sing-box/common/mitm/h2"

const (
	h2ProfileDefault = "default"
	h2ProfileChrome  = "chrome"
)

// h2Profile is the h2 package's upstream client profile of a connection.
func h2Profile(config *compiledConfig) string {
	if config.upstream.h2Profile == h2ProfileChrome {
		return h2.ProfileChrome
	}
	return ""
}
