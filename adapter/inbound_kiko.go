package adapter

// InboundKikoInternal is the inbound name of connections the core opens for
// the application itself (HTTP replay). They are routed like any other
// connection but never decrypted.
const InboundKikoInternal = "kiko-internal"

// InboundKikoScript is the inbound name of the connections of the script
// $httpClient; they are internal connections too, and the user field carries
// the tag of the script.
const InboundKikoScript = "kiko-script"
