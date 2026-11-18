package adapter

// InboundKikoInternal is the inbound name of connections the core opens for
// the application itself (HTTP replay). They are routed like any other
// connection but never decrypted.
const InboundKikoInternal = "kiko-internal"
