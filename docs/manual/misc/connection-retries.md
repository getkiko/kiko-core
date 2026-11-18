# Connection establishment retries

VLESS, VMess and ShadowTLS outbounds accept `handshake_retries` (default: `0`).
The value counts additional attempts after the first connection attempt.

Each retry establishes a fresh server connection. VLESS and VMess retry the
underlying dial, TLS handshake or transport connection; ShadowTLS also retries
its handshake. Protocol request writes and application traffic retain upstream
behavior. Established connections and traffic transfers are outside the retry loop.

With retries enabled, each attempt has a 10-second timeout. Context cancellation
stops subsequent attempts. Failed connections are closed, and errors marked
`NonRetryableError` stop the loop immediately.
