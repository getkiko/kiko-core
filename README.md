# sing-box

The universal proxy platform.

## About this fork

This repository is a fork of [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
maintained for [Kiko](https://github.com/getkiko/kiko). It is not an official
sing-box release and is not endorsed by the sing-box authors.

The `kiko` branch is based on the upstream tag `v1.14.4`. The upstream history is
kept unchanged; the Kiko changes are a small series of commits on top of the tag.

Additions:

* Burrow inbound and outbound (`"type": "burrow"`): TCP and UDP NAT traversal
  through [Burrow](https://github.com/getkiko/burrow)
* HTTPS decryption: certificate authority management, HTTP/1.1 and HTTP/2
  relays, header and body rewrites, HTTP capture and request replay
* Script engine: JavaScript request, response, cron, rule and DNS scripts
* Policy groups: `fallback`, `loadbalance` and `smart`, with shared member health
* Live configuration apply for route, outbounds and DNS without a restart
* DNS monitoring service and concurrent queries across several DNS servers
* Rule set overrides, manual rule set updates and a rule set content API
* Connection establishment retries (`handshake_retries`) for VLESS, VMess and
  ShadowTLS
* Tailscale: per-peer UDP paths through a detour, TCP congestion control choice
  and network diagnostics
* `override_destination` for the `sniff` route action
* Fixes: selector and URLTest connection interruption, transactional reload,
  Reality handshake compatibility with the Xray post-quantum key exchange and
  macOS connection owner PIDs

### Following upstream

To move to a new upstream release, fetch the new tag and rebase the Kiko commits
onto it:

```shell
git remote add upstream https://github.com/SagerNet/sing-box.git
git fetch upstream --tags
git rebase --onto v1.x.y v1.14.4 kiko
```

Resolve conflicts commit by commit, build and test, and update the base tag named
above. `go.mod` points `github.com/getkiko/burrow` at `../burrow` for local
development; releases pin a tagged Burrow version instead.

### License

The fork keeps the upstream license, GPL-3.0-or-later, as stated below.

[![Packaging status](https://repology.org/badge/vertical-allrepos/sing-box.svg)](https://repology.org/project/sing-box/versions)

## Documentation

https://sing-box.sagernet.org

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```