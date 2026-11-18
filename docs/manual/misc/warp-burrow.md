# Burrow over WARP

This setup gives the burrow TCP sockets a Cloudflare WARP IPv6 path through a system WireGuard interface. Cloudflare only provides the WARP tunnel; both participating devices run burrow and connect to the same IPv6-capable signal server.

WireGuard uses UDP for the outer WARP tunnel. The burrow protocol in this setup uses TCP only.

## Generate WARP credentials

Generate a WireGuard profile with [wgcf](https://github.com/ViRb3/wgcf):

```shell
wgcf register
wgcf generate
```

Read the following values from `wgcf-profile.conf`:

| wgcf field | sing-box field |
|---|---|
| `[Interface] PrivateKey` | `private_key` |
| `[Interface] Address` | `address` |
| `[Peer] PublicKey` | `peers[].public_key` |
| `[Peer] Endpoint` | `peers[].address` and `peers[].port` |

## Configuration

Replace every angle-bracket placeholder. `physical-interface` is the interface used by the outer WireGuard connection, such as `eth0` or `wlan0`.

```json
{
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "warp",
      "system": true,
      "name": "warp0",
      "mtu": 1280,
      "address": [
        "<wgcf-ipv4>/32",
        "<wgcf-ipv6>/128"
      ],
      "private_key": "<wgcf-private-key>",
      "peers": [
        {
          "address": "<warp-endpoint-host>",
          "port": 2408,
          "public_key": "<warp-peer-public-key>",
          "allowed_ips": ["0.0.0.0/0", "::/0"],
          "persistent_keepalive_interval": 25
        }
      ],
      "bind_interface": "<physical-interface>"
    }
  ],
  "outbounds": [
    {
      "type": "burrow",
      "tag": "burrow-warp",
      "server": "<signal-server-with-aaaa-record>",
      "server_port": 9960,
      "room": "<shared-room>",
      "network": ["tcp"],
      "bind_interface": "warp0",
      "address_family": "ipv6"
    }
  ]
}
```

`address_family: "ipv6"` applies to the TCP signal connection, mapping probe, listener, and active dial sockets. All of them bind to the global IPv6 address on `warp0` and reuse the selected local TCP port.

## Verify

Start sing-box with the privileges required to create a system interface, then verify the interface and WARP egress:

```shell
ip -6 addr show dev warp0
curl --interface warp0 -6 https://www.cloudflare.com/cdn-cgi/trace
```

Run the same setup with separate WARP registrations on both participating devices. Use the same room and signal server on both sides. A successful end-to-end test also confirms that the active Cloudflare WARP edge preserves a usable TCP mapping and delivers the simultaneous-open SYN traffic.
