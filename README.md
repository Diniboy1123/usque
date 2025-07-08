# usque

🥚➡️🍏🍎

Usque is an open-source reimplementation of the Cloudflare WARP client's MASQUE mode. It leverages the [Connnect-IP (RFC 9484)](https://datatracker.ietf.org/doc/rfc9484/) protocol and comes with many operation modes including a native tunnel (currently Linux only), a SOCKS5 proxy, and a HTTP proxy.

## Table of Contents

- [usque](#usque)
          - [🥚➡️🍏🍎](#️)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Building from source](#building-from-source)
    - [Docker](#docker)
  - [Usage](#usage)
    - [Registration](#registration)
    - [Enrolling](#enrolling)
    - [Native Tunnel Mode (for Advanced Users, Linux and Windows only!)](#native-tunnel-mode-for-advanced-users-linux-and-windows-only)
      - [On Linux](#on-linux)
      - [On Windows](#on-windows)
      - [Routes on Linux](#routes-on-linux)
      - [Routes on Windows](#routes-on-windows)
    - [SOCKS5 Proxy Mode (easy, cross-platform)](#socks5-proxy-mode-easy-cross-platform)
    - [HTTP Proxy Mode (easy, cross-platform)](#http-proxy-mode-easy-cross-platform)
    - [Port Forwarding Mode (for Advanced Users, cross-platform)](#port-forwarding-mode-for-advanced-users-cross-platform)
    - [Configuration](#configuration)
      - [Fields](#fields)
  - [ZeroTrust support](#zerotrust-support)
  - [Performance](#performance)
    - [Performance Tuning](#performance-tuning)
      - [Linux/BSD](#linuxbsd)
      - [DNS](#dns)
  - [Using this tool as a library](#using-this-tool-as-a-library)
  - [Known Issues](#known-issues)
  - [Miscellaneous](#miscellaneous)
    - [Censorship circumvention](#censorship-circumvention)
  - [Should I replace WireGuard with this?](#should-i-replace-wireguard-with-this)
    - [Why would you still switch?](#why-would-you-still-switch)
  - [Protocol \& research details](#protocol--research-details)
  - [Why was this built?](#why-was-this-built)
  - [Why the name?](#why-the-name)
  - [Contributing](#contributing)
  - [Acknowledgements](#acknowledgements)
  - [Disclaimer](#disclaimer)

## Installation

You can download the latest release from the [releases page](https://github.com/Diniboy1123/usque/releases). For now, Android (`arm64`), Linux (`armv5`, `armv6`, `armv7`, `arm64`, `amd64`), Windows (`arm64`, `amd64`) and Darwin (`arm64`, `amd64`) binaries are provided. **However only the Linux `amd64` binary was tested.** If you have a different platform, you can build from source.

Extract the archive and you will find a binary named `usque` in the root directory. You can move this binary to a directory in your `PATH` to make it accessible from anywhere.

## Building from source

Since the tool is written in Go, it should be rather trivial.

1. Ensure that you have Go installed on your system. You can download it from [here](https://golang.org/dl/). At least Go 1.23.1 is required.
2. Clone this repository and switch to the project's root directory
3. Build the project using the following command:
```shell
CGO_ENABLED=0 go build -ldflags="-s -w" .
```

And that will produce an `usque` binary in the current directory.

If you would rather cross compile, set the `GOOS` and `GOARCH` environment variables accordingly. For example, to build for Windows on a Linux system:
```shell
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" .
```

### Docker

You can deploy the tool using Docker. [Dockerfile](Dockerfile) is provided in the repository. To build the image, run:

```shell
docker build -t usque:latest .
```

Example usage *(spawns a SOCKS proxy and exposes it on port 1080)*:

```shell
docker run -it --rm -p 1080:1080 usque:latest socks
```

## Usage

```shell
$ ./usque --help
An unofficial Cloudflare Warp CLI that uses the MASQUE protocol and exposes the tunnel as various different services.

Usage:
  usque [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  enroll      Enrolls a MASQUE private key and switches mode
  help        Help about any command
  http-proxy  Expose Warp as an HTTP proxy with CONNECT support
  nativetun   Expose Warp as a native TUN device
  portfw      Forward ports through a MASQUE tunnel
  register    Register a new client and enroll a device key
  socks       Expose Warp as a SOCKS5 proxy

Flags:
  -c, --config string   config file (default is config.json) (default "config.json")
  -h, --help            help for usque

Use "usque [command] --help" for more information about a command.
```

Before doing anything, you need to *register*.

### Registration

There is a handy *(though not too feature-rich)* `register` subcommand that creates a fresh Warp account ready to use. It also takes care of device registration and MASQUE device enrollment. Call this once and it will create a working configuration for future use in modules.

A simple example would be:

```shell
$ ./usque register
```

> [!TIP]
> If you want to specify a name for the device, you may do so by specifying `-n <device-name>`.

> [!TIP]
> If you want to register with ZeroTrust, you need to obtain the team token and do so by specifying `--jwt <team-token>`.
> 1. Visit `https://<team-domain>/warp` and complete the authentication process.
> 2. Obtain the team token from the success page's source code, or execute the following command in the browser console: `console.log(document.querySelector("meta[http-equiv='refresh']").content.split("=")[2])`.

If you didn't get rate-limited or any other error, you should see a `Successful registration` message and a working config. In case of certain issues such as rate limiting, you may need to wait a bit and try again.

### Enrolling

While the registration command also handles device enrollment, in some cases, you may want to re-enroll the old key found in the config. This is useful when migrating from one device to another while the server still has the old client key enrolled. Or if your account had WireGuard enabled and you want to switch to MASQUE.

> [!NOTE]
> This command refreshes your config with data downloaded from Cloudflare servers, so make sure you have backups.

> [!TIP]
> When using ZeroTrust this command can update the config with the newly assigned IPv4 and IPv6 addresses. This is useful, because IPv6 doesn't seem to work there if the IPv6 in config isn't up to date. Personal WARP doesn't seem to be affected by this.

```shell
$ ./usque enroll
```

### Native Tunnel Mode (for Advanced Users, Linux and Windows only!)

The native tunnel is probably the most **efficient** mode of operation *(as of now)*. 

#### On Linux

It **requires the `TUN` device** to be available on the system. This means your kernel must support loading the `tun.ko` module. **`iproute2` is also a requirement**. While it is still userspace, traffic is directly injected into the kernel's network stack, therefore you will see a real network interface and you will be able to tunnel any IP (Layer 3) traffic that WARP supports. Since it creates a real network interface and also attempts to set IP addresses, **it will most likely require root privileges**.

#### On Windows

It requires the [wintun.dll](https://www.wintun.net/) file to be present in the same directory as the `usque.exe` binary. Then it will take care of bringing up the interface and setting the IP addresses. Normally this also requires administrative privileges.

To bring up a native tunnel, execute:

```shell
$ sudo ./usque nativetun
```

Unless otherwise specified, you should see a `tun0` (or `tun1`, `tun2`, etc.) interface appear on Linux. On Windows, the interface is typically named `usque`. If you didn't disable IPv4 and IPv6 inside the tunnel using cli flags (on Linux), you should also see the IPv4 and IPv6 address pre-assigned to this interface. This should be enough for applications that can route traffic through a specific network interface to function. For example `ping`:

```shell
$ ping -I tun0 1.1
```

Or `curl`:

```shell
$ curl --interface tun0 https://cloudflare.com/cdn-cgi/trace
```

Should just work. However **the tool doesn't set any routes**. If you need that, you have to do that manually. For example, to route all traffic to the tunnel, you need to make sure that the address used for tunnel communication is routed to your regular network interface. For that, open the `config.json` and check the endpoint address. If you plan to connect to the Cloudflare endpoint using IPv4, you will most likely see this:

```json
"endpoint_v4": "162.159.198.1"
```

Remember that for the next steps.

#### Routes on Linux

Assuming your regular network interface is `eth0` and your gateway address is `192.168.1.1`, you can add a route like this:

```shell
$ sudo ip route add 162.159.198.1/32 via 192.168.1.1 dev eth0
```

After that, you can add a default route to the `tun0` interface for both IPv4 and IPv6:

```shell
$ sudo ip route add default dev tun0 && sudo ip -6 route add default dev tun0
```

#### Routes on Windows

First, determine the interface index for your regular network adapter by running:

```cmd
route print
```

Look under the **Interface List** for the correct index number.

Before adding default routes, determine the gateway for your tunnel interface by running:

```cmd
ipconfig
```

Look for the adapter named `usque` (or whatever name you have for your tunnel interface) and note its gateway address.

Assuming:

* Tunnel endpoint: `162.159.198.1`
* Gateway: `192.168.1.1`
* Interface index: `12`
* Tunnel interface: `usque` (replace with the actual name or index of your tunnel interface)

Run the following commands in an **elevated Command Prompt** (Run as Administrator):

```cmd
route add 162.159.198.1 mask 255.255.255.255 192.168.1.1 metric 1 if 12
```

Then add default routes to route all traffic through the tunnel:

```cmd
route add 0.0.0.0 mask 0.0.0.0 [TUNNEL_GATEWAY] metric 1 if [TUN_INTERFACE_INDEX]
route add ::/0 [TUNNEL_GATEWAY] metric 1 if [TUN_INTERFACE_INDEX]
```

> [!NOTE]
> Replace `[TUNNEL_GATEWAY]` and `[TUN_INTERFACE_INDEX]` with the actual values for your tunnel adapter. You can get these by checking `ipconfig` and `route print`.

> [!CAUTION]
> Always be careful with default routes, especially if you are running this on a headless machine. It is very easy to close yourself out of your current session. I suggest [network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html) on Linux as a safer playground for experiments or a spare VM with physical access or serial console.
> On Windows, you can set specific routes first such as `8.8.8.8/32` to ensure the tunnel works before adding a default route.

### SOCKS5 Proxy Mode (easy, cross-platform)

If you just want to expose the tunnel as a quickly deployable proxy and your client supports SOCKS5, this mode is for you. It **supports both IPv4 and IPv6**. **TCP and UDP** even! It is also **cross-platform** and doesn't require any special kernel modules or root privileges. However it emulates an entire user-space network stack, so it can be resource hungry.

To start a SOCKS5 proxy, you can run:

```shell
$ ./usque socks
```

By default this will launch a SOCKS5 proxy on `0.0.0.0:1080` **with no authentication**. You can choose to bind to a specific address and port by specifying `-b` and `-p` respectively. You can also enable authentication by specifying `-u` and `-w` for username and password. For example:

```shell
$ ./usque socks -b 127.0.0.1 -p 8080 -u myuser -w mypass
```

Will start a SOCKS5 proxy accessible only on `127.0.0.1:8080` with username `myuser` and password `mypass`.

Test the proxy with `curl`:

```shell
curl -x socks5://myuser:mypass@localhost:8080 https://cloudflare.com/cdn-cgi/trace
```

> [!NOTE]
> Since the proxy emulates its own networking stack, it's generally safe to say that users won't be able to access internal IPs and services the host has access to using the proxy. However the internal WARP network is available for them unfiltered. If you have ZeroTrust and Gateway on, users of your proxy may be able to reach each other as no manual filtering is applied. **Inside the tunnel they will be able to connect to any TCP or UDP service**.

> [!CAUTION]
> Local SOCKS5 **traffic is not encrypted** since SOCKS5 does not support encryption. You probably shouldn't transport statewide secrets from one device to another on a public WiFi that has `usque` running.

> [!NOTE]
> For now only one `user:pass` is supported.

### HTTP Proxy Mode (easy, cross-platform)

Another easy to "*get up and running*" mode of operation is the HTTP proxy mode. **Almost all clients support HTTP proxies**. Regular HTTP unencrypted traffic sent to this proxy will simply be forwarded to the WARP network. For HTTPS and any other **TCP traffic**, the proxy exposes a HTTP `CONNECT` method. This mode is **cross-platform** and doesn't require any special kernel modules or root privileges. However it emulates an entire user-space network stack, so it can be resource hungry.

To start a HTTP proxy, you can run:

```shell
$ ./usque http-proxy
```

By default this will launch a HTTP proxy on `0.0.0.0:8000` **with no authentication**. You can choose to bind to a specific address and port by specifying `-b` and `-p` respectively. You can also enable authentication by specifying `-u` and `-w` for username and password. For example:

```shell
$ ./usque http-proxy -b 127.0.0.1 -p 8080 -u myuser -w mypass
```

Will start a HTTP proxy accessible only on `127.0.0.1:8080` with username `myuser` and password `mypass`.

Test the proxy with `curl`:

```shell
curl -x http://myuser:mypass@localhost:8080 https://cloudflare.com/cdn-cgi/trace
```

> [!NOTE]
> Since the proxy emulates its own networking stack, it's generally safe to say that users won't be able to access internal IPs and services the host has access to using the proxy. However the internal WARP network is available for them unfiltered. If you have ZeroTrust and Gateway on, users of your proxy may be able to reach each other as no manual filtering is applied. **Inside the tunnel they will be able to connect to any TCP service.**

> [!CAUTION]
> Local HTTP **traffic is not encrypted** since HTTP does not support encryption, and HTTPS isn't implemented. It should be trivial to add, but I didn't need it yet. You probably shouldn't transport statewide secrets from one device to another on a public WiFi that has `usque` running.

> [!NOTE]
> For now only one `user:pass` is supported.

### Port Forwarding Mode (for Advanced Users, cross-platform)

While most other modes expose the tunnel in some way or another, this mode is intended for more advanced use-cases. Think of it a bit like SSH forwarding. It allows you to either forward a specific port from the host to the WARP network or from the WARP network to the host.

*Why would you do that, you may ask?* For regular WARP, this feature is pretty useless. In fact the tool's `registration` command cannot even set this up properly. However with some manual configuration and assuming you have a ZeroTrust network, you can configure WARP to WARP device communication. Each device will have a unique internal IPv4 and IPv6 address and they can reach each other that way. This is not how it works out of the box however, so [follow the offical guide](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/private-net/warp-to-warp/) to set it up. Once you have it working, you can use this feature to forward ports to and from the WARP network.

> [!TIP]
> It is very important for this mode to function properly to have up to date IP addresses in the config. Running the [enrollment](#enrolling) process before bringing up the forwarding should set the correct IPs.

This mode is **cross-platform** and doesn't require any special kernel modules or root privileges. However it emulates an entire user-space network stack, so it can be resource hungry.

As for the setup. Let's say you have this in the config:

```json
"ipv4": "100.96.0.3"
```

Which means that your device's internal IPv4 address is `100.96.0.3`. You are running a webserver on the host machine on port `8080`. Then there is another device with internal IPv4 address `100.96.0.2` that also exposes a webserver on port `8081`. You would like to forward the host's port `8080` to the WARP network and the WARP network's port `8081` to the host. To set this up, you can run:

```shell
$ ./usque portfw -R 100.96.0.3:8080:localhost:8080 -L localhost:8081:100.96.0.2:8081
```

> [!TIP]
> The syntax isn't exactly like the one from SSH. I suggest that you specify the syntax as seen in the example preferably with IP addresses and not hosts.

> [!TIP]
> Any number of ports are supported. You can chain many ports together if you specify the flag and the corresponding argument one after another.

### Configuration

For simplicity, the tool uses a JSON configuration file. The default file is `config.json` in the current directory. You can specify a different file using the `-c` flag. This will be respected by all subcommands. Without a configuration file only the `register` subcommand will work.

Example config:

```json
{
  "private_key": "M...redacted...==",
  "endpoint_v4": "162.159.198.1",
  "endpoint_v6": "2606:4700:103::",
  "endpoint_pub_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG\n7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==\n-----END PUBLIC KEY-----\n",
  "license": "A...redacted...Z",
  "id": "00000000-0000-0000-0000-000000000000",
  "access_token": "00000000-0000-0000-0000-000000000000",
  "ipv4": "172.16.0.2",
  "ipv6": "2606:redacted:1"
}
```

#### Fields

- `private_key`: Base64 encoded ECDSA private key on the NIST P-256 curve in ASN.1 DER format. **Confidential.** This is used for device authentication.
- `endpoint_v4`: IPv4 address of the Cloudflare WARP endpoint. **Public.** Used for connecting to the WARP network.
- `endpoint_v6`: IPv6 address of the Cloudflare WARP endpoint. **Public.** Used for connecting to the WARP network.
- `endpoint_pub_key`: Base64 encoded ECDSA public key on the NIST P-256 curve in PEM format. **Public.** This is used to ensure that we are indeed talking to the Cloudflare WARP endpoint and not being [MiTM](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)'d.
- `license`: License returned by the server for our account. **Confidential.** With this, you can pair multiple devices to the same account.
- `id`: Device ID given by the server to us. **Public.** This is used for device identification and API calls.
- `access_token`: Access token given by the server to us upon registration/login. **Confidential.** This is used for API calls.
- `ipv4`: Internal IPv4 address assigned to the device by the Cloudflare WARP network. **Public.** This is assigned to the device's interface and is also used for communication between devices in the [port forwarding mode](#port-forwarding-mode-for-advanced-users-cross-platform).
- `ipv6`: Internal IPv6 address assigned to the device by the Cloudflare WARP network. **Public.** This is assigned to the device's interface and is also used for communication between devices in the [port forwarding mode](#port-forwarding-mode-for-advanced-users-cross-platform).

## ZeroTrust support

In my view ZeroTrust is Cloudflare's enterprise version of WARP. Explaining this in depth would be beyond the scope of this README.

While the tool won't be able to log you in to ZeroTrust *(as SSO is required for login there)* practice shows that you can get connection working if you really want to. For that you need to run `./usque register --jwt <jwt>` or put together a config file manually. If you choose to put together a config file manually, I suggest using the `register` command to obtain a personal WARP config. Keep all fields unchanged except for `access_token` and `id`. As for how to obtain these, be creative. For example both of these can be carved out from `/var/lib/cloudflare-warp/reg.json` if using the official WARP client on Linux. Or existing device IDs are listed in the ZeroTrust dashboard. Once these are in place, you can use the `enroll` command to refresh the config with the new data. You will see that the `license` field is empty. This is normal. ZeroTrust doesn't use licenses *(to my knowledge)*.

Warp to warp communication is supported by all modes of this tool if you have it [correctly set up](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/private-net/warp-to-warp/). Proxies and tunnels can reach services exposed on other devices and [port forwarding](#port-forwarding-mode-for-advanced-users-cross-platform) can be used to forward ports to and from the WARP network.

> [!TIP]
> These tunnels seem to access the better-routed `warp=plus` network. However, once Proxy is enabled—which is required for Warp-to-Warp communication—the connection is downgraded to `warp=on`. This results in degraded *(athough usually still quite generous)* performance.

> [!TIP]
> By default Cloudflare logs most requests. You might want to turn that off to preserve the uncertain belief of a little more privacy. 👀

> [!WARNING]
> **You must reconnect after making changes for them to take effect.**

> [!NOTE]
> **You should probably set SNI to `zt-masque.cloudflareclient.com`** by specifying `-s zt-masque.cloudflareclient.com` when using any mode that involves tunnel connection. The default `consumer-masque.cloudflareclient.com` also works, but discouraged.

## Performance

The project is still in early stages of development *(I am happy I even got it working)* and performance wasn't a priority. In fact I am not even too familiar with Go. The official client *(at least on Linux and Android)* is implemented in Rust with the awesome [quiche](https://github.com/cloudflare/quiche) project. In contrast, this tool is written in Go and leverages the well-maintained [quic-go](https://github.com/quic-go/quic-go) library, which offers broad support for the QUIC protocol. However it only supports `reno` congestion control and it isn't the most performant implementation out there especially for high latency network environments.

Many other features such as [happy eyeballs](https://en.wikipedia.org/wiki/Happy_Eyeballs) are also missing.

So yes, the performance might not be the best. However, I was able to squeeze out `833.60 Mbps` download and `772.88 Mbps` upload on a 1 Gbps connection with Warp+ upon the first try using the SOCKS5 proxy mode with Firefox and [speedtest.net](https://www.speedtest.net/). The test was conducted on an `AMD Ryzen 7 5700U` config with `16 GB` of RAM on `Arch Linux`. That is good enough for me. I am sure there is room for improvement. But keep in mind that this is all userspace; SOCKS mode even emulates its own network stack. CPU usage was around 26%.

I heard that Windows performance is worse. I don't have a Windows machine to test it on. If you do, please let me know about your experience.

### Performance Tuning

#### Linux/BSD

`quic-go` will nicely warn you if this is set to a too small value on your machine. But the default UDP buffer size on Linux is quite small. You can increase it by running:

```shell
$ sudo sysctl -w net.core.rmem_max=7500000
$ sudo sysctl -w net.core.wmem_max=7500000
```

Refer to the [quic-go documentation](https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes) for a better explanation.

#### DNS

By default all modes except for the native tunnel mode will use [Quad9](https://quad9.net/) to resolve DNS traffic. While this seems to be an odd choice for a Cloudflare client, I prefer them over `1.1.1.1` because of their privacy claims. I believe it's a decent default. However `1.1.1.1` has better performance usually. You are free to change the DNS server used by the tool by specifying the `-d` flag.

For example:

```shell
$ ./usque socks -d 1.1.1.1 -d 1.0.0.1 -d 2606:4700:4700::1111 -d 2606:4700:4700::1001
```

Native tunnels will not customize DNS. Whatever you have set on your system will be preferred. Routing of DNS packets to the tunnel or somewhere else is also entirely up to you.

## Using this tool as a library

This is primarily a CLI tool for now. However some efforts were made to document and expose certain functions that can be used to build your own applications. **I do not recommend this** as of now though, because the implementation is quite unstable and the API is subject to change. I also didn't do the best job at abstraction, because my primary goal was to get it working and the second goal was to make something easily readable. So instead of using it directly as a library, people can fork and plug in extra functionality as they wish. I am open to PRs that make the code more modular and easier to use as a library.

As a starting point, you can reach out to the [`api/`](api/) package. For examples, take a look at the [`cmd/`](cmd/) package.

## Known Issues

- **remote end disconnects**: If you are inactive for a while, the remote end might disconnect you with a `H3_NO_ERROR` error. Similar behavior was observed earlier on their well studied `WireGuard` implementation where too long open connections with not significant network activity were disconnected. The official apps just reconnect once that happens, therefore I implemented a similar behavior. Therefore if you see disconnects, don't worry, it's probably just the remote end. The tool will reconnect automatically.
- **interaction with the Cloudflare API is limited**: This one is also intended. The tool's primary focus is MASQUE. If you want better support, I suggest the official client or [wgcf](https://github.com/ViRb3/wgcf).
- **no support for WireGuard**: This is a MASQUE client. If you want WireGuard, use the official client or [wgcf](https://github.com/ViRb3/wgcf).
- **no support for DoH etc.**: Yeah, the official clients expose a lot of extra DNS related features. I wanted to keep this lightweight. Those will probably not be supported by me. If you want, you are free to use 3rd party DoH clients and configure them to use the tunnel interface. DNS over Warp should already be working on all modes except for the native tunnel mode as all DNS queries made inside the tunnel will go through the tunnel (unless you use the `-l` flag).
- **slow initial speeds**: You may experience slow speeds when opening a new connection that can gradually increase by time. This is due to the `reno` congestion control algorithm used by `quic-go`. It is not the most performant one out there, especially not for high latency environments. We have to wait for support for different congestion control algorithms and see how they compare. For instance there is an open issue for [BBR](https://github.com/quic-go/quic-go/issues/4565).
- **native tunnels only support Linux**: This is due to the fact that we depend on the `TUN` device. While that exists on Android, without root it's hard to use in its current form. Windows support would be feasible, but I don't have experience with the Windows APIs regarding how to assign IP addresses to network interfaces. BSD and macOS support is uncertain. All these platforms are unsupported for now, because I don't have the means to test them and I am not willing to share untested code. PRs are welcome.

## Miscellaneous

### Censorship circumvention

There is hardly a way to distinguish MASQUE traffic from other HTTP/3 traffic. However QUIC mandates TLS v1.3 so we send a ClientHello with `client-masque.cloudflareclient.com` in the SNI field. Some firewalls may block this. You can change the SNI by specifying `-s` flag to any domain *(based on my experience)* and the connection will still work. Please note that this is definitely not Cloudflare's intended use case *(just a nice side effect)*. And before doing any circumvention attempts, you should make sure you are not breaking any laws. Personally I only see this as a clear benefit for masking the fact that we are connecting to Warp from MiTMers.

### HTTP/2 Fallback Support

The tool now includes HTTP/2 fallback support for better compatibility when HTTP/3 over QUIC is not available or blocked. The connection process works as follows:

1. **Primary connection**: Attempts HTTP/3 over QUIC (the preferred method)
2. **Fallback detection**: If HTTP/3 fails, the tool automatically tests HTTP/2 connectivity
3. **Error reporting**: Provides clear information about which protocols were attempted and why they failed

This fallback mechanism is particularly useful in environments where:
- QUIC/UDP traffic is blocked or throttled
- Network middleboxes interfere with QUIC connections
- Firewalls allow TCP but restrict UDP protocols

The HTTP/2 fallback currently provides connection testing and protocol negotiation. The TLS configuration automatically includes support for HTTP/3 (`h3`), HTTP/2 (`h2`), and HTTP/1.1 protocols, allowing the best available protocol to be negotiated during the TLS handshake.

## Should I replace WireGuard with this?

That depends on your needs. 😊 WireGuard is a great protocol and its modern/fast cryptography plus the ability to have kernel mode support are both great things. If it works for you, I don't believe you should switch.

MASQUE is userspace, and so is QUIC, the underlying protocol, making the implementation slower. While it also has certain benefits such as full blown TLS support *(WireGuard comes with a fixed set of ciphers)*, adjustable congestion control, more advanced tuning parameters, it is also more complex.

At the end of the day, if you are happy with WireGuard, I don't see a reason to switch. If you are happy with Warp, but you want to use it on a platform that doesn't have official support, this tool might be for you.

### Why would you still switch?

- **reports that WARP+ doesn't work anymore over WireGuard arose lately**: I saw reports that WARP+ doesn't work anymore over WireGuard. While I cannot confirm this, I read reports that it is the case for some, ([see](https://github.com/ViRb3/wgcf/issues/459#issuecomment-2645319671)). It seems to work for me with this tool, so I consider this a feasible alternative.
- **you want to use WARP on a platform that doesn't have official support**: This tool is cross-platform and open-source, so you are free to use it on any platform that supports Go. This includes Windows, macOS, BSD, Linux, Android, iOS, etc. I hope it will work on all of them.
- **certain networks block WireGuard**: Certain networks block WireGuard, but don't block QUIC.
- **you are the curious type**: You are the curious type and you want to experiment with cool new technologies. MASQUE is a new and interesting approach... So why not? 😊

## Protocol & research details

This document would be large and too horrific for the average reader if I included all the details about the protocol and the research I did. If you are one of the few people who would be interested in some details, please refer to the [RESEARCH.md](RESEARCH.md) file. That one summarizes the research I did and the protocol details I found in a blog post like format. In the future I plan to write a clear and concise protocol document as well that will be linked here.

## Why was this built?

Mostly because I wanted to experiment with cool new technology, and MASQUE caught my attention. I was shocked to see that there are not many open-source implementations out there, in fact I haven't really seen any practical uses for `connect-ip` open-sourced yet. I wanted to change that and *"advertise"* a bit.

Secondly, I rely on WARP quite frequently for Cloudflare proxied websites as peering between my ISP and regular Cloudflare protected websites is not the best. With WARP+, I get better routes and faster speeds. However, the official client's WireGuard implementation runs in userspace, so I was using `wgcf` instead to run it in kernel mode. It has been misbehaving a lot lately; for some reason, I have to reconnect multiple times whenever I want to use it. It started working after a few tries, but it was annoying. There are a few issues open on the `wgcf` repository that are related to this, like [this](https://github.com/ViRb3/wgcf/issues/158) and [this](https://github.com/ViRb3/wgcf/issues/50). WireGuard was also blocked on the local train WiFi, but MASQUE wasn't.

Then I switched to the official client and MASQUE which worked much more reliably. However the whole app is quite heavy ([260 MiB compressed for Android](https://play.google.com/store/apps/details?id=com.cloudflare.onedotonedotonedotone) by the time I am writing this). *Cloudflare One, the enterprise version is much lighter...*

But anyway, I found that the app used too much memory and that wasn't even the worst part.

I figured this while casually sitting on a train, browsing the interwebz with Warp on. Once in a while it would crash and disconnect the entire VPN profile leaving my traffic exposed to the local WiFi. That was quite unpleasant and the final straw that made me start this project.

While it doesn't exactly solve the reconnect issue yet either, it is planned. And with the leap forward to open-sourcing this, I hope that the community can help me make this tool better and more reliable.

## Why did you fork connect-ip-go?

Because Cloudflare's implementation isn't exactly RFC 9484 compliant and it's not going to work without directly monkey patching the library. Find my ugly, but hopefully working version [here](https://github.com/Diniboy1123/connect-ip-go).

## Why the name?

Obviously I didn't plan to name it `warp`, `cloudflare` or anything similar to reduce conflicts or to make users knock on the wrong doors for support because of my faulty implementation attempts.

Since the underlying technology is MASQUE, I wanted to come up with something short, memorable and unique, but still related to the underlying technology. I had a fun 4 years of Latin in school, so I figured the perfect name would be `usque`. If I can trust my rusty memory, it means `all the way`. I thought it was a good fit, because it is a tool that tunnels all the way to the Cloudflare network. We also go a long way until this becomes stable. You get the idea... 😊  It is also (hopefully) unique enough to not conflict with other projects.

## Contributing

Contributions are welcome. In fact I am a university student with very limited time and resources. For now the tool mostly implements my needs and ideas, but I would like to see it grow and become more stable with many exciting features to come. If you have any ideas, suggestions, bug reports or even code contributions, feel free to open an issue or a pull request. I will do my best to get back to you.

## Acknowledgements

This tool wouldn't exist without the following incredible projects. Please go and star them all if you like this project!

- [Cloudflare Blogs](https://blog.cloudflare.com/) - They have some interesting insights documented across their blogs. I learned some bits and pieces from there.
- [cobra](github.com/spf13/cobra) - Powerful CLI library for Go. Used for the CLI interface. Absolutely love it.
- [connect-ip-go](https://github.com/quic-go/connect-ip-go) - ~~The only open-source implementation for `RFC 9484` I could find.~~ (this is not true anymore, [see](RESEARCH.md#interesting-other-connect-ip-related-projects)) Our entire IP tunneling depends on this. We rely on my fork of this project heavily.
- [Frida](https://frida.re/) - This was a huge help for dynamic analysis of the official client. I was able to see what was going on in the app in real time and dumping certain values.
- [frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning/tree/4d477da) - Very good at unpinning cert. pinning, so I could explore how API calls were made by the app.
- [friTap](https://github.com/fkie-cad/friTap) - For being an exceptionally well written and easy to use Frida script that one can use to dump TLS secrets effortlessly.
- [Go](https://go.dev/) - The Go programming language. I am not a professional developer, but I was able to get this working with Go. It is a great language.
- [go-socks5](github.com/things-go/go-socks5) - A great SOCKS5 library for Go. Used for the SOCKS5 proxy mode. Taught me a lot about the SOCKS protocol.
- [gvisor](https://gvisor.dev/) - Gvisor is a great tool for running untrusted code in a safe environment. They also implement a complete network stack in userspace. This makes it possible for all proxy modes to run without root and cross-platform.
- [IDA Free](https://hex-rays.com/ida-free) - Great stuff for dealing with rust binaries. Helped a lot with understanding the official client.
- [JADX-GUI](https://github.com/skylot/jadx) - Great stuff for dealing with Android APKs. Helped a lot with understanding the official client.
- [masque-go](https://github.com/quic-go/masque-go) - While I didn't end up using it, as this is for `connect-udp` like `RFC 9298` compliant MASQUE servers, it was a great starting point while I was researching the topic.
- [mitmproxy](https://mitmproxy.org/) - Very useful for intercepting API calls made by the official client.
- [netlink](github.com/vishvananda/netlink) - A great library for interacting with the Linux network stack using `iproute2`. Used for the native tunnel mode on Linux.
- [quic-go](https://github.com/quic-go/quic-go) - Powerful QUIC library for Go, used for many things from establishing the connection to maintaining it.
- [uritemplate](github.com/yosida95/uritemplate) - A great library for parsing URI templates. Used as a utility to pass the correct endpoint URI to `connect-ip-go`.
- [water](https://github.com/songgao/water) - A TUN/TAP library for Go. Used for the native tunnel mode. Taught me everything I know about TUN/TAP devices.
- [wireguard-go](golang.zx2c4.com/wireguard) - A WireGuard library for Go. Used very widely by the project too for rootless virtual tun networks, because its `netstack` implementation is very easy to use.
- [wireshark](https://www.wireshark.org/) - I used Wireshark to debug both the official client and this tool during initial development. A real swiss army knife for network debugging.

Special shoutout to [**@monkeywave**](https://github.com/monkeywave), one of the [friTap](https://github.com/fkie-cad/friTap) contributors who helped me decipher the last bit of information I needed to get this tool working. In fact if it wasn't for them, I would have probably given up on this project. They helped me and patiently guided me through the process of dumping TLS secrets from the official client. The issue is worth a read [if you are interested](https://github.com/fkie-cad/friTap/issues/38). One of the best experiences I had in the open-source community. Thank you!

Another shoutout goes to [**@marten-seemann**](https://github.com/marten-seemann) for maintaining the entire quic-go ecosystem. I opened a few issues there as well and always got a helpful response. Thank you!

## Disclaimer

Please do NOT use this tool for abuse. At the end of the day you hurt Cloudflare, which is probably unfair as you get this stuff even for free, secondly you will most likely get this tool sanctioned and ruin the fun for everyone.

The tool mimics certain properties of the official clients, those are mostly done for stability and compatibility reasons. I never intended to make this tool indistinguishable from the official clients. That means if they want to detect this tool, they can. I am not responsible for any consequences that may arise from using this tool. That is absolutely your own responsibility. I am not responsible for any damage that may occur to your system or your network. This tool is provided as is without any guarantees. Use at your own risk.

While the tool was made with security considerations in mind, I am not a security expert nor an IT professional. I am just a hobbyist and this is just a hobby project. Again, use at your own risk. However security reports are welcome. Feel free to open an issue with your contact details and I will get back to you, so you can share your findings **IN PRIVATE**. Once there was enough time to fix the issue, I will credit you in the release notes and the findings can be made public. I appreciate any help in making this tool more secure.

**This tool is not affiliated with Cloudflare in any way. The tool was neither endorsed nor reviewed by Cloudflare. It is an independent research project. Cloudflare Warp, Warp+, 1.1.1.1™, Cloudflare Access™, Cloudflare Gateway™ and Cloudflare One™ [are all registered trademarks/wordmarks](https://www.cloudflare.com/trademark/) of Cloudflare, Inc. If you are a Cloudflare employee and you think this project is in any way harmful, please open an issue and I will do my best to contact you and resolve the issue.**

WireGuard™ is a [registered trademark](https://www.wireguard.com/trademark-policy/) of Jason A. Donenfeld.