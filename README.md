# prometheus cfaccess roundtripper

[![Go Reference](https://pkg.go.dev/badge/github.com/prometheus/cfaccess.svg)](https://pkg.go.dev/github.com/prometheus/cfaccess)

`cfaccess` provides an `http.RoundTripper` that authenticates requests to
applications protected by [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/).
It implements Cloudflare's browser-based login flow and shares cloudflared's
normal on-disk token cache, without depending on cloudflared.

This is a separate module from `github.com/prometheus/common` so that projects
which do not use Cloudflare Access do not inherit its authentication code.

This module is considered internal to Prometheus, without any stability
guarantees for external usage.

## Usage

The target application is discovered lazily from the first request to each
host, because its Cloudflare Access audience is not known when the transport is
constructed.

```go
transport := cfaccess.NewRoundTripper(http.DefaultTransport)
client := &http.Client{Transport: transport}
```

When using `prometheus/common/config`, the existing HTTP configuration format
can select Cloudflare Access authentication:

```yaml
authorization:
  type: cf-access
```

The consumer must prepare the configuration before passing it to common, then
conditionally install the Cloudflare Access transport:

```go
cfg, enabled, err := cfaccess.PrepareHTTPClientConfig(cfg)
if err != nil {
	return err
}

transport, err := commonconfig.NewRoundTripperFromConfig(cfg, "example")
if err != nil {
	return err
}
if enabled {
	transport = cfaccess.NewRoundTripper(transport)
}
```

For a client created with `commonconfig.NewClientFromConfig`, wrap
`client.Transport` in the same way.

## Interactive authentication

If no valid token is cached, the first request opens the user's browser and
blocks until login completes. This behavior is intended for interactive tools,
not unattended servers.

Cancelling the request interrupts authentication HTTP requests and waits for
in-process or on-disk cache locks. It does not close an already opened browser.
The authenticated request is not sent if its context has expired.

Cache locks coordinate interactive logins across processes. An abandoned lock
causes a bounded wait followed by an error identifying the lock file. Remove
that file only after checking that no other login is still running.

The private [token implementation](internal/token/README.md) documents the
upstream protocol source and compatibility details.
