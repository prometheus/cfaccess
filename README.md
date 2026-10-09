# prometheus cfaccess roundtripper

[![Go Reference](https://pkg.go.dev/badge/github.com/prometheus/cfaccess.svg)](https://pkg.go.dev/github.com/prometheus/cfaccess)

`cfaccess` provides an `http.RoundTripper` that authenticates requests to
applications protected by [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/).
It uses cloudflared's browser-based login flow and stores tokens in cloudflared's
normal on-disk cache.

This is a separate module from `github.com/prometheus/common` so that projects
which do not use Cloudflare Access do not inherit cloudflared's dependency tree.

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

Cloudflared's token APIs do not currently accept a `context.Context`, so
cancelling the original request cannot interrupt an authentication operation
already in progress. The authenticated request is not sent if its context has
expired by the time authentication completes.
