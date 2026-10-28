# Access token protocol

This private package implements the browser authentication subset of
[cloudflare/cloudflared/token](https://github.com/cloudflare/cloudflared/tree/d2a87e9b9345/token),
adapted from commit d2a87e9b9345 under the Apache License 2.0.
The upstream implementation is by Cloudflare and its contributors.
See the repository LICENSE and NOTICE.

The extraction preserves application discovery, organization-token exchange,
browser login query parameters, NaCl box transfer encryption, and the
~/.cloudflared application and organization token filenames. It does not
include tunnel configuration, SSH certificates, or the cloudflared CLI.

Compared with the upstream implementation:

- The standard library replaces configuration, logging, error and home-directory
  helpers. The existing JWT dependency parses cached tokens; as upstream does,
  cache parsing checks format and expiration without verifying signatures.
  The Access server validates the application token on authenticated requests.
- Every HTTP operation and cache-lock wait observes the caller's context.
  Redirects require HTTPS, are bounded, and organization/session cookies are
  restricted to their intended hosts.
- Each browser login generates an ephemeral key pair instead of reading key
  files from the current directory. Transfer responses have size and key/nonce
  length checks.
- Cache writes use private temporary files and rename. Lock acquisition uses
  exclusive creation and never installs signal handlers or exits the process.
  A caller waits at most two minutes for an existing lock; an abandoned lock
  must be removed manually after checking that no login is still running.
  Older cloudflared versions can remove locks themselves, so coordination with
  those versions retains their limitations.
- Browser-launch failure prints a URL for manual login. Browser launchers are
  reaped asynchronously, and unsupported systems use the same manual fallback.

Tests cover protocol requests, encrypted transfers, cache reuse, organization
exchange, concurrent callers, cancellation, redirect credential scoping and
malformed responses without contacting Cloudflare. A live browser login against
an actual Access-protected application remains an integration check for releases.
