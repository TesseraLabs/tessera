# Autostart examples for `issuer serve`

The Tessera issuer local signing agent (`issuer serve`) is a **per-user**,
loopback-only service — never a system daemon and never root. These files start
it automatically in the operator's own session on each platform. In every case
the pairing token is delivered through `--daemon-token-file` (written to the
per-user runtime directory with private permissions) rather than printed.

| Platform | File | Runtime token directory |
|----------|------|-------------------------|
| Linux    | [`issuer-serve.service`](issuer-serve.service) — `systemd --user` unit | `$XDG_RUNTIME_DIR/tessera-issuer/` (dir `0700`, file `0600`) |
| macOS    | [`com.tesseralabs.issuer-serve.plist`](com.tesseralabs.issuer-serve.plist) — launchd LaunchAgent | `~/Library/Application Support/tessera-issuer/` (dir `0700`, file `0600`) |
| Windows  | [`issuer-serve-task.xml`](issuer-serve-task.xml) — Task Scheduler (logon trigger) | `%LOCALAPPDATA%\tessera-issuer\` (protected by the user profile's ACLs) |

Each file carries its own install commands in a header comment. Before enabling,
edit the PKCS#11 module path, key label, signing algorithm and allowed cabinet
origin for your deployment.

The token PIN is entered on the agent side — pinentry (`pinentry`,
`pinentry-mac`, or Gpg4win's `pinentry` on Windows) if one is on `PATH`,
otherwise the controlling terminal — and is never accepted over HTTP. Every sign
request is shown to the operator and signed only after explicit confirmation.
