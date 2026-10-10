# goportforwarding

A small desktop app (Go + [Fyne](https://fyne.io)) for a single SSH **local port-forwarding** tunnel — a GUI for:

```bash
ssh -N -L 15432:db.internal.example:5432 alice@bastion.example.com
```

```text
Your application → 127.0.0.1:<local port>
                 → SSH server
                 → <destination host>:<destination port>   (reached from the SSH server's network)
```

## Features

- Local (`-L`) TCP forwarding, one tunnel at a time, listening on **127.0.0.1 only**.
- Authentication by SSH private key, by the keys in your **ssh-agent** (`ssh-add`), or by password
  (sent as password or keyboard-interactive auth, whichever the server uses). Encrypted keys prompt
  for a passphrase. Neither the password nor the passphrase is ever saved.
- **Profiles:** save the form under a name and pick it from the list next time; the last-used
  profile is loaded at startup. Profiles are stored (mode 0600) in `profiles.json` under the
  per-user config directory — `~/Library/Application Support/goportforwarding/` on macOS,
  `%AppData%\goportforwarding\` on Windows, `~/.config/goportforwarding/` on Linux.
- Host keys are checked against `~/.ssh/known_hosts`, the same file OpenSSH uses. When a host is
  seen for the first time, you're asked to confirm its SHA256 fingerprint and it is saved. If a key
  changes, the connection is refused.
- Before reporting **Connected**, it checks that the local port can be opened, the SSH login works,
  and the destination is reachable through the server.
- Sends keepalives every 30 s. If the connection drops, the status changes to **Disconnected** and
  an error is shown.
- **Stop Forwarding** (or closing the window) closes the listener, the active connections and the
  SSH session.

## Usage

1. Start the app and pick a saved profile, or fill in: SSH server host/port, username,
   authentication (**Private key** with a key file, **ssh-agent**, or **Password**), local port,
   destination host/port. Click **Save…** to keep it as a profile. Use `localhost` as the
   destination if the service runs on the SSH server itself.
2. Click **Start Forwarding**. When it says **Connected**, point your client at the address shown
   (for example, `127.0.0.1:15432`).
3. Click **Stop Forwarding** when you're done.

## Building

Fyne uses cgo, so each target needs a C toolchain.

| Target | Command | Requirements |
|---|---|---|
| macOS (universal arm64+amd64) | `make darwin` | Xcode Command Line Tools |
| Windows amd64 | `make windows` | `brew install mingw-w64` (or build natively on Windows with `go build -ldflags "-H windowsgui"`) |
| Linux amd64 + arm64 | `make linux` | Docker |
| All of the above | `make all` | |
| Tests | `make test` | |

The binaries are written to `dist/`.

Building natively on Linux requires
`gcc pkg-config libgl1-mesa-dev xorg-dev libwayland-dev libxkbcommon-dev` (Debian/Ubuntu package names).

### Platform notes

- **macOS:** the binary is unsigned. The first time, right-click it and choose **Open**. For an
  `.app` bundle, use `go install fyne.io/tools/cmd/fyne@latest` and `fyne package -os darwin`
  (this requires an `Icon.png`).
- **ssh-agent** is found through `SSH_AUTH_SOCK`. macOS sets it for apps automatically; on Linux it
  depends on the desktop session. The Windows OpenSSH agent (a named pipe) is not supported yet.
- **Windows:** built as a GUI app (no console window). SmartScreen may warn because it is unsigned.

## Layout

- `tunnel/` — SSH and forwarding logic, with no GUI dependency. Tested against an in-process SSH
  server and ssh-agent.
- `profile/` — saved profiles (JSON), with no GUI dependency.
- `main.go` — Fyne user interface.
