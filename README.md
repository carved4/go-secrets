# go-secrets

a secure, local-first secrets management tool for developers

## why i made this

managing secrets sucks. we all know it. you've got `.env` files scattered across projects, api keys in your shell history, passwords in plaintext config files. one accidental `git add .` and your production database credentials are on github for the world to see.

i wanted something simple: a single encrypted vault on my machine, protected by my os keyring, with secrets i can inject into any command without ever touching a file. no cloud services, no subscriptions, no complexity. just secure local storage that actually works.

## what it does

secrets manager stores your sensitive data (api keys, tokens, passwords, connection strings) in an encrypted vault. each secret is encrypted with aes-256-gcm, and the master encryption key is stored in your system keyring (windows credential manager, macos keychain, or linux secret service).

you can:
- store secrets from your clipboard with one command
- retrieve secrets to clipboard or display them securely
- inject all secrets as environment variables into any command
- list your stored secrets without authentication
- delete secrets when you're done with them

## installation

requires go 1.24 or later.

```bash
git clone github.com/carved4/go-secrets
cd go-secrets/cmd/secrets
go build .
```

on windows, run as administrator. on linux/macos, run with sudo.

## usage

### initialize your vault

```bash
# windows (run as administrator)
secrets.exe init

# linux/macos (run with sudo)
sudo secrets init
```

you'll be prompted to create a password (minimum 12 characters). this password encrypts your master key.

### add a secret

copy your secret to clipboard, then:

```bash
secrets add
```

you'll be prompted for your password and a name for the secret (use env var format like `DATABASE_URL` or `API_KEY`).

### retrieve a secret

```bash
# display in terminal
secrets get DATABASE_URL

# copy to clipboard (auto-clears after 30 seconds)
secrets get DATABASE_URL --clip
```

### list all secrets

```bash
secrets list
```

no password required - just shows names, not values.

### delete a secret

```bash
secrets delete API_KEY
```

### run commands with secrets as environment variables

```bash
secrets env run -- node server.js
secrets env run -- python app.py
secrets env run -- ./your-binary
```

all your secrets are automatically injected as environment variables.

## why use this over traditional .env files?

### security benefits

**encrypted at rest**: your secrets are encrypted with aes-256-gcm. even if someone gets your vault file, they can't read it without your password and the master key from your system keyring.

**no plaintext files**: traditional `.env` files are plaintext. they get committed to git, copied around, left in temp directories, and post compromise everything is just one 'env' command away. secrets manager never writes plaintext secrets to disk, and with this you can replace storing anything in your environment variables, just inject them with the binary :3

**os-level key protection**: the master encryption key is stored in your system keyring (windows credential manager, macos keychain, linux secret service). these are designed to protect sensitive data and integrate with your os security.

**memory protection**: sensitive data is locked in memory using `VirtualLock` (windows) or `mlock` (unix) to prevent swapping to disk. when done, memory is zeroed before unlocking.

**rate limiting**: after 10 failed password attempts, the vault locks for 5 minutes to prevent brute force attacks.

**integrity verification**: each vault has an hmac signature to detect tampering. if someone modifies your vault file, you'll know.

### operational benefits

**centralized management**: one vault for all your secrets across all projects. no more hunting through dozens of `.env` files.

**clipboard integration**: copy secrets directly to clipboard with auto-clear after 30 seconds. no terminal history pollution.

**easy injection**: `secrets env run --` injects all secrets as environment variables without modifying your shell or project files.

**no git accidents**: secrets never touch your project directory. no risk of committing them.

**cross-project sharing**: use the same database url across multiple projects without duplicating it.

## technical implementation

### architecture

```
┌─────────────────────────────────────────────────┐
│                  user password                   │
│                  (pbkdf2 600k)                   │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│              derived key (32 bytes)              │
│         (used to encrypt master key)             │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  encrypted master key + salt → system keyring   │
│    (windows credential manager / keychain)       │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│         master key (32 bytes, decrypted)         │
│       (used to encrypt/decrypt secrets)          │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│         encrypted secrets in vault.json          │
│     (stored in admin-protected directory)        │
└─────────────────────────────────────────────────┘
```

### encryption details

- **key derivation**: pbkdf2-hmac-sha256 with 600,000 iterations (owasp 2023 recommendation)
- **encryption**: aes-256-gcm with random nonces
- **master key**: 256-bit random key generated with `crypto/rand`
- **vault integrity**: hmac-sha256 with vault-specific key derived from vault id

### storage locations

- **windows**: `C:\ProgramData\secrets-manager\vault\vault.json`
- **linux/macos**: `/var/lib/secrets-manager/vault.json`

these directories require administrator/root privileges to write, preventing unauthorized modification.

### security features

1. **memory locking**: sensitive data (keys, passwords, decrypted secrets) is locked in ram using `VirtualLock` (windows) or `mlock` (unix) to prevent swapping to disk.

2. **memory zeroing**: all sensitive byte arrays are zeroed before being unlocked and garbage collected.

3. **rate limiting**: failed authentication attempts are tracked. after 10 failures, the vault locks for 5 minutes.

4. **privilege enforcement**: vault initialization and modification require administrator (windows) or root (linux/macos) privileges.

5. **input validation**: secret names must match `^[A-Z_][A-Z0-9_]*$` to prevent injection attacks when used as environment variables.

6. **clipboard safety**: when copying secrets to clipboard with `--clip`, the clipboard is only cleared if it still contains the secret after 30 seconds (prevents clearing user's new clipboard content).

### dependencies

- `golang.org/x/crypto` - pbkdf2 key derivation
- `golang.org/x/sys` - memory locking (VirtualLock/mlock)
- `github.com/zalando/go-keyring` - system keyring integration
- `github.com/atotto/clipboard` - clipboard operations
- `github.com/charmbracelet/lipgloss` - terminal ui styling

## security considerations

this tool is designed for local dev use. it's significantly more secure than plaintext `.env` files, but it's not a replacement for production secret management systems like hashicorp vault or aws secrets manager.

**threat model**: protects against accidental exposure (git commits, file sharing), casual snooping, basic attacks, and even admin/root access without your password. does not protect against:
- malware with keylogger capabilities (can capture your password as you type it)
- sophisticated memory dump attacks (untested, but memory locking should help)

note: even with physical access to an unlocked system, secrets are safe unless you have a terminal open displaying them without using `--clip`. admin/root access alone doesn't help an attacker, they still need your password.

**password strategy**: use a long passphrase (6+ random words like `correct-horse-battery-staple-purple-elephant`) rather than a complex password. it's easier to remember and with 600k pbkdf2 iterations, brute force is impractical. if you want maximum security, store the password in a hardware-backed password manager (yubikey + bitwarden/1password), but that's overkill for most dev use cases.

if your threat model includes advanced persistent threats or you're working with highly sensitive data, consider hardware security modules (hsm) or cloud-based secret management with mfa.

## contributing

this is a personal project, but if you find bugs or have suggestions, feel free to open an issue.


---

made with :3 by someone who was tired of people deploying shit with their db string and paypal password and home address and social security number and the name of the first girl they ever liked in env vars
