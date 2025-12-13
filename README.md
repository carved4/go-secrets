# go-secrets

a secure, local-first secrets management tool for developers

## why i made this

managing secrets sucks. we all know it. you've got `.env` files scattered across projects, api keys in your shell history, passwords in plaintext config files. one accidental `git add .` and your production database credentials are on github for the world to see.

i wanted something simple: a single encrypted vault on my machine, protected by my os keyring, with secrets i can inject into any command without ever touching a file. no cloud services, no subscriptions, no complexity. just secure local storage that actually works.

## what it does

secrets manager stores your sensitive data (api keys, tokens, passwords, connection strings) in an encrypted vault. each secret is encrypted with aes-256-gcm, and the master encryption key is stored in your system keyring (windows credential manager, macos keychain, or linux secret service).

### core features

- **multiple vaults**: create separate vaults for different contexts (personal, work, projects)
- **easy vault switching**: switch between vaults with a single command
- store secrets from your clipboard with one command
- retrieve secrets to clipboard or display them securely
- inject all secrets as environment variables into any command
- list your stored secrets without authentication
- delete secrets when you're done with them

### backup and recovery

- export encrypted backups of your entire vault
- import secrets from encrypted backup files
- automatic backups after add/delete operations
- keeps last 10 backups with automatic cleanup

### multi-user support

- optional multi-user mode with separate vault
- per-user encrypted master key shares
- group-based access control with secret prefix matching
- independent solo and group vaults can coexist

### audit logging

- encrypted audit trail of all operations
- tracks user, action, timestamp, local ip, public ip, and success/failure
- view history with the history command
- retains last 10,000 events

## installation

requires go 1.24 or later.

```bash
go install github.com/carved4/go-secrets/cmd/secrets@latest
```

on windows, run as administrator. on linux/macos, run with sudo.

## usage

### solo vault (default)

#### create and manage vaults

```bash
# create a new vault
secrets vault create

# list all vaults
secrets vault list

# switch to a different vault
secrets vault switch work

# show current vault info
secrets vault info

# delete a vault
secrets vault delete old-vault
```

each vault is completely independent with its own:
- secrets
- encryption keys (derived from same passphrase but cryptographically independent)
- audit logs
- backups

#### initialize your vault

```bash
# windows (run as administrator)
# open cmd prompt as admin, then
secrets

# linux/macos (run with sudo)
sudo secrets init
```

you'll be prompted to create a password (minimum 12 characters). this password encrypts your master key.

#### add a secret

copy your secret to clipboard, then:

```bash
secrets add
```

you'll be prompted for your password and a name for the secret (use env var format like `DATABASE_URL` or `API_KEY`).

#### retrieve a secret

```bash
# display in terminal
secrets get DATABASE_URL

# copy to clipboard (auto-clears after 30 seconds)
secrets get DATABASE_URL --clip
```

#### list all secrets

```bash
secrets list
```

no password required - just shows names, not values.

#### delete a secret

```bash
secrets delete API_KEY
```

#### rotate secrets

rotate all secrets (post-compromise or regular rotation):

```bash
secrets rotate
```

you'll be asked if you want to import from a `.env` file or paste each secret individually. importing from a file will:
1. parse the `.env` file
2. replace all secrets with new values
3. offer to delete the source file for security

rotate a specific secret:

```bash
secrets rotate API_KEY
```

prompts you to paste the new value for that specific secret.

#### run commands with secrets as environment variables

```bash
secrets env run -- node server.js
secrets env run -- python app.py
secrets env run -- ./your-binary
```

all your secrets are automatically injected as environment variables.

#### store and restore large files (databases, keys, assets)

store large files (up to 100GB) like database files, SSH keys, or other assets:

```bash
# store a file as a secret
secrets add --file database.db

# files over 100MB automatically use streaming encryption (64MB chunks)
# this keeps memory usage low even for very large files

# restore the file when needed
secrets restore DATABASE_DB

# restore to a specific path
secrets restore DATABASE_DB --output ./restored/database.db

# securely wipe the file when done (3-pass overwrite + deletion)
secrets wipe ./restored/database.db
```

perfect for:
- database dumps and backups (up to 100GB)
- ssl/tls certificates and private keys
- ssh keys
- application binaries
- large configuration files
- encrypted backups
- vm images or container layers

**streaming encryption**: files larger than 100MB are automatically encrypted in 64MB chunks, meaning:
- memory usage stays constant regardless of file size
- can handle 10GB+ files without loading everything into RAM
- each chunk is independently encrypted with AES-256-GCM
- decryption is also streamed, writing directly to disk

the `wipe` command performs 3-pass random overwriting before deletion to prevent data recovery.

### backup and recovery

#### export secrets

```bash
secrets export backup.enc
```

creates an encrypted backup file containing all secrets and vault metadata.

#### import secrets

```bash
secrets import backup.enc
```

imports and merges secrets from an encrypted backup file.

#### manual backup

```bash
secrets backup
```

creates an automatic backup in the vault backup directory. backups are created automatically after add/delete operations.

### multi-user vault

#### initialize group vault

```bash
secrets --group init
```

you'll be prompted for:
- admin username
- admin password
- initial group name
- secret prefixes for the group (comma-separated, e.g., `DB_,API_`)

#### switch between vaults

in interactive mode, use `mode` or `toggle` to switch between solo and group vaults. the prompt shows current mode:
- `secrets>` - solo vault
- `secrets[group]>` - group vault

alternatively, use `--group` flag with any command:

```bash
secrets --group add
secrets --group list
```

#### manage users

```bash
# add a new user
secrets --group user add

# list all users
secrets --group user list
```

#### manage groups

```bash
# create a new group
secrets --group group create

# list all groups
secrets --group group list
```

groups control access to secrets based on name prefixes. for example, a group with prefix `DB_` can access `DB_PASSWORD` and `DB_URL` but not `API_KEY`.

### audit logging

```bash
secrets history
```

displays the last 50 audit events showing user, action, secret name, timestamp, local IP, public IP, and success/failure status.

audit logs track both local network IP and public IP to help identify access patterns, especially useful in multi-user environments where team members may be accessing from different locations.

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

#### solo vault architecture

```
┌─────────────────────────────────────────────────┐
│           user password + vault name             │
│         (mixed into pbkdf2 600k for              │
│          vault-specific key derivation)          │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│         vault-specific derived key               │
│         (used to encrypt master key)             │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  encrypted master key + salt → keyring.json     │
│        (stored in vault directory)               │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│      vault-specific master key (decrypted)       │
│       (used to encrypt/decrypt secrets)          │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│         encrypted secrets in vault.json          │
│     (stored in admin-protected directory)        │
└─────────────────────────────────────────────────┘
```

**key insight**: same passphrase unlocks all vaults, but each vault has a cryptographically independent master key because the vault name is mixed into the key derivation function. this means:
- convenience: remember one passphrase
- security: compromising one vault doesn't compromise others
- flexibility: each vault can be backed up, rotated, and managed independently

#### multi-user vault

```
vault-group.json structure:
{
  "mode": "multi-user",
  "secrets": { "DB_URL": "encrypted...", ... },
  "master_key_shares": {
    "user1": { "encrypted_share": "...", "salt": "..." },
    "user2": { "encrypted_share": "...", "salt": "..." }
  },
  "groups": {
    "admins": {
      "users": ["user1", "user2"],
      "secret_prefix": ["DB_", "API_", "ADMIN_"]
    }
  }
}
```

each user has their own encrypted copy of the master key. groups define which users can access which secrets based on name prefixes.

### encryption details

- **key derivation**: pbkdf2-hmac-sha256 with 600,000 iterations (owasp 2023 recommendation)
- **encryption**: aes-256-gcm with random nonces
- **master key**: 256-bit random key generated with `crypto/rand`
- **vault integrity**: hmac-sha256 with vault-specific key derived from vault id

### storage locations

#### windows
- vault config: `C:\ProgramData\secrets-manager\vault-config.json`
- vaults: `C:\ProgramData\secrets-manager\vaults\<vault-name>\`
  - vault file: `vault.json`
  - keyring: `keyring.json`
  - audit log: `audit.json`
  - backups: `backups\`

#### linux/macos
- vault config: `/var/lib/secrets-manager/vault-config.json`
- vaults: `/var/lib/secrets-manager/vaults/<vault-name>/`
  - vault file: `vault.json`
  - keyring: `keyring.json`
  - audit log: `audit.json`
  - backups: `backups/`

these directories require administrator/root privileges to write, preventing unauthorized modification.

### security features

1. **memory locking**: sensitive data (keys, passwords, decrypted secrets) is locked in ram using `VirtualLock` (windows) or `mlock` (unix) to prevent swapping to disk.

2. **memory zeroing**: all sensitive byte arrays are zeroed before being unlocked and garbage collected.

3. **rate limiting**: failed authentication attempts are tracked. after 10 failures, the vault locks for 5 minutes.

4. **privilege enforcement**: vault initialization and modification require administrator (windows) or root (linux/macos) privileges.

5. **input validation**: secret names must match `^[A-Z_][A-Z0-9_]*$` to prevent injection attacks when used as environment variables.

6. **clipboard safety**: when copying secrets to clipboard with `--clip`, the clipboard is only cleared if it still contains the secret after 30 seconds (prevents clearing user's new clipboard content).

7. **audit logging**: all operations are logged with encryption. audit events include timestamp, user, action, secret name, local ip, public ip, and success/failure status. logs are encrypted with the master key and stored separately from the vault. public ip tracking helps identify access patterns in multi-user scenarios.

8. **automatic backups**: encrypted backups are created automatically after add/delete operations. backups include vault metadata and timestamp, with automatic cleanup keeping only the last 10 backups.

9. **large file support**: store files up to 100GB. files over 100MB use streaming encryption (64MB chunks) to keep memory usage constant. the `restore` command decrypts to disk and `wipe` provides secure 3-pass deletion.

10. **async public ip fetching**: public ip addresses are fetched asynchronously during audit logging to avoid blocking operations, with a 3-second timeout per service.

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
