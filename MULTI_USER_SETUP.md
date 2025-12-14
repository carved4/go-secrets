# Multi-User Vault Setup Guide

## Important: Multi-User Vaults Require Shared Storage

Multi-user vaults in this system are designed for **shared filesystem access**, not remote access. This means:

### Prerequisites
- All users must have access to the same vault directory
- Common scenarios:
  - Network share (\\server\shared\vaults\)
  - Cloud sync folder (Dropbox, OneDrive, etc.)
  - Shared server with multiple SSH users

### Setup Workflow

#### Option 1: Network Share (Recommended for Teams)

**Admin Setup:**
```bash
# On admin machine or server
1. Create network share: \\fileserver\secrets\team-vault
2. Grant access to all team members (Read/Write permissions)
3. Initialize the vault:
   
   vault create team-vault (type: group)
   vault switch team-vault
   mode                    # switch to group mode
   init                    # creates multi-user vault
   # Enter admin credentials and initial group setup
   
4. Share the vault location with team members
```

**Team Member Setup:**
```bash
# On each team member's machine
1. Mount the network share (Z:\team-vault)
2. Configure secrets-manager to use shared location:
   
   # Create symlink or configure vault path
   mklink /D "C:\ProgramData\secrets-manager\vaults\team-vault" "Z:\team-vault"
   
3. Switch to the vault:
   vault switch team-vault
   
4. Ask admin to add your user:
   # Admin runs: user add
   
5. You can now authenticate with your username/password
```

#### Option 2: Cloud Sync Folder

**Admin Setup:**
```bash
1. Create vault in synced folder:
   # Windows: C:\Users\Admin\Dropbox\secrets\
   # Mac: ~/Dropbox/secrets/
   
2. Create symlink:
   mklink /D "C:\ProgramData\secrets-manager\vaults\shared" "C:\Users\Admin\Dropbox\secrets"
   
3. Initialize as group vault (same as above)
```

**Team Member Setup:**
```bash
1. Wait for Dropbox to sync the vault files
2. Create symlink on your machine:
   mklink /D "C:\ProgramData\secrets-manager\vaults\shared" "C:\Users\YourName\Dropbox\secrets"
   
3. Switch to vault and authenticate
```

### Security Considerations

**SECURITY NOTES:**

1. **Filesystem Permissions**: Vault files on the shared location should have strict access controls
2. **Audit Logging**: The vault records all access in audit logs (encrypted)
3. **Master Key**: Each user has their own password-encrypted copy of the master key
4. **Group Permissions**: Use groups to control which users can access which secrets
5. **Backup Password**: Store the backup password securely - users need it for recovery

### Current Limitations

- No built-in remote server/client architecture (files must be accessible via filesystem)
- No real-time sync notifications (users see changes on next operation)
- No conflict resolution (last write wins)
- Network latency affects performance

### Recommended Use Cases

**Good for:**
- Small teams with network share access
- DevOps teams on same infrastructure
- Synchronized folder scenarios (Dropbox, etc.)

❌ **Not ideal for:**
- Remote teams without shared storage
- Large distributed teams
- High-frequency concurrent access

### Alternative: Solo Vault Per User + Shared Secrets

For remote teams without shared storage, consider:
1. Each user has their own solo vault
2. Use `export` command to share specific secrets securely
3. Re-import into each user's vault

```bash
# User A exports a secret
secrets export shared-api-keys.enc
# Send file securely to User B

# User B imports
secrets import shared-api-keys.enc
```

This is less convenient but works without shared filesystem access.

