# pgvictoria-admin

`pgvictoria-admin` is the administration utility used to manage the master key file and encrypt user credentials for the `pgvictoria` environment.

## Usage

```bash
pgvictoria-admin [ -f FILE ] [ -F FORMAT ] [ COMMAND ]
```

## Options

*   **-f, --file FILE**
    Set the path to the `pgvictoria_users.conf` configuration file (defaults to `/etc/pgvictoria/pgvictoria_users.conf`).

*   **-U, --user USER**
    Set the user name to be added, edited, or removed.

*   **-P, --password PASSWORD**
    Set the password for the user.
    *Note: Providing passwords directly on the command line is not recommended for production setups, as it exposes the password in process listings.*

*   **-g, --generate**
    Generate a secure random password for the user.

*   **-l, --length LENGTH**
    Specify the length of the generated password (defaults to 64).

*   **-F, --format FORMAT**
    Set the output format of the administration commands: `text` (default) or `json`.

*   **-V, --version**
    Display version information.

*   **-?, --help**
    Display the help and usage guide.

---

## Commands

### master-key

Generates a secure master key used to encrypt the user passwords. The master key will be created in the user's home directory under `~/.pgvictoria/master.key`.

```bash
pgvictoria-admin master-key
```

*Note: You can pass the master key password non-interactively using the `PGVICTORIA_PASSWORD` environment variable.*

### user add

Adds a new user and encrypted password entry to `pgvictoria_users.conf`.

```bash
pgvictoria-admin -U <username> user add
```

### user edit

Updates the password of an existing user in `pgvictoria_users.conf`.

```bash
pgvictoria-admin -U <username> user edit
```

### user del

Removes a user's entry from `pgvictoria_users.conf`.

```bash
pgvictoria-admin -U <username> user del
```

### user ls

Lists all configured usernames in `pgvictoria_users.conf`.

```bash
pgvictoria-admin user ls
```

---

## Security

`pgvictoria-admin` implements standard security best-practices:
- **Strict File Permissions**: The `~/.pgvictoria` folder is created with `0700` permissions, and `master.key` and `pgvictoria_users.conf` are created with `0600` permissions.
- **Memory Cleansing**: Sensitive memory buffers (plaintext passwords and master keys) are securely zeroed out in RAM using `pgvictoria_cleanse` before freeing to mitigate exposure in core dumps or memory dumps.
