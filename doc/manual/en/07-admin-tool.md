\newpage

# Administration utility

`pgvictoria-admin` is the administration utility used to manage the master key file and encrypt user credentials for the `pgvictoria` environment.

## Overview

The tool provides several commands to interact with credentials:

*   **master-key**: Create or update the master key.
*   **user add**: Add a new user with an encrypted password.
*   **user edit**: Update the password of an existing user.
*   **user del**: Remove a user.
*   **user ls**: List all users.

## Usage

### Generating a Master Key

Before user passwords can be encrypted or decrypted, a master key must be generated:

``` sh
pgvictoria-admin master-key
```

This prompts for a password and creates the key file in `~/.pgvictoria/master.key` with `0600` permissions. The key can also be provided non-interactively via the `PGVICTORIA_PASSWORD` environment variable.

### Adding a User

To add a user and encrypt their database password:

``` sh
pgvictoria-admin -f pgvictoria_users.conf -U username user add
```

This will prompt for the password, encrypt it using the master key with `AES-256-CBC`, and save the base64-encoded encrypted string in `pgvictoria_users.conf`.

### Listing Registered Users

To view all configured usernames:

``` sh
pgvictoria-admin -f pgvictoria_users.conf user ls
```

## Security

`pgvictoria-admin` implements several security-hardening features:
*   **Strict File Permissions**: Config files and directories are created with `0600` and `0700` permissions respectively.
*   **Memory Wiping**: Sensitive stack-allocated key material and heap-allocated plaintext passwords are zeroed out using `pgvictoria_cleanse` before being freed to prevent leaks in core dumps or memory dumps.
