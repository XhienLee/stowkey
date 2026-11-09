# Stowkey

A small, self-hosted encrypted file locker written in plain PHP. There are no usernames or passwords: registering creates a random access key, and that key is the only way into the vault.

## Features

- Anonymous accounts based on a server-generated UUIDv4 access key
- Every file and filename encrypted, with tamper detection
- Multi-file upload with progress, trash, restore and permanent delete
- 1 GiB storage quota per user
- Files kept outside the web root, so uploads can never be executed or opened by URL

> **There is no key recovery.** If an access key is lost, its files cannot be decrypted by anyone.

## Requirements

- PHP 8.1 or newer with the `sodium`, `pdo_sqlite` and `mbstring` extensions
- Apache with mod_php, or nginx with PHP-FPM
- HTTPS for any public deployment, because the access key is sent at login

## Install

These examples use `/var/www/vault` for the code and `/var/lib/vault` for data. The data folder **must be outside the web root**. The app returns a 500 error and logs the reason if it is not.

```bash
sudo mkdir -p /var/www/vault /var/lib/vault
sudo cp -r *.php app.css app.js favicon.svg fonts /var/www/vault/
sudo chown www-data /var/lib/vault
sudo chmod 700 /var/lib/vault
```

### Apache

```apache
<VirtualHost *:80>
    DocumentRoot /var/www/vault
    SetEnv VAULT_DATA_DIR /var/lib/vault
    php_admin_value upload_max_filesize 100M
    php_admin_value post_max_size 110M

    <Directory /var/www/vault>
        AllowOverride None
        Require all granted
        DirectoryIndex index.php
    </Directory>
</VirtualHost>
```

### nginx with PHP-FPM

```nginx
server {
    listen 80;
    root /var/www/vault;
    index index.php;
    client_max_body_size 110M;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~ \.php$ {
        try_files $uri =404;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param VAULT_DATA_DIR /var/lib/vault;
        fastcgi_param HTTPS $https if_not_empty;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
}
```

Set `upload_max_filesize` and `post_max_size` in the PHP-FPM `php.ini`, then restart PHP-FPM. Adjust the socket path to match your PHP version.

If `VAULT_DATA_DIR` is not set, the app uses a `vault_data` folder next to the code folder.

## Configuration

These limits are constants at the top of `lib.php`:

| Constant | Default | Purpose |
|---|---|---|
| `VAULT_QUOTA_BYTES` | 1 GiB | Storage per user, including trash |
| `VAULT_IDLE_SECONDS` | 1800 | Log users out after this much inactivity |
| `VAULT_MIN_FREE_BYTES` | 1 GiB | Uploads stop when free disk falls below this |
| `VAULT_REG_PER_IP_HOUR` | 5 | New keys per IP address (or IPv6 /64) each hour |
| `VAULT_REG_GLOBAL_HOUR` | 100 | New keys across the whole site each hour |
| `VAULT_CHUNK_BYTES` | 1 MiB | Encryption chunk size. Do not change once files exist |

`VAULT_QUOTA_BYTES`, `VAULT_IDLE_SECONDS` and the two registration limits can also be set with environment variables of the same name.

The browser checks file sizes before uploading, but that is only for convenience. The server still enforces the quota. To reject oversized uploads as early as possible, also set `LimitRequestBody` on Apache or `client_max_body_size` on nginx.

For a public demo, lower the storage limits, for example `VAULT_QUOTA_BYTES=104857600` (100 MiB) and `VAULT_REG_GLOBAL_HOUR=20`.

Behind a reverse proxy or CDN, configure your web server to restore the real client address (`mod_remoteip` or nginx `real_ip`). Otherwise every visitor shares the proxy address and one limit.

## Upgrading from the `keys.json` version

Accounts and files from the old version are not migrated. After deploying, delete the old `keys.json` and `repo/` from the web root, because they remain publicly reachable until you do.

## Backups

Back up `vault.db` and the `files/` folder together, from the data folder. Stop the web server first, or copy the database with SQLite's `.backup` command.

## Security model

- The database stores only a one-way hash of each access key.
- Keys are derived from the access key with HKDF. Files use XChaCha20-Poly1305 through libsodium's secretstream, and filenames use `crypto_secretbox`.
- Stolen files and databases cannot be decrypted without the access keys.
- Registration limits use a salted hash of the client address, kept for one hour. Raw addresses are not stored.
- The Content-Security-Policy allows scripts only from this site, with no inline scripts.
- Forms use CSRF tokens, and session cookies are `HttpOnly` and `SameSite=Lax`, plus `Secure` over HTTPS.

Known limits:

- While a user is logged in, their derived key is in a session file in the private data folder. A newly created access key also stays there until the user confirms they saved it or the session times out. Someone who controls the running server can read files of active users or capture keys at login.
- File sizes, upload times and the number of files per user are not encrypted.
- Disk can still be filled by many accounts. When free space runs out, uploads stop for everyone.
- Registration limits slow abuse but cannot stop an attacker with many IP addresses. The site-wide limit caps growth, but such an attacker could use it up and block new keys for an hour.
- The HKDF labels in `lib.php` must not change once data exists, or existing files become unreadable.
