<?php
declare(strict_types=1);

const VAULT_CHUNK_BYTES = 1048576;
const VAULT_QUOTA_BYTES = 1073741824;
const VAULT_MIN_FREE_BYTES = 1073741824;
const VAULT_IDLE_SECONDS = 1800;
const VAULT_REG_PER_IP_HOUR = 5;
const VAULT_REG_GLOBAL_HOUR = 100;
const VAULT_UUID4 = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';

function vault_fail(string $log): never {
    error_log("vault: $log");
    http_response_code(500);
    exit('Server error.');
}

function data_dir(): string {
    static $dir = null;
    if ($dir !== null) return $dir;

    $configured = $_SERVER['VAULT_DATA_DIR'] ?? getenv('VAULT_DATA_DIR') ?: dirname(__DIR__) . '/vault_data';
    if (!is_dir($configured) && !@mkdir($configured, 0700, true) && !is_dir($configured)) {
        vault_fail("cannot create data directory $configured");
    }
    $real = realpath($configured);
    foreach ([$_SERVER['DOCUMENT_ROOT'] ?? '', __DIR__] as $root) {
        $root = $root === '' ? false : realpath($root);
        if ($real === false || ($root !== false && str_starts_with($real . '/', rtrim($root, '/') . '/'))) {
            vault_fail('VAULT_DATA_DIR must be outside the web root');
        }
    }
    return $dir = $real;
}

function db(): PDO {
    static $db = null;
    if ($db !== null) return $db;

    $path = data_dir() . '/vault.db';
    $db = new PDO("sqlite:$path");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $db->setAttribute(PDO::ATTR_TIMEOUT, 5);
    $db->exec('PRAGMA journal_mode=WAL');
    $db->exec('PRAGMA foreign_keys=ON');
    $db->exec('CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_hash TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL
    )');
    $db->exec('CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        stored_name TEXT NOT NULL UNIQUE,
        name_enc BLOB NOT NULL,
        size INTEGER NOT NULL,
        stored_size INTEGER NOT NULL,
        in_trash INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
    )');
    $db->exec('CREATE TABLE IF NOT EXISTS settings (
        name TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )');
    $db->exec('CREATE TABLE IF NOT EXISTS registrations (
        client TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )');
    $db->exec('CREATE INDEX IF NOT EXISTS registrations_by_time ON registrations(created_at)');
    $db->exec('CREATE INDEX IF NOT EXISTS files_by_user ON files(user_id, in_trash)');
    @chmod($path, 0600);
    return $db;
}

function start_session(): void {
    data_dir();
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    $idle = limit_setting('VAULT_IDLE_SECONDS', VAULT_IDLE_SECONDS);
    $sessions = data_dir() . '/sessions';
    if (!is_dir($sessions) && !@mkdir($sessions, 0700, true) && !is_dir($sessions)) {
        vault_fail("cannot create $sessions");
    }
    session_save_path($sessions);
    ini_set('session.gc_maxlifetime', (string) $idle);
    ini_set('session.gc_probability', '1');
    ini_set('session.gc_divisor', '50');
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
    session_set_cookie_params([
        'lifetime' => 0, 'path' => '/', 'secure' => $https, 'httponly' => true, 'samesite' => 'Lax',
    ]);
    session_start();
    $now = time();
    if (!empty($_SESSION['uid']) && $now - (int) ($_SESSION['last_seen'] ?? $now) > $idle) {
        $_SESSION = ['timed_out' => true];
        session_regenerate_id(true);
    }
    $_SESSION['last_seen'] = $now;
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
}

function csrf_token(): string {
    return $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
}

function csrf_valid(): bool {
    return isset($_SESSION['csrf'], $_POST['csrf']) && is_string($_POST['csrf'])
        && hash_equals($_SESSION['csrf'], $_POST['csrf']);
}

function h(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function generate_uuid4(): string {
    $data = random_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

function key_lookup(string $accessKey): string {
    return bin2hex(hash_hkdf('sha256', strtolower($accessKey), 32, 'nos-vault-lookup-v1'));
}

function key_master(string $accessKey): string {
    return hash_hkdf('sha256', strtolower($accessKey), 32, 'nos-vault-master-v1');
}

function subkey(string $master, string $purpose): string {
    return hash_hkdf('sha256', $master, 32, "nos-vault-$purpose-v1");
}

function log_in(int $userId, string $accessKey): void {
    session_regenerate_id(true);
    $_SESSION['uid'] = $userId;
    $_SESSION['master'] = base64_encode(key_master($accessKey));
    unset($_SESSION['csrf']);
}

function encrypt_name(string $name, string $master): string {
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return $nonce . sodium_crypto_secretbox($name, $nonce, subkey($master, 'names'));
}

function decrypt_name(string $blob, string $master): string {
    $nonce = substr($blob, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $box = substr($blob, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $name = sodium_crypto_secretbox_open($box, $nonce, subkey($master, 'names'));
    return $name === false ? '[unreadable name]' : $name;
}

function read_full($handle, int $length): string {
    $buffer = '';
    while (strlen($buffer) < $length && !feof($handle)) {
        $part = fread($handle, $length - strlen($buffer));
        if ($part === false) throw new RuntimeException('read failed');
        $buffer .= $part;
    }
    return $buffer;
}

function write_full($handle, string $data): void {
    if (fwrite($handle, $data) !== strlen($data)) throw new RuntimeException('write failed');
}

function encrypt_file(string $source, string $target, string $master, string $storedName): void {
    $in = fopen($source, 'rb');
    $out = fopen($target, 'xb');
    if (!$in || !$out) throw new RuntimeException('cannot open file');

    try {
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push(subkey($master, 'files'));
        write_full($out, $header);
        $chunk = read_full($in, VAULT_CHUNK_BYTES);
        while (true) {
            $next = strlen($chunk) === VAULT_CHUNK_BYTES ? read_full($in, VAULT_CHUNK_BYTES) : '';
            $tag = $next === ''
                ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
            write_full($out, sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk, $storedName, $tag));
            if ($next === '') break;
            $chunk = $next;
        }
    } finally {
        fclose($in);
        fclose($out);
    }
}

function decrypt_chunks(string $path, string $master, string $storedName): Generator {
    $in = fopen($path, 'rb');
    if (!$in) throw new RuntimeException('cannot open file');

    try {
        $header = read_full($in, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
        if (strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
            throw new RuntimeException('truncated header');
        }
        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, subkey($master, 'files'));
        $sealed = VAULT_CHUNK_BYTES + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
        while (true) {
            $cipher = read_full($in, $sealed);
            if (strlen($cipher) < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES) {
                throw new RuntimeException('truncated file');
            }
            $result = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $cipher, $storedName);
            if ($result === false) throw new RuntimeException('authentication failed');
            [$plain, $tag] = $result;
            if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                if (read_full($in, 1) !== '') throw new RuntimeException('trailing data');
                yield $plain;
                return;
            }
            yield $plain;
        }
    } finally {
        fclose($in);
    }
}

function clean_name(string $name): string {
    $name = basename(str_replace('\\', '/', $name));
    $name = preg_replace('/[\x00-\x1f\x7f]/u', '', $name) ?? '';
    $name = mb_substr($name, 0, 200, 'UTF-8');
    return ($name === '' || $name === '.' || $name === '..') ? 'unnamed' : $name;
}

function unique_name(string $name, array $taken): string {
    $extension = pathinfo($name, PATHINFO_EXTENSION);
    $stem = pathinfo($name, PATHINFO_FILENAME);
    $candidate = $name;
    for ($i = 1; in_array($candidate, $taken, true); $i++) {
        $candidate = $stem . " ($i)" . ($extension === '' ? '' : ".$extension");
    }
    return $candidate;
}

function file_rows(int $userId, bool $trash): array {
    $stmt = db()->prepare('SELECT * FROM files WHERE user_id = ? AND in_trash = ? ORDER BY id DESC');
    $stmt->execute([$userId, $trash ? 1 : 0]);
    return $stmt->fetchAll();
}

function active_names(int $userId, string $master): array {
    return array_map(fn($row) => decrypt_name($row['name_enc'], $master), file_rows($userId, false));
}

function user_dir(int $userId): string {
    $dir = data_dir() . "/files/$userId";
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        vault_fail("cannot create $dir");
    }
    return $dir;
}

function upload_error(int $code): string {
    return match ($code) {
        UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'file exceeds the server upload limit',
        UPLOAD_ERR_PARTIAL => 'upload was interrupted',
        default => 'upload failed',
    };
}

function format_bytes(int $bytes): string {
    if ($bytes < 1024) return $bytes . ' B';
    if ($bytes < 1048576) return round($bytes / 1024) . ' KB';
    if ($bytes < 1073741824) return number_format($bytes / 1048576, 1) . ' MB';
    return rtrim(rtrim(number_format($bytes / 1073741824, 1), '0'), '.') . ' GB';
}

function set_flash(string $message, ?int $undo = null): void {
    $_SESSION['flash'] = ['message' => $message, 'undo' => $undo];
}

function take_flash(): ?array {
    $flash = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    return $flash;
}

function page_head(string $title): void {
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?php echo h($title); ?></title>
    <link rel="icon" href="favicon.svg" type="image/svg+xml">
    <link rel="stylesheet" href="app.css">
    <script src="app.js" defer></script>
</head>
<?php
}

function key_tag(string $key): void {
    echo '<div class="key-tag"><span class="key-hole" aria-hidden="true"></span><div class="key-segments">';
    foreach (explode('-', $key) as $part) {
        echo '<span>' . h($part) . '</span>';
    }
    echo '</div></div>';
}

function limit_setting(string $name, int $default): int {
    $value = $_SERVER[$name] ?? getenv($name);
    return ($value !== false && ctype_digit((string) $value)) ? (int) $value : $default;
}

function client_fingerprint(): string {
    $packed = @inet_pton($_SERVER['REMOTE_ADDR'] ?? '') ?: '';
    if (strlen($packed) === 16) {
        $mapped = str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff");
        $packed = $mapped ? substr($packed, 12) : substr($packed, 0, 8);
    }
    db()->exec("INSERT OR IGNORE INTO settings (name, value) VALUES ('client_salt', '" . bin2hex(random_bytes(32)) . "')");
    $salt = db()->query("SELECT value FROM settings WHERE name = 'client_salt'")->fetchColumn();
    return hash_hmac('sha256', $packed, $salt);
}

function register_user(string $accessKey): ?int {
    $client = client_fingerprint();
    $since = time() - 3600;
    $db = db();
    $db->exec('BEGIN IMMEDIATE');
    try {
        $db->prepare('DELETE FROM registrations WHERE created_at <= ?')->execute([$since]);
        $total = (int) $db->query('SELECT COUNT(*) FROM registrations')->fetchColumn();
        $mine = $db->prepare('SELECT COUNT(*) FROM registrations WHERE client = ?');
        $mine->execute([$client]);
        if ($total >= limit_setting('VAULT_REG_GLOBAL_HOUR', VAULT_REG_GLOBAL_HOUR)
            || (int) $mine->fetchColumn() >= limit_setting('VAULT_REG_PER_IP_HOUR', VAULT_REG_PER_IP_HOUR)) {
            $db->exec('ROLLBACK');
            return null;
        }
        $db->prepare('INSERT INTO registrations (client, created_at) VALUES (?, ?)')->execute([$client, time()]);
        $db->prepare('INSERT INTO users (key_hash, created_at) VALUES (?, ?)')->execute([key_lookup($accessKey), time()]);
        $id = (int) $db->lastInsertId();
        $db->exec('COMMIT');
        return $id;
    } catch (Throwable $e) {
        if ($db->inTransaction()) $db->exec('ROLLBACK');
        throw $e;
    }
}

const SESSION_STATES = [
    'anonymous' => ['home' => 'login.php', 'pages' => ['index', 'login', 'state'], 'actions' => ['login', 'register']],
    'key_pending' => ['home' => 'key.php', 'pages' => ['index', 'key', 'state', 'logout'], 'actions' => ['confirm_key_saved', 'logout']],
    'ready' => ['home' => 'dashboard.php', 'pages' => ['index', 'dashboard', 'state', 'logout'], 'actions' => ['upload', 'download', 'delete', 'restore', 'perm_delete', 'logout']],
];

const FILE_TRANSITIONS = [
    'delete' => ['from' => 0, 'to' => 1],
    'restore' => ['from' => 1, 'to' => 0],
    'perm_delete' => ['from' => 1, 'to' => null],
];

function session_state(): string {
    if (empty($_SESSION['uid']) || empty($_SESSION['master'])) {
        unset($_SESSION['uid'], $_SESSION['master'], $_SESSION['new_key']);
        return 'anonymous';
    }
    return empty($_SESSION['new_key']) ? 'ready' : 'key_pending';
}

function is_xhr(): bool {
    return strtolower($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'xmlhttprequest';
}

function json_exit(int $status, array $body): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($body);
    exit();
}

function enter_page(string $page): string {
    $state = session_state();
    if (in_array($page, SESSION_STATES[$state]['pages'], true)) return $state;
    $next = SESSION_STATES[$state]['home'];
    if (is_xhr()) {
        json_exit(401, ['ok' => false, 'code' => 'wrong_state', 'state' => $state, 'next' => $next, 'errors' => [['code' => 'wrong_state', 'message' => 'Your session ended. Log in again, then add your files again.']]]);
    }
    header("Location: $next");
    exit();
}

function vault_quota(): int {
    return limit_setting('VAULT_QUOTA_BYTES', VAULT_QUOTA_BYTES);
}

function brand_mark(): string {
    return '<svg class="brand-mark" width="26" height="26" viewBox="0 0 28 28" aria-hidden="true"><path fill="currentColor" fill-rule="evenodd" d="M9 3h15a2 2 0 0 1 2 2v18a2 2 0 0 1-2 2H9l-7-7V10z M10 14a3 3 0 1 0 6 0a3 3 0 1 0-6 0z"/></svg>';
}

function file_badge(string $name): string {
    $extension = strtoupper(pathinfo($name, PATHINFO_EXTENSION));
    return ($extension === '' || strlen($extension) > 4 || !ctype_alnum($extension)) ? 'FILE' : $extension;
}
