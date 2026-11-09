<?php
require __DIR__ . '/lib.php';
start_session();

enter_page('dashboard');

$user_id = (int) $_SESSION['uid'];
$master = base64_decode($_SESSION['master']);
$dir = user_dir($user_id);

function find_file(int $user_id, mixed $id, int $in_trash): ?array {
    if (!is_scalar($id) || !ctype_digit((string) $id)) return null;
    $stmt = db()->prepare('SELECT * FROM files WHERE id = ? AND user_id = ? AND in_trash = ?');
    $stmt->execute([(int) $id, $user_id, $in_trash]);
    return $stmt->fetch() ?: null;
}

function upload_response(array $errors, int $saved = 0): never {
    json_exit($errors && !$saved ? 400 : 200, ['ok' => !$errors, 'saved' => $saved, 'errors' => $errors, 'state' => 'ready']);
}

if (isset($_GET['download'])) {
    $row = find_file($user_id, $_GET['download'], 0);
    if (!$row) {
        http_response_code(404);
        exit('File not found.');
    }
    try {

        $chunks = decrypt_chunks("$dir/{$row['stored_name']}", $master, $row['stored_name']);
        $first = $chunks->current();
    } catch (Throwable $e) {
        error_log('vault: download failed for file ' . $row['id'] . ': ' . $e->getMessage());
        http_response_code(500);
        exit('This file is damaged and cannot be decrypted.');
    }

    session_write_close();
    $name = decrypt_name($row['name_enc'], $master);
    $ascii = preg_replace('/[^A-Za-z0-9._ ()-]/', '_', $name);
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header("Content-Disposition: attachment; filename=\"$ascii\"; filename*=UTF-8''" . rawurlencode($name));
    header('Content-Length: ' . $row['size']);
    while (ob_get_level()) ob_end_clean();
    echo $first;
    try {
        for ($chunks->next(); $chunks->valid(); $chunks->next()) {
            echo $chunks->current();
            flush();
        }
    } catch (Throwable $e) {

        error_log('vault: download aborted for file ' . $row['id'] . ': ' . $e->getMessage());
    }
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_POST) && empty($_FILES) && (int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 0) {
        upload_response([['code' => 'too_large', 'message' => 'Upload is larger than the server allows.']]);
    }
    if (!csrf_valid()) {
        if (is_xhr()) json_exit(403, ['ok' => false, 'errors' => [['code' => 'csrf_invalid', 'message' => 'This page expired. Reload it and try again.']]]);
        set_flash('This page had expired, so nothing changed. Please try again.');
        header('Location: dashboard.php');
        exit();
    }

    $action = $_POST['action'] ?? '';

    if ($action === 'upload') {
        $files = $_FILES['file_upload'] ?? null;
        if (!$files || !is_array($files['name'])) upload_response([['code' => 'no_files', 'message' => 'No files received.']]);

        $errors = [];
        $saved = 0;
        $last_name = '';
        $taken = active_names($user_id, $master);
        foreach ($files['name'] as $i => $raw_name) {
            $name = clean_name((string) $raw_name);
            $tmp = $files['tmp_name'][$i];
            if ($files['error'][$i] !== UPLOAD_ERR_OK || !is_uploaded_file($tmp)) {
                $errors[] = ['file' => $name, 'code' => 'upload_failed', 'message' => "$name: " . upload_error((int) $files['error'][$i])];
                continue;
            }
            $current = db()->prepare('SELECT COALESCE(SUM(stored_size), 0) FROM files WHERE user_id = ?');
            $current->execute([$user_id]);
            if ((int) $current->fetchColumn() + (int) $files['size'][$i] + stored_size_for((int) $files['size'][$i]) > vault_quota()) {
                $errors[] = ['file' => $name, 'code' => 'quota_exceeded', 'message' => "$name: storage quota exceeded"];
                continue;
            }
            $free = disk_free_space($dir);
            if ($free === false || $free - 2 * $files['size'][$i] < VAULT_MIN_FREE_BYTES) {
                $errors[] = ['file' => $name, 'code' => 'disk_full', 'message' => "$name: server storage is full"];
                continue;
            }

            $stored = bin2hex(random_bytes(32));
            $target = "$dir/$stored";
            try {
                encrypt_file($tmp, $target, $master, $stored);
                $stored_size = filesize($target);
                $final_name = unique_name($name, $taken);

                db()->exec('BEGIN IMMEDIATE');
                $used = db()->prepare('SELECT COALESCE(SUM(stored_size), 0) FROM files WHERE user_id = ?');
                $used->execute([$user_id]);
                if ((int) $used->fetchColumn() + $stored_size > vault_quota()) {
                    db()->exec('ROLLBACK');
                    @unlink($target);
                    $errors[] = ['file' => $name, 'code' => 'quota_exceeded', 'message' => "$name: storage quota exceeded"];
                    continue;
                }
                $insert = db()->prepare('INSERT INTO files (user_id, stored_name, name_enc, size, stored_size, created_at) VALUES (?, ?, ?, ?, ?, ?)');
                $insert->bindValue(1, $user_id, PDO::PARAM_INT);
                $insert->bindValue(2, $stored);
                $insert->bindValue(3, encrypt_name($final_name, $master), PDO::PARAM_LOB);
                $insert->bindValue(4, (int) $files['size'][$i], PDO::PARAM_INT);
                $insert->bindValue(5, $stored_size, PDO::PARAM_INT);
                $insert->bindValue(6, time(), PDO::PARAM_INT);
                $insert->execute();
                db()->exec('COMMIT');
                $taken[] = $final_name;
                $saved++;
                $last_name = $final_name;
            } catch (Throwable $e) {
                if (db()->inTransaction()) db()->exec('ROLLBACK');
                @unlink($target);
                error_log('vault: upload failed: ' . $e->getMessage());
                $errors[] = ['file' => $name, 'code' => 'save_failed', 'message' => "$name: could not be saved"];
            }
        }
        $problem = $errors ? ' Not saved: ' . implode('; ', array_column($errors, 'message')) : '';
        if ($saved === 1) set_flash($last_name . ' uploaded and encrypted.' . $problem);
        if ($saved > 1) set_flash($saved . ' files uploaded and encrypted.' . $problem);
        upload_response($errors, $saved);
    }

    $move = FILE_TRANSITIONS[$action] ?? null;
    if ($move && !find_file($user_id, $_POST['file'] ?? null, $move['from'])) {
        set_flash('That file already changed in another tab, so nothing was done.');
    } elseif ($action === 'delete' && ($row = find_file($user_id, $_POST['file'] ?? null, 0))) {
        db()->prepare('UPDATE files SET in_trash = 1 WHERE id = ?')->execute([$row['id']]);
        set_flash(decrypt_name($row['name_enc'], $master) . ' moved to Trash', (int) $row['id']);
    } elseif ($action === 'restore' && ($row = find_file($user_id, $_POST['file'] ?? null, 1))) {
        $name = unique_name(decrypt_name($row['name_enc'], $master), active_names($user_id, $master));
        $stmt = db()->prepare('UPDATE files SET in_trash = 0, name_enc = :name WHERE id = :id');
        $stmt->bindValue(':name', encrypt_name($name, $master), PDO::PARAM_LOB);
        $stmt->bindValue(':id', (int) $row['id'], PDO::PARAM_INT);
        $stmt->execute();
        set_flash($name . ' restored');
    } elseif ($action === 'perm_delete' && ($row = find_file($user_id, $_POST['file'] ?? null, 1))) {
        db()->prepare('DELETE FROM files WHERE id = ?')->execute([$row['id']]);
        @unlink("$dir/{$row['stored_name']}");
        set_flash(decrypt_name($row['name_enc'], $master) . ' permanently deleted');
    }

    $back = $action === 'perm_delete' ? '?view=trash' : '';
    header("Location: dashboard.php$back");
    exit();
}

$view_trash = ($_GET['view'] ?? '') === 'trash';
$rows = file_rows($user_id, $view_trash);
$csrf = h(csrf_token());
$file_count = count($view_trash ? file_rows($user_id, false) : $rows);
$trash_count = count($view_trash ? $rows : file_rows($user_id, true));
$usage = db()->prepare('SELECT COALESCE(SUM(stored_size), 0) FROM files WHERE user_id = ?');
$usage->execute([$user_id]);
$used = (int) $usage->fetchColumn();
$used_pct = min(100, round($used / vault_quota() * 100, 1));
$flash = take_flash();
page_head(($view_trash ? 'Trash' : 'My files') . ' - Stowkey');
?>
<body data-state="ready" data-view="<?php echo $view_trash ? 'trash' : 'files'; ?>">
<header class="appbar">
    <div class="wrap">
        <a href="index.php" class="brand"><?php echo brand_mark(); ?>Stowkey</a>
        <div class="appbar-right">
            <div class="meter">
                <?php echo h(format_bytes($used)); ?> of <?php echo h(format_bytes(vault_quota())); ?> used
                <div class="meter-track"><span style="width: <?php echo $used_pct; ?>%"></span></div>
            </div>
            <form method="POST" action="logout.php">
                <input type="hidden" name="csrf" value="<?php echo $csrf; ?>">
                <button type="submit" class="link-btn">Log out</button>
            </form>
        </div>
    </div>
</header>
<main class="main">
    <nav class="views" aria-label="Views">
        <a href="dashboard.php"<?php if (!$view_trash) echo ' aria-current="page"'; ?>>My files (<?php echo $file_count; ?>)</a>
        <a href="dashboard.php?view=trash"<?php if ($view_trash) echo ' aria-current="page"'; ?>>Trash (<?php echo $trash_count; ?>)</a>
    </nav>

    <?php if (!$view_trash): ?>
    <section class="drop" id="dropZone" data-free="<?php echo max(0, vault_quota() - $used); ?>" data-max-file="<?php echo ini_bytes('upload_max_filesize'); ?>" data-max-request="<?php echo ini_bytes('post_max_size'); ?>" data-max-count="<?php echo (int) ini_get('max_file_uploads'); ?>" data-header="<?php echo SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES; ?>" data-tag="<?php echo SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES; ?>" data-chunk="<?php echo VAULT_CHUNK_BYTES; ?>" data-trash="<?php echo $trash_count; ?>">
        <p class="drop-title">Add your files</p>
        <input type="hidden" id="csrfToken" value="<?php echo $csrf; ?>">
        <label class="sr-only" for="fileInput">Choose files to upload</label>
        <input class="sr-only" type="file" id="fileInput" multiple tabindex="-1">
        <button type="button" class="btn btn-primary" id="pickBtn">Choose files</button>
        <p class="drop-note">You can also drag files here. Every file is encrypted automatically.</p>
        <div class="progress" id="progress" role="status" hidden>
            <div class="progress-row"><span id="progressLabel">Uploading</span><span id="progressPct">0%</span></div>
            <progress id="progressBar" value="0" max="100"></progress>
        </div>
        <p class="upload-error" id="uploadError" role="alert"></p>
    </section>
    <?php endif; ?>

    <section class="list" aria-label="<?php echo $view_trash ? 'Deleted files' : 'Your files'; ?>">
        <?php if (empty($rows)): ?>
            <p class="empty"><?php echo $view_trash ? 'Trash is empty. Deleted files appear here so you can restore them.' : 'No files yet. Add your first file above.'; ?></p>
        <?php else: foreach ($rows as $row):
            $name = decrypt_name($row['name_enc'], $master);
            $id = (int) $row['id'];
        ?>
            <div class="file-item">
                <?php if (!$view_trash): ?>
                    <a href="?download=<?php echo $id; ?>" class="file-open" aria-label="Download <?php echo h($name); ?>">
                        <span class="file-badge" aria-hidden="true"><?php echo h(file_badge($name)); ?></span>
                        <span class="file-info">
                            <span class="file-name"><?php echo h($name); ?></span>
                            <span class="file-meta"><?php echo h(format_bytes((int) $row['size'])); ?> · <?php echo h(date('M j, Y', (int) $row['created_at'])); ?></span>
                        </span>
                    </a>
                    <details class="more">
                        <summary aria-label="More actions for <?php echo h($name); ?>"><svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true"><circle cx="4" cy="10" r="1.8" fill="currentColor"/><circle cx="10" cy="10" r="1.8" fill="currentColor"/><circle cx="16" cy="10" r="1.8" fill="currentColor"/></svg></summary>
                        <div class="more-menu">
                            <a href="?download=<?php echo $id; ?>" class="more-item">Download</a>
                            <form method="POST">
                                <input type="hidden" name="csrf" value="<?php echo $csrf; ?>">
                                <input type="hidden" name="action" value="delete">
                                <input type="hidden" name="file" value="<?php echo $id; ?>">
                                <button type="submit" class="more-item btn-danger">Delete</button>
                            </form>
                        </div>
                    </details>
                <?php else: ?>
                    <span class="file-badge" aria-hidden="true"><?php echo h(file_badge($name)); ?></span>
                    <div class="file-info">
                        <span class="file-name"><?php echo h($name); ?></span>
                        <span class="file-meta"><?php echo h(format_bytes((int) $row['size'])); ?> · Still counts toward your storage</span>
                    </div>
                    <div class="actions">
                        <form method="POST">
                            <input type="hidden" name="csrf" value="<?php echo $csrf; ?>">
                            <input type="hidden" name="action" value="restore">
                            <input type="hidden" name="file" value="<?php echo $id; ?>">
                            <button type="submit" class="btn btn-line btn-small res-btn">Restore</button>
                        </form>
                        <form method="POST" class="confirm-form">
                            <input type="hidden" name="csrf" value="<?php echo $csrf; ?>">
                            <input type="hidden" name="action" value="perm_delete">
                            <input type="hidden" name="file" value="<?php echo $id; ?>">
                            <button type="submit" class="btn btn-small btn-danger">Delete forever</button>
                        </form>
                    </div>
                <?php endif; ?>
            </div>
        <?php endforeach; endif; ?>
    </section>
</main>

<?php if ($flash): ?>
<div class="toast" role="status">
    <span><?php echo h($flash['message']); ?></span>
    <?php if (!empty($flash['undo'])): ?>
    <form method="POST">
        <input type="hidden" name="csrf" value="<?php echo $csrf; ?>">
        <input type="hidden" name="action" value="restore">
        <input type="hidden" name="file" value="<?php echo (int) $flash['undo']; ?>">
        <button type="submit">Undo</button>
    </form>
    <?php endif; ?>
</div>
<?php endif; ?>

</body>
</html>
