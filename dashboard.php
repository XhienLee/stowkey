<?php
require __DIR__ . '/lib.php';
start_session();

if (empty($_SESSION['uid']) || empty($_SESSION['master'])) {
    header('Location: login.php');
    exit();
}

$user_id = (int) $_SESSION['uid'];
$master = base64_decode($_SESSION['master']);
$dir = user_dir($user_id);

function find_file(int $user_id, mixed $id, int $in_trash): ?array {
    if (!is_scalar($id) || !ctype_digit((string) $id)) return null;
    $stmt = db()->prepare('SELECT * FROM files WHERE id = ? AND user_id = ? AND in_trash = ?');
    $stmt->execute([(int) $id, $user_id, $in_trash]);
    return $stmt->fetch() ?: null;
}

function upload_response(array $errors): never {
    http_response_code($errors ? 400 : 200);
    header('Content-Type: text/plain; charset=utf-8');
    echo $errors ? implode("\n", $errors) : 'ok';
    exit();
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
        upload_response(['Upload is larger than the server allows.']);
    }
    if (!csrf_valid()) {
        http_response_code(403);
        exit('Your session expired. Reload the page and try again.');
    }

    $action = $_POST['action'] ?? '';

    if ($action === 'upload') {
        $files = $_FILES['file_upload'] ?? null;
        if (!$files || !is_array($files['name'])) upload_response(['No files received.']);

        $errors = [];
        $taken = active_names($user_id, $master);
        foreach ($files['name'] as $i => $raw_name) {
            $name = clean_name((string) $raw_name);
            $tmp = $files['tmp_name'][$i];
            if ($files['error'][$i] !== UPLOAD_ERR_OK || !is_uploaded_file($tmp)) {
                $errors[] = "$name: " . upload_error((int) $files['error'][$i]);
                continue;
            }
            $free = disk_free_space($dir);
            if ($free === false || $free - 2 * $files['size'][$i] < VAULT_MIN_FREE_BYTES) {
                $errors[] = "$name: server storage is full";
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
                if ((int) $used->fetchColumn() + $stored_size > VAULT_QUOTA_BYTES) {
                    db()->exec('ROLLBACK');
                    @unlink($target);
                    $errors[] = "$name: storage quota exceeded";
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
            } catch (Throwable $e) {
                if (db()->inTransaction()) db()->exec('ROLLBACK');
                @unlink($target);
                error_log('vault: upload failed: ' . $e->getMessage());
                $errors[] = "$name: could not be saved";
            }
        }
        upload_response($errors);
    }

    if ($action === 'dismiss_key') {
        unset($_SESSION['new_key']);
    } elseif ($action === 'delete' && ($row = find_file($user_id, $_POST['file'] ?? null, 0))) {
        db()->prepare('UPDATE files SET in_trash = 1 WHERE id = ?')->execute([$row['id']]);
    } elseif ($action === 'restore' && ($row = find_file($user_id, $_POST['file'] ?? null, 1))) {
        $name = unique_name(decrypt_name($row['name_enc'], $master), active_names($user_id, $master));
        $stmt = db()->prepare('UPDATE files SET in_trash = 0, name_enc = :name WHERE id = :id');
        $stmt->bindValue(':name', encrypt_name($name, $master), PDO::PARAM_LOB);
        $stmt->bindValue(':id', (int) $row['id'], PDO::PARAM_INT);
        $stmt->execute();
    } elseif ($action === 'perm_delete' && ($row = find_file($user_id, $_POST['file'] ?? null, 1))) {
        db()->prepare('DELETE FROM files WHERE id = ?')->execute([$row['id']]);
        @unlink("$dir/{$row['stored_name']}");
    }

    $back = ($action === 'perm_delete' || ($_POST['view'] ?? '') === 'trash') ? '?view=trash' : '';
    header("Location: dashboard.php$back");
    exit();
}

$view_trash = ($_GET['view'] ?? '') === 'trash';
$rows = file_rows($user_id, $view_trash);
$csrf = h(csrf_token());
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f4f4f9; display: flex; justify-content: center; padding: 20px; }
        .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 600px; }
        .file-list { margin-top: 20px; border-top: 1px solid #eee; padding-top: 10px; }
        .file-item { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; font-family: monospace; font-size: 0.9rem; border-bottom: 1px solid #f9f9f9; }
        .file-info { display: flex; flex-direction: column; }
        .file-meta { font-size: 0.75rem; color: #999; margin-top: 2px; }
        .error { color: red; font-size: 0.8rem; }

        .upload-section { margin-bottom: 20px; }
        input[type="file"] { margin-bottom: 10px; width: 100%; }

        .logout { color: #d9534f; text-decoration: none; font-size: 0.8rem; float: right; margin-left: 15px;}
        .trash-link { color: #555; text-decoration: none; font-size: 0.8rem; float: right; }
        .trash-link:hover { text-decoration: underline; }

        .action-link { margin-left: 10px; text-decoration: none; font-size: 0.85rem; background: none; border: none; padding: 0; cursor: pointer; font-family: inherit; }
        .actions form, .logout-form { display: inline; }
        .logout-form button { background: none; border: none; padding: 0; cursor: pointer; font-family: inherit; }
        .key-banner { background: #fff3cd; color: #664d03; padding: 12px; border-radius: 4px; margin-bottom: 15px; font-size: 0.85rem; }
        .key-banner code { display: block; margin: 8px 0; font-size: 0.95rem; word-break: break-all; }
        .upload-error { color: #d9534f; font-size: 0.8rem; margin-top: 10px; white-space: pre-wrap; }
        .dl-btn { color: #007bff; }
        .del-btn { color: #d9534f; }
        .res-btn { color: #28a745; }

        .btn-upload { background: #28a745; color: white; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; }
        .btn-upload:disabled { background: #94d3a2; cursor: not-allowed; }

        #progress-container { display: none; margin-top: 15px; background: #f1f1f1; padding: 10px; border-radius: 4px; font-size: 0.85rem; }
        .stat-row { display: flex; justify-content: space-between; margin-bottom: 4px; }
        progress { width: 100%; height: 8px; }

        .trash-header { background: #fff3cd; padding: 10px; border-radius: 4px; margin-bottom: 15px; font-size: 0.9rem; color: #856404; display: flex; justify-content: space-between; align-items: center;}
    </style>
</head>
<body>
    <div class="card">
        <div style="margin-bottom: 20px; overflow: hidden;">
            <form method="POST" action="logout.php" class="logout-form">
                <input type="hidden" name="csrf" value="<?php echo $csrf; ?>">
                <button type="submit" class="logout">Logout</button>
            </form>
            <?php if(!$view_trash): ?>
                <a href="?view=trash" class="trash-link">🗑️ View Trash</a>
            <?php else: ?>
                <a href="dashboard.php" class="trash-link">📁 View Files</a>
            <?php endif; ?>
        </div>

        <?php if (!empty($_SESSION['new_key'])): ?>
            <div class="key-banner">
                <strong>Save your access key now.</strong> It is shown only until you dismiss this and cannot be recovered.
                <code><?php echo h($_SESSION['new_key']); ?></code>
                <form method="POST">
                    <input type="hidden" name="csrf" value="<?php echo $csrf; ?>">
                    <input type="hidden" name="action" value="dismiss_key">
                    <input type="hidden" name="view" value="<?php echo $view_trash ? 'trash' : ''; ?>">
                    <button type="submit" onclick="return confirm('Have you saved your key? It cannot be shown again.')">I saved it</button>
                </form>
            </div>
        <?php endif; ?>

        <h3><?php echo $view_trash ? 'Trash Bin' : 'Repository'; ?></h3>

        <?php if(!$view_trash): ?>
        <div class="upload-section">
            <form id="uploadForm">
                <input type="hidden" id="csrfToken" value="<?php echo $csrf; ?>">
                <input type="file" name="file_upload[]" id="fileInput" multiple required><br>
                <p style="font-size: 0.8rem; color: #666;">Every file is encrypted automatically.</p>
                <button type="submit" id="uploadBtn" class="btn-upload">Upload Files</button>
            </form>

            <div id="progress-container">
                <div class="stat-row">
                    <span id="stat-status">Uploading...</span>
                    <span id="stat-percent">0%</span>
                </div>
                <progress id="progressBar" value="0" max="100"></progress>
                <div class="stat-row" style="color: #666; font-size: 0.75rem; margin-top: 5px;">
                    <span id="stat-size">0 / 0 MB</span>
                    <span id="stat-speed">0 Mbps</span>
                </div>
            </div>
            <div id="upload-error" class="upload-error"></div>
        </div>
        <?php else: ?>
            <div class="trash-header">
                <span>Items in trash are hidden from your main list.</span>
            </div>
        <?php endif; ?>

        <div class="file-list">
            <strong><?php echo $view_trash ? 'Deleted Items:' : 'Files:'; ?></strong>
            <?php if (empty($rows)): ?>
                <p style="color: #999;">No files found.</p>
            <?php else:
                foreach ($rows as $row):
                    $name = decrypt_name($row['name_enc'], $master);
                    $id = (int) $row['id'];
            ?>
                <div class="file-item">
                    <div class="file-info">
                        <span><?php echo h($name); ?></span>
                        <span class="file-meta"><?php echo h(date('F j, Y, g:i a', (int) $row['created_at'])); ?></span>
                    </div>

                    <div class="actions">
                        <?php if (!$view_trash): ?>
                            <a href="?download=<?php echo $id; ?>" class="action-link dl-btn">Download</a>
                            <form method="POST" onsubmit="return confirm('Move to trash?')">
                                <input type="hidden" name="csrf" value="<?php echo $csrf; ?>">
                                <input type="hidden" name="action" value="delete">
                                <input type="hidden" name="file" value="<?php echo $id; ?>">
                                <button type="submit" class="action-link del-btn">Delete</button>
                            </form>
                        <?php else: ?>
                            <form method="POST">
                                <input type="hidden" name="csrf" value="<?php echo $csrf; ?>">
                                <input type="hidden" name="action" value="restore">
                                <input type="hidden" name="file" value="<?php echo $id; ?>">
                                <button type="submit" class="action-link res-btn">Restore</button>
                            </form>
                            <form method="POST" onsubmit="return confirm('Permanently delete? This cannot be undone.')">
                                <input type="hidden" name="csrf" value="<?php echo $csrf; ?>">
                                <input type="hidden" name="action" value="perm_delete">
                                <input type="hidden" name="file" value="<?php echo $id; ?>">
                                <button type="submit" class="action-link del-btn">Delete Forever</button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; endif; ?>
        </div>
    </div>

    <script>

        const form = document.getElementById('uploadForm');
        if(form){
            const fileInput = document.getElementById('fileInput');
            const uploadError = document.getElementById('upload-error');
            const uploadBtn = document.getElementById('uploadBtn');
            const progressContainer = document.getElementById('progress-container');
            const progressBar = document.getElementById('progressBar');
            const statPercent = document.getElementById('stat-percent');
            const statSize = document.getElementById('stat-size');
            const statSpeed = document.getElementById('stat-speed');

            function formatBytes(bytes) {
                if (bytes === 0) return '0 B';
                const k = 1024;
                const sizes = ['B', 'KB', 'MB', 'GB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }

            form.addEventListener('submit', function(e) {
                e.preventDefault();
                if(fileInput.files.length === 0) return;

                const formData = new FormData();
                for (let i = 0; i < fileInput.files.length; i++) {
                    formData.append('file_upload[]', fileInput.files[i]);
                }
                formData.append('csrf', document.getElementById('csrfToken').value);
                formData.append('action', 'upload');
                uploadError.textContent = '';

                const xhr = new XMLHttpRequest();
                const startTime = new Date().getTime();

                xhr.open('POST', '', true);
                xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

                xhr.upload.onprogress = function(e) {
                    if (e.lengthComputable) {
                        const percentComplete = (e.loaded / e.total) * 100;
                        const duration = (new Date().getTime() - startTime) / 1000;
                        const mbps = ((e.loaded / duration) * 8) / (1000 * 1000);

                        progressContainer.style.display = 'block';
                        progressBar.value = percentComplete;
                        statPercent.innerText = Math.round(percentComplete) + '%';
                        statSize.innerText = formatBytes(e.loaded) + ' / ' + formatBytes(e.total);
                        statSpeed.innerText = mbps.toFixed(2) + ' Mbps';
                    }
                };

                xhr.onload = function() {
                    if (xhr.status === 200) {
                        window.location.reload();
                    } else {
                        uploadError.textContent = xhr.responseText || 'Upload failed.';
                        uploadBtn.disabled = false;
                    }
                };
                xhr.onerror = function() {
                    uploadError.textContent = 'Network error. Upload failed.';
                    uploadBtn.disabled = false;
                };
                uploadBtn.disabled = true;
                xhr.send(formData);
            });
        }
    </script>
</body>
</html>
