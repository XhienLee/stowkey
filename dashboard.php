<?php
session_start();
if (!isset($_SESSION['user_login'])) {
    header("Location: index.php");
    exit();
}

$user_key = $_SESSION['key'];
$base_dir = "repo/$user_key";
$trash_dir = "$base_dir/.trash";
$error_msg = "";

// 1. Ensure Directories Exist
if (!file_exists($base_dir)) {
    mkdir($base_dir, 0777, true);
}
if (!file_exists($trash_dir)) {
    mkdir($trash_dir, 0777, true);
}

// 2. Encryption/Decryption Helpers
function encrypt_content($data, $key) {
    $cipher = "aes-256-cbc";
    $iv_len = openssl_cipher_iv_length($cipher);
    $iv = openssl_random_pseudo_bytes($iv_len);
    $encrypted = openssl_encrypt($data, $cipher, substr(hash('sha256', $key), 0, 32), 0, $iv);
    return "::SECURE::" . $iv . $encrypted;
}

function decrypt_content($data, $key) {
    $cipher = "aes-256-cbc";
    $iv_len = openssl_cipher_iv_length($cipher);
    $data = substr($data, 10); 
    $iv = substr($data, 0, $iv_len);
    $encrypted = substr($data, $iv_len);
    return openssl_decrypt($encrypted, $cipher, substr(hash('sha256', $key), 0, 32), 0, $iv);
}

// 3. Handle File Actions (Delete, Restore, Permanent Delete)
if (isset($_GET['action']) && isset($_GET['file'])) {
    $file = basename($_GET['file']); // Security
    
    if ($_GET['action'] === 'delete') {
        // Soft Delete: Move to trash
        rename("$base_dir/$file", "$trash_dir/$file");
    } elseif ($_GET['action'] === 'restore') {
        // Restore: Move back to main
        rename("$trash_dir/$file", "$base_dir/$file");
    } elseif ($_GET['action'] === 'perm_delete') {
        // Permanent: Unlink
        unlink("$trash_dir/$file");
    }
    
    // Redirect to clear query params
    $redirect_tab = ($_GET['action'] === 'delete') ? '' : '?view=trash';
    if ($_GET['action'] === 'restore') $redirect_tab = '';
    
    header("Location: dashboard.php$redirect_tab");
    exit();
}

// 4. Download Handler
if (isset($_GET['download'])) {
    $file = basename($_GET['download']);
    $filepath = $base_dir . "/" . $file;
    if (file_exists($filepath)) {
        $content = file_get_contents($filepath);
        if (substr($content, 0, 10) === "::SECURE::") {
            $content = decrypt_content($content, $user_key);
        }
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.$file.'"');
        header('Content-Length: ' . strlen($content));
        echo $content;
        exit;
    }
}

// 5. Upload Handler
if (isset($_FILES['file_upload'])) {
    $files = $_FILES['file_upload'];
    $count = is_array($files['name']) ? count($files['name']) : 1;

    for ($i = 0; $i < $count; $i++) {
        $name = is_array($files['name']) ? $files['name'][$i] : $files['name'];
        $tmp_name = is_array($files['tmp_name']) ? $files['tmp_name'][$i] : $files['tmp_name'];
        
        if (empty($name)) continue;

        $extension = pathinfo($name, PATHINFO_EXTENSION);
        $name_part = pathinfo($name, PATHINFO_FILENAME);
        $new_name = $name;
        $counter = 1;
        while(file_exists($base_dir . "/" . $new_name)){
            $new_name = $name_part . " (" . $counter . ")." . $extension;
            $counter++;
        }

        $target_file = $base_dir . "/" . $new_name;
        $file_content = file_get_contents($tmp_name);

        if (isset($_POST['encrypt']) && $_POST['encrypt'] === 'true') {
            $final_content = encrypt_content($file_content, $user_key);
            file_put_contents($target_file, $final_content);
        } else {
            move_uploaded_file($tmp_name, $target_file);
        }
    }

    if(!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
        echo "ok";
        exit;
    }
    header("Location: dashboard.php");
    exit();
}

// Determine View Mode
$view_trash = (isset($_GET['view']) && $_GET['view'] === 'trash');
$current_dir = $view_trash ? $trash_dir : $base_dir;
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
        
        /* Links & Buttons */
        .logout { color: #d9534f; text-decoration: none; font-size: 0.8rem; float: right; margin-left: 15px;}
        .trash-link { color: #555; text-decoration: none; font-size: 0.8rem; float: right; }
        .trash-link:hover { text-decoration: underline; }
        
        .action-link { margin-left: 10px; text-decoration: none; font-size: 0.85rem; }
        .dl-btn { color: #007bff; }
        .del-btn { color: #d9534f; } /* Red for delete */
        .res-btn { color: #28a745; } /* Green for restore */
        
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
            <a href="logout.php" class="logout">Logout</a>
            <?php if(!$view_trash): ?>
                <a href="?view=trash" class="trash-link">🗑️ View Trash</a>
            <?php else: ?>
                <a href="dashboard.php" class="trash-link">📁 View Files</a>
            <?php endif; ?>
        </div>

        <h3><?php echo $view_trash ? 'Trash Bin' : 'Repository'; ?></h3>
        
        <?php if(!$view_trash): ?>
        <div class="upload-section">
            <form id="uploadForm">
                <input type="file" name="file_upload[]" id="fileInput" multiple required><br>
                <label style="font-size: 0.9rem;">
                    <input type="checkbox" id="encryptCheck"> Encrypt with AES-256
                </label><br><br>
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
        </div>
        <?php else: ?>
            <div class="trash-header">
                <span>Items in trash are hidden from your main list.</span>
            </div>
        <?php endif; ?>

        <div class="file-list">
            <strong><?php echo $view_trash ? 'Deleted Items:' : 'Files:'; ?></strong>
            <?php
            // Filter out . and .. and .trash folder itself
            $files = array_diff(scandir($current_dir), array('..', '.', '.trash'));
            
            if (empty($files)): ?>
                <p style="color: #999;">No files found.</p>
            <?php else: 
                foreach ($files as $file): 
                    $filepath = $current_dir.'/'.$file;
                    $mod_date = date("F j, Y, g:i a", filemtime($filepath));
                    
                    $is_encrypted = false;
                    $first_bytes = file_get_contents($filepath, false, null, 0, 10);
                    if ($first_bytes === "::SECURE::") $is_encrypted = true;
            ?>
                <div class="file-item">
                    <div class="file-info">
                        <span>
                            <?php echo htmlspecialchars($file); ?>
                            <?php if($is_encrypted) echo '<span style="color:orange; font-size:0.7em;">(🔒)</span>'; ?>
                        </span>
                        <span class="file-meta"><?php echo $mod_date; ?></span>
                    </div>
                    
                    <div class="actions">
                        <?php if(!$view_trash): ?>
                            <a href="?download=<?php echo urlencode($file); ?>" class="action-link dl-btn">Download</a>
                            <a href="?action=delete&file=<?php echo urlencode($file); ?>" class="action-link del-btn" onclick="return confirm('Move to trash?')">Delete</a>
                        <?php else: ?>
                            <a href="?action=restore&file=<?php echo urlencode($file); ?>" class="action-link res-btn">Restore</a>
                            <a href="?action=perm_delete&file=<?php echo urlencode($file); ?>" class="action-link del-btn" onclick="return confirm('Permanently delete? This cannot be undone.')">Delete Forever</a>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; endif; ?>
        </div>
    </div>

    <script>
        // Only run upload script if form exists (not in trash view)
        const form = document.getElementById('uploadForm');
        if(form){
            const fileInput = document.getElementById('fileInput');
            const encryptCheck = document.getElementById('encryptCheck');
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
                if(encryptCheck.checked) formData.append('encrypt', 'true');

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
                        alert('Upload failed');
                        uploadBtn.disabled = false;
                    }
                };
                uploadBtn.disabled = true;
                xhr.send(formData);
            });
        }
    </script>
</body>
</html>