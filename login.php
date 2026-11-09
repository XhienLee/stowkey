<?php
require __DIR__ . '/lib.php';
start_session();

enter_page('login');

$error_msg = '';
$is_new = ($_GET['mode'] ?? '') === 'new';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if (!csrf_valid()) {
        $error_msg = 'Your session expired. Please try again.';
    } elseif ($action === 'register') {

        $accessKey = generate_uuid4();
        $new_id = register_user($accessKey);
        if ($new_id === null) {
            http_response_code(429);
            $is_new = true;
            $error_msg = 'Too many new keys were created recently. Please try again in about an hour.';
        } else {
            log_in($new_id, $accessKey);
            $_SESSION['new_key'] = $accessKey;
            header('Location: key.php');
            exit();
        }
    } elseif ($action === 'login') {
        $userKey = trim(is_string($_POST['key'] ?? null) ? $_POST['key'] : '');
        if (!preg_match(VAULT_UUID4, $userKey)) {
            $error_msg = "That doesn't look like a full key. It should have 36 characters with dashes.";
        } else {
            $stmt = db()->prepare('SELECT id FROM users WHERE key_hash = ?');
            $stmt->execute([key_lookup($userKey)]);
            $user = $stmt->fetch();
            if ($user) {
                log_in((int) $user['id'], $userKey);
                header('Location: dashboard.php');
                exit();
            }
            $error_msg = "We couldn't find a vault with that key. Check it for typos.";
        }
    }
}
$csrf = h(csrf_token());
page_head($is_new ? 'Get your key - Stowkey' : 'Open your vault - Stowkey');
?>
<body>
<div class="center-page">
    <a href="index.php" class="brand">Stowkey</a>
    <main class="panel">
        <nav class="tabs" aria-label="Choose an option">
            <a href="login.php"<?php if (!$is_new) echo ' aria-current="page"'; ?>>I have a key</a>
            <a href="login.php?mode=new"<?php if ($is_new) echo ' aria-current="page"'; ?>>I need a key</a>
        </nav>
        <?php if ($is_new): ?>
            <h1>Get your private key</h1>
            <p class="lead">No email or password. Your key is created in one click.</p>
            <?php if ($error_msg): ?><p class="alert" role="alert"><?php echo h($error_msg); ?></p><?php endif; ?>
            <ul class="ticks">
                <li>Your vault is ready right away</li>
                <li><?php echo h(format_bytes(VAULT_QUOTA_BYTES)); ?> of encrypted storage</li>
                <li>You'll save the key on the next screen</li>
            </ul>
            <form method="POST" action="login.php?mode=new">
                <input type="hidden" name="csrf" value="<?php echo $csrf; ?>">
                <input type="hidden" name="action" value="register">
                <button type="submit" class="btn btn-primary">Create my key</button>
            </form>
        <?php else: ?>
            <h1>Open your vault</h1>
            <p class="lead">Paste the key you saved when you signed up.</p>
            <?php if ($error_msg): ?><p class="alert" role="alert"><?php echo h($error_msg); ?></p><?php endif; ?>
            <form method="POST" action="login.php">
                <input type="hidden" name="csrf" value="<?php echo $csrf; ?>">
                <input type="hidden" name="action" value="login">
                <label class="field-label" for="key">Your key</label>
                <input class="field" id="key" type="text" name="key" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="Paste your key here" required>
                <p class="hint" id="keyHint" aria-live="polite"></p>
                <button type="submit" class="btn btn-primary">Open my vault</button>
            </form>
            <p class="fine">Lost your key? It can't be reset, because it is never stored.</p>
        <?php endif; ?>
    </main>
</div>
</body>
</html>
