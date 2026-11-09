<?php
require __DIR__ . '/lib.php';
start_session();

enter_page('key');

$error_msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_valid()) {
        $error_msg = 'Your session expired. Please try again.';
    } elseif (($_POST['saved'] ?? '') !== '1') {
        $error_msg = 'Please confirm that you saved your key.';
    } else {
        unset($_SESSION['new_key']);
        header('Location: dashboard.php');
        exit();
    }
}

$key = $_SESSION['new_key'];
page_head('Save your key - Stowkey');
?>
<body>
<div class="center-page">
    <span class="brand"><?php echo brand_mark(); ?>Stowkey</span>
    <main class="panel panel-wide">
        <p class="eyebrow">Your vault is ready</p>
        <h1>Save your key before you continue</h1>
        <p class="lead">This key is the only way to open your vault. It can't be reset if you lose it.</p>
        <?php if ($error_msg): ?><p class="alert" role="alert"><?php echo h($error_msg); ?></p><?php endif; ?>
        <?php key_tag($key); ?>
        <div class="key-actions">
            <button type="button" class="btn btn-line" id="copyKey" data-key="<?php echo h($key); ?>">Copy key</button>
            <button type="button" class="btn btn-line" id="downloadKey">Download as a file</button>
        </div>
        <form method="POST">
            <input type="hidden" name="csrf" value="<?php echo h(csrf_token()); ?>">
            <label class="check"><input type="checkbox" name="saved" value="1" id="savedCheck"> I saved my key somewhere safe</label>
            <button type="submit" class="btn btn-primary" id="continueBtn" disabled>Continue to my vault</button>
        </form>
    </main>
</div>
</body>
</html>
