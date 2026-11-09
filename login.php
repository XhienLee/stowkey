<?php
require __DIR__ . '/lib.php';
start_session();

if (!empty($_SESSION['uid'])) {
    header('Location: dashboard.php');
    exit();
}

$error_msg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if (!csrf_valid()) {
        $error_msg = 'Your session expired. Please try again.';
    } elseif ($action === 'register') {

        $accessKey = generate_uuid4();
        $stmt = db()->prepare('INSERT INTO users (key_hash, created_at) VALUES (?, ?)');
        $stmt->execute([key_lookup($accessKey), time()]);
        log_in((int) db()->lastInsertId(), $accessKey);
        $_SESSION['new_key'] = $accessKey;
        header('Location: dashboard.php');
        exit();
    } elseif ($action === 'login') {
        $userKey = trim(is_string($_POST['key'] ?? null) ? $_POST['key'] : '');
        if (!preg_match(VAULT_UUID4, $userKey)) {
            $error_msg = 'Invalid UUID4 format.';
        } else {
            $stmt = db()->prepare('SELECT id FROM users WHERE key_hash = ?');
            $stmt->execute([key_lookup($userKey)]);
            $user = $stmt->fetch();
            if ($user) {
                log_in((int) $user['id'], $userKey);
                header('Location: dashboard.php');
                exit();
            }
            $error_msg = 'Key not found.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vault Access</title>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;600&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        :root {
            --bg: #0a0a0a;
            --surface: #111;
            --border: #222;
            --accent: #c8f060;
            --accent-dim: #8aaa30;
            --text: #e8e8e8;
            --muted: #555;
            --error: #ff5f5f;
            --success: #c8f060;
            --mono: 'IBM Plex Mono', monospace;
            --display: 'Syne', sans-serif;
        }

        body {
            font-family: var(--mono);
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            overflow: hidden;
        }

        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background-image:
                linear-gradient(rgba(200,240,96,0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(200,240,96,0.03) 1px, transparent 1px);
            background-size: 40px 40px;
            pointer-events: none;
            z-index: 0;
        }

        .wrapper {
            position: relative;
            z-index: 1;
            width: 100%;
            max-width: 420px;
        }

        .header {
            margin-bottom: 2.5rem;
        }

        .header .label {
            font-size: 0.65rem;
            letter-spacing: 0.25em;
            color: var(--accent);
            text-transform: uppercase;
            margin-bottom: 0.5rem;
        }

        .header h1 {
            font-family: var(--display);
            font-size: 2.8rem;
            font-weight: 800;
            line-height: 1;
            color: var(--text);
        }

        .header h1 span {
            color: var(--accent);
        }

        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 2px;
            padding: 2rem;
            position: relative;
        }

        .card::before {
            content: '';
            position: absolute;
            top: -1px; left: -1px;
            width: 24px; height: 24px;
            border-top: 2px solid var(--accent);
            border-left: 2px solid var(--accent);
        }
        .card::after {
            content: '';
            position: absolute;
            bottom: -1px; right: -1px;
            width: 24px; height: 24px;
            border-bottom: 2px solid var(--accent);
            border-right: 2px solid var(--accent);
        }

        .tabs {
            display: flex;
            border-bottom: 1px solid var(--border);
            margin-bottom: 1.75rem;
            gap: 0;
        }

        .tab-btn {
            flex: 1;
            background: none;
            border: none;
            color: var(--muted);
            font-family: var(--mono);
            font-size: 0.75rem;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            padding: 0.75rem;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            margin-bottom: -1px;
            transition: color 0.2s, border-color 0.2s;
        }

        .tab-btn.active {
            color: var(--accent);
            border-bottom-color: var(--accent);
        }

        .keygen-box {
            background: #0d0d0d;
            border: 1px solid var(--border);
            border-radius: 2px;
            padding: 0.85rem 1rem;
            font-size: 0.8rem;
            color: var(--muted);
            font-family: var(--mono);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            margin-bottom: 1rem;
            min-height: 48px;
            cursor: pointer;
            transition: border-color 0.2s;
        }

        .keygen-box:hover { border-color: #444; }

        .keygen-box .key-text {
            flex: 1;
            word-break: break-all;
            color: var(--accent);
            font-size: 0.78rem;
            transition: opacity 0.3s;
        }

        .keygen-box .key-text.empty { color: var(--muted); font-style: italic; }

        .copy-btn {
            background: none;
            border: 1px solid var(--border);
            color: var(--muted);
            font-family: var(--mono);
            font-size: 0.65rem;
            letter-spacing: 0.1em;
            padding: 4px 8px;
            cursor: pointer;
            white-space: nowrap;
            transition: all 0.2s;
            border-radius: 2px;
        }

        .copy-btn:hover { border-color: var(--accent); color: var(--accent); }
        .copy-btn.copied { border-color: var(--accent); color: var(--accent); }

        .gen-btn {
            width: 100%;
            background: none;
            border: 1px solid var(--border);
            color: var(--text);
            font-family: var(--mono);
            font-size: 0.75rem;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            padding: 0.7rem;
            cursor: pointer;
            margin-bottom: 1.5rem;
            transition: all 0.2s;
            border-radius: 2px;
        }

        .gen-btn:hover { border-color: var(--accent); color: var(--accent); }

        .field { margin-bottom: 1rem; }

        .field label {
            display: block;
            font-size: 0.65rem;
            letter-spacing: 0.15em;
            text-transform: uppercase;
            color: var(--muted);
            margin-bottom: 0.5rem;
        }

        .field input {
            width: 100%;
            background: #0d0d0d;
            border: 1px solid var(--border);
            color: var(--text);
            font-family: var(--mono);
            font-size: 0.8rem;
            padding: 0.75rem 1rem;
            border-radius: 2px;
            outline: none;
            transition: border-color 0.2s;
        }

        .field input:focus { border-color: var(--accent); }
        .field input::placeholder { color: var(--muted); }

        .submit-btn {
            width: 100%;
            background: var(--accent);
            border: none;
            color: #0a0a0a;
            font-family: var(--mono);
            font-size: 0.8rem;
            font-weight: 600;
            letter-spacing: 0.15em;
            text-transform: uppercase;
            padding: 0.85rem;
            cursor: pointer;
            border-radius: 2px;
            transition: background 0.2s, transform 0.1s;
        }

        .submit-btn:hover { background: #d4f570; }
        .submit-btn:active { transform: scale(0.99); }

        .message {
            font-size: 0.75rem;
            padding: 0.6rem 0.8rem;
            border-radius: 2px;
            margin-bottom: 1rem;
            border-left: 2px solid;
        }

        .message.error { color: var(--error); border-color: var(--error); background: rgba(255,95,95,0.05); }
        .message.success { color: var(--success); border-color: var(--success); background: rgba(200,240,96,0.05); }

        .hint {
            font-size: 0.65rem;
            color: var(--muted);
            margin-top: 1.25rem;
            line-height: 1.6;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
        }

        .panel { display: none; }
        .panel.active { display: block; }

        @keyframes fadeUp {
            from { opacity: 0; transform: translateY(12px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .wrapper { animation: fadeUp 0.4s ease; }
    </style>
</head>
<body>
<div class="wrapper">
    <div class="header">
        <div class="label">// secure file vault</div>
        <h1>VAULT<span>.</span>ACCESS</h1>
    </div>

    <div class="card">
        <?php if ($error_msg): ?>
            <div class="message error"><?php echo htmlspecialchars($error_msg); ?></div>
        <?php endif; ?>

        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('login', this)">Login</button>
            <button class="tab-btn" onclick="switchTab('register', this)">Register</button>
        </div>

        <div class="panel active" id="panel-login">
            <form method="POST" action="">
                <input type="hidden" name="csrf" value="<?php echo h(csrf_token()); ?>">
                <input type="hidden" name="action" value="login">
                <div class="field">
                    <label>Access Key</label>
                    <input type="text" name="key" placeholder="xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx" required>
                </div>
                <button type="submit" class="submit-btn">Authenticate →</button>
            </form>
            <p class="hint">Don't have a key yet? Switch to <strong>Register</strong> to create one.</p>
        </div>

        <div class="panel" id="panel-register">
            <form method="POST" action="">
                <input type="hidden" name="csrf" value="<?php echo h(csrf_token()); ?>">
                <input type="hidden" name="action" value="register">
                <button type="submit" class="submit-btn">Create My Key →</button>
            </form>
            <p class="hint">⚠ Your key is shown once after registering and cannot be recovered. It is the only way to open your vault.</p>
        </div>
    </div>
</div>

<script>
    function switchTab(tab, btn) {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById('panel-' + tab).classList.add('active');
    }
</script>
</body>
</html>