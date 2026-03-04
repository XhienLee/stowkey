<?php
session_start();
if (@$_SESSION['user_login']) {
    header("Location: dashboard.php");
    exit();
}

$error_msg = "";
$success_msg = "";

function loadKeys($jsonFile) {
    if (!file_exists($jsonFile)) return [];
    $data = json_decode(file_get_contents($jsonFile), true);
    return is_array($data) ? $data : [];
}

function saveKeys($jsonFile, $keys) {
    file_put_contents($jsonFile, json_encode(array_values($keys), JSON_PRETTY_PRINT));
}

$jsonFile = 'keys.json';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action  = $_POST['action'] ?? '';
    $userKey = trim($_POST['key'] ?? '');
    $validUUID4 = preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $userKey);

    if (!$validUUID4) {
        $error_msg = "Invalid UUID4 format.";
    } else {
        $keys = loadKeys($jsonFile);

        if ($action === 'register') {
            // Key must NOT already exist
            if (in_array($userKey, $keys)) {
                $error_msg = "That key is already registered. Use Login instead.";
            } else {
                $keys[] = $userKey;
                saveKeys($jsonFile, $keys);
                $_SESSION['user_login'] = true;
                $_SESSION['key'] = $userKey;
                header("Location: dashboard.php");
                exit();
            }
        } elseif ($action === 'login') {
            // Key MUST already exist
            if (in_array($userKey, $keys)) {
                $_SESSION['user_login'] = true;
                $_SESSION['key'] = $userKey;
                header("Location: dashboard.php");
                exit();
            } else {
                $error_msg = "Key not found. Generate a new key and register it first.";
            }
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

        /* Animated grid background */
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

        /* Corner accent */
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

        /* Tabs */
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

        /* Key generator */
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

        /* Input */
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

        /* Submit */
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

        /* Messages */
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

        /* Panel switching */
        .panel { display: none; }
        .panel.active { display: block; }

        /* Fade in */
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

        <!-- LOGIN PANEL -->
        <div class="panel active" id="panel-login">
            <form method="POST" action="">
                <input type="hidden" name="action" value="login">
                <div class="field">
                    <label>Access Key</label>
                    <input type="text" name="key" placeholder="xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx" required>
                </div>
                <button type="submit" class="submit-btn">Authenticate →</button>
            </form>
            <p class="hint">Don't have a key yet? Switch to <strong>Register</strong> to generate and lock in your key.</p>
        </div>

        <!-- REGISTER PANEL -->
        <div class="panel" id="panel-register">
            <div class="keygen-box" id="keygenBox" onclick="copyKey()">
                <span class="key-text empty" id="keyDisplay">Click "Generate" to create your key</span>
                <button class="copy-btn" id="copyBtn" onclick="event.stopPropagation(); copyKey()">COPY</button>
            </div>
            <button class="gen-btn" type="button" onclick="generateKey()">⟳ Generate New Key</button>

            <form method="POST" action="" id="registerForm">
                <input type="hidden" name="action" value="register">
                <div class="field">
                    <label>Paste Your Key to Register</label>
                    <input type="text" name="key" id="registerKeyInput" placeholder="Paste generated key here" required>
                </div>
                <button type="submit" class="submit-btn">Register &amp; Enter →</button>
            </form>
            <p class="hint">⚠ Save your key somewhere safe — it cannot be recovered. Once registered, only this key unlocks your vault.</p>
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

    let generatedKey = '';

    function generateKey() {
        const display = document.getElementById('keyDisplay');
        display.classList.add('empty');
        display.textContent = 'Generating...';

        fetch('generate.php')
            .then(r => r.json())
            .then(data => {
                if (data.key) {
                    generatedKey = data.key;
                    display.classList.remove('empty');
                    display.textContent = generatedKey;
                    document.getElementById('registerKeyInput').value = generatedKey;
                    document.getElementById('copyBtn').textContent = 'COPY';
                    document.getElementById('copyBtn').classList.remove('copied');
                }
            })
            .catch(() => { display.textContent = 'Error — try again.'; });
    }

    function copyKey() {
        if (!generatedKey) return;
        navigator.clipboard.writeText(generatedKey).then(() => {
            const btn = document.getElementById('copyBtn');
            btn.textContent = 'COPIED!';
            btn.classList.add('copied');
            setTimeout(() => {
                btn.textContent = 'COPY';
                btn.classList.remove('copied');
            }, 2000);
        });
    }
</script>
</body>
</html>