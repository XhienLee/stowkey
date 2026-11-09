<?php
require __DIR__ . '/lib.php';
start_session();
$state = enter_page('index');
page_head('Stowkey: private file storage with one key');
?>
<body>
<header class="hero on-dark">
    <div class="wrap topbar">
        <a href="index.php" class="brand"><?php echo brand_mark(); ?>Stowkey</a>
        <a href="<?php echo SESSION_STATES[$state]['home']; ?>" class="topbar-link">Open my vault</a>
    </div>
    <div class="hero-body">
        <h1>One key.<br>Your private files.</h1>
        <p class="hero-lead">No account. No password. Get a key, add your files, and open them from any browser.</p>
        <div class="hero-key">
            <span class="key-hole" aria-hidden="true"></span>
            <div>
                <small>Example key</small>
                <div class="key-segments"><span>7168ebda</span><span>690b</span><span>4e82</span><span>9f55</span><span>0784d7381697</span></div>
            </div>
        </div>
        <div class="hero-actions">
            <a href="login.php?mode=new" class="btn btn-light">Get your key</a>
            <a href="login.php" class="hero-link">I already have a key</a>
        </div>
    </div>
</header>
<main>
    <section class="wrap section">
        <h2>Three steps</h2>
        <ol class="steps">
            <li><h3>Get your key</h3><p>One click creates a private key just for you.</p></li>
            <li><h3>Save your key</h3><p>Copy it or download it before you continue.</p></li>
            <li><h3>Add your files</h3><p>They are encrypted and ready whenever you need them.</p></li>
        </ol>
    </section>
    <div class="wrap split">
        <section>
            <h2>What you get</h2>
            <ul class="ticks">
                <li>Every file and filename encrypted automatically</li>
                <li><?php echo h(format_bytes(vault_quota())); ?> of storage for each key</li>
                <li>Deleted files wait in Trash until you decide</li>
                <li>Works in any browser, on phone or computer</li>
            </ul>
        </section>
        <section class="note">
            <h2>Keep your key safe</h2>
            <p>Your key can't be reset. If you lose it, your files are gone for good, so keep it in a password manager.</p>
            <p>Stored files and filenames can't be read without your key. The key is used on the server while you're logged in, so only use a host you trust.</p>
        </section>
    </div>
</main>
<footer class="footer">Stowkey</footer>
</body>
</html>
