<?php
require __DIR__ . '/lib.php';
start_session();

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !csrf_valid()) {
    header('Location: dashboard.php');
    exit();
}

$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', [
        'expires' => time() - 42000, 'path' => $params['path'], 'domain' => $params['domain'],
        'secure' => $params['secure'], 'httponly' => $params['httponly'], 'samesite' => $params['samesite'],
    ]);
}
session_destroy();
header('Location: login.php');
exit();
