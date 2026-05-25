<?php
if (session_status() === PHP_SESSION_NONE) { session_start(); }

if (isset($_GET['logout'])) {
    $_SESSION = array();
    setcookie(session_name(), false, time() - 3600);
    session_destroy();
    session_unset();
    $date = $_GET['date'] ?? 'rt_1';
    header('Location: /realtime/?date=' . ($date === 'rt_2' ? 'rt_2' : 'rt_1'));
    exit;
}

$_SESSION['timestamp']=time();

$autologout = 900; // 15 minutes of inactivity
$lastactive = $_SESSION['timestamp'] ?? 0;

if (time() - $lastactive > $autologout) {
    $_SESSION = array();
    setcookie(session_name(), false, time() - 3600);
    session_destroy();
    session_unset();
    header('Location: /realtime/?date=rt_1');
    exit;
} else {
    $_SESSION['timestamp'] = time();
}
