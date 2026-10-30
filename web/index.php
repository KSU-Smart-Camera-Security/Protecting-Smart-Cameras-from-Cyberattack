<?php
date_default_timezone_set('Asia/Riyadh');

// Safer session cookies (must be set before session_start)
session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Strict',
    'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
]);
session_start();

$config = require __DIR__ . '/config.php';

// =========================
// HTTP Access Detection
// =========================
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {

    if (!isset($_SESSION['http_alert_sent'])) {

        $to = $config['alert_email'];
        $subject = "⚠️ HTTP Connection Detected";

        $message = "
Warning!

An insecure HTTP connection was detected.

IP Address: " . $_SERVER['REMOTE_ADDR'] . "
Time: " . date("Y-m-d H:i:s") . "

The user accessed the system without HTTPS encryption.
";

        $headers = "From: Raspberry Camera <security@picam.local>";

        mail($to, $subject, $message, $headers);
        file_put_contents($config['event_log'], date("Y-m-d H:i:s") . " | HTTP Connection Detected | IP: " . $_SERVER['REMOTE_ADDR'] . "\n", FILE_APPEND);
        $_SESSION['http_alert_sent'] = true;
    }
}

$db_path = $config['db_path'];
$db = new PDO("sqlite:$db_path");
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$check_global = $db->query("SELECT brute_force_enabled FROM users WHERE username = 'admin'")->fetch();
$global_protection = $check_global['brute_force_enabled'] ?? 0;

if (!isset($_SESSION['attempts'])) { $_SESSION['attempts'] = 0; }
if (!isset($_SESSION['lockout_time'])) { $_SESSION['lockout_time'] = 0; }
if (!isset($_SESSION['mfa_step'])) { $_SESSION['mfa_step'] = false; }

$msg = "";

// MFA limits
const MFA_CODE_LIFETIME = 300; // seconds (5 minutes)
const MFA_MAX_TRIES     = 5;

function mfa_reset() {
    unset($_SESSION['mfa_code'], $_SESSION['mfa_user'], $_SESSION['mfa_time'], $_SESSION['mfa_attempts']);
    $_SESSION['mfa_step'] = false;
}

$camera_url = "http://" . rawurlencode($config['camera_user']) . ":" . rawurlencode($config['camera_pass'])
    . "@" . $config['camera_ip'] . ":" . $config['camera_port'] . "/cam";

// =========================
// Login
// =========================
if (isset($_POST['login'])) {
    $current_time = time();
    if ($global_protection && $current_time < $_SESSION['lockout_time']) {
        $remaining = $_SESSION['lockout_time'] - $current_time;
        $msg = "⛔ Too many failed attempts. Try again after $remaining seconds.";
    } else {
        $username_input = (string)($_POST['username'] ?? '');
        $password_input = (string)($_POST['password'] ?? '');
        $stmt = $db->prepare("SELECT * FROM users WHERE username = :user");
        $stmt->execute([':user' => $username_input]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $stored = (string)$user['password'];
            if (strncmp($stored, '$2y$', 4) === 0) {
                $valid = password_verify($password_input, $stored);
            } else {
                // Legacy plaintext value: accept once, then upgrade it to a hash.
                $valid = hash_equals($stored, $password_input);
                if ($valid) {
                    $db->prepare("UPDATE users SET password = :p WHERE id = :id")
                       ->execute([':p' => password_hash($password_input, PASSWORD_DEFAULT), ':id' => $user['id']]);
                }
            }
            if (!$valid) { $user = false; }
        }

        if ($user) {
            $_SESSION['attempts'] = 0;

            if ($user['mfa_enabled'] == 1) {
                $_SESSION['mfa_user']     = $user['username'];
                $_SESSION['mfa_code']     = random_int(100000, 999999);
                $_SESSION['mfa_time']     = time();
                $_SESSION['mfa_attempts'] = 0;
                $_SESSION['mfa_step']     = true;
                mail($user['email'], "Security Verification Code", "Your code is: " . $_SESSION['mfa_code'] . "\nIt expires in 5 minutes.");
            } else {
                session_regenerate_id(true);
                $_SESSION['user'] = $user['username'];
            }
        } else {
            $msg = "Invalid username or password";
            if ($global_protection) {
                $_SESSION['attempts']++;

                if ($_SESSION['attempts'] >= 5) {

                    $_SESSION['lockout_time'] = time() + 30;

                    $to = $config['alert_email'];
                    $subject = "🚨 Brute Force Attack Detected";

                    $message = "
Warning!

Multiple failed login attempts detected.

IP Address: " . $_SERVER['REMOTE_ADDR'] . "
Attempts: " . $_SESSION['attempts'] . "
Time: " . date("Y-m-d H:i:s") . "

The system temporarily locked login access.
";

                    $headers = "From: Raspberry Camera <security@picam.local>";

                    mail($to, $subject, $message, $headers);
                    file_put_contents($config['event_log'], date("Y-m-d H:i:s") . " | Brute Force Attack Detected | Attempts: " . $_SESSION['attempts'] . " | IP: " . $_SERVER['REMOTE_ADDR'] . "\n", FILE_APPEND);
                }
            }
        }
    }
}

// =========================
// MFA verification (5 minutes, 5 tries)
// =========================
if (isset($_POST['verify_mfa'])) {
    $_SESSION['mfa_attempts'] = ($_SESSION['mfa_attempts'] ?? 0) + 1;
    $expired = empty($_SESSION['mfa_time']) || (time() - $_SESSION['mfa_time']) > MFA_CODE_LIFETIME;

    if (empty($_SESSION['mfa_code']) || $expired) {
        mfa_reset();
        $msg = "Verification code expired. Please log in again.";
    } elseif ($_SESSION['mfa_attempts'] > MFA_MAX_TRIES) {
        mfa_reset();
        $msg = "Too many wrong codes. Please log in again.";
    } elseif (hash_equals((string)$_SESSION['mfa_code'], trim((string)($_POST['otp'] ?? '')))) {
        session_regenerate_id(true);
        $_SESSION['user'] = $_SESSION['mfa_user'];
        mfa_reset();
        $_SESSION['attempts'] = 0;
    } else {
        $msg = "Invalid Verification Code";
    }
}

if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header("Location: index.php");
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Live Stream - Dashboard</title>
    <style>
        body { margin: 0; font-family: 'Segoe UI', sans-serif; background-color: #0f1115; color: white; }
        .login-screen { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: #0f1115; z-index: 9999; display: flex; justify-content: center; align-items: center; }
        .box { background: #1a1f29; padding: 40px; border-radius: 15px; border: 2px solid #2c3442; text-align: center; width: 350px; }
        header { background: #1a1f29; padding: 15px 30px; display: flex; align-items: center; border-bottom: 2px solid #2c3442; }
        .nav-group { display: flex; gap: 30px; align-items: center; }
        .nav-icon { font-size: 24px; text-decoration: none; color: #555; transition: 0.3s; }
        .active-icon { color: #7cc7ff; }
        .logout-btn { color: #ff4444; text-decoration: none; font-size: 14px; font-weight: bold; margin-left: auto; border: 1px solid #ff4444; padding: 6px 15px; border-radius: 6px; transition: 0.3s; }
        .logout-btn:hover { background: #ff4444; color: white; }
        .container { max-width: 900px; margin: 30px auto; padding: 0 20px; }
        .card { background: #1a1f29; border: 1px solid #2c3442; border-radius: 12px; padding: 20px; margin-bottom: 20px; }
        .video-feed { width: 100%; height: 480px; background: #000; border-radius: 8px; border: 1px solid #3b4758; overflow: hidden; }
        iframe { width: 100%; height: 100%; border: none; }
        input { width: 100%; padding: 12px; margin: 10px 0; background: #0f1115; color: white; border: 1px solid #2c3442; border-radius: 8px; box-sizing: border-box; }
        .alert-box { background: #2a1616; border: 1px solid #ff4444; color: #ffb3b3; padding: 10px; border-radius: 8px; margin-top: 12px; font-size: 14px; }
    </style>
</head>
<body>
<?php if (!isset($_SESSION['user'])): ?>
    <div class="login-screen">
        <div class="box">
            <?php if ($_SESSION['mfa_step']): ?>
                <h2 style="color:#7cc7ff;">MFA Verification</h2>
                <p style="font-size:13px; color:#93a3b8;">Enter the code sent to your Email</p>
                <form method="POST">
                    <input type="text" name="otp" placeholder="6-Digit Code" required autofocus>
                    <button type="submit" name="verify_mfa" style="width:100%; background:#4cff88; color:black; padding:12px; border:none; border-radius:8px; cursor:pointer; font-weight:bold;">Verify</button>
                </form>
            <?php else: ?>
                <h2 style="color:#7cc7ff;">Admin Login</h2>
                <form method="POST">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit" name="login" style="width:100%; background:#7cc7ff; color:black; padding:12px; border:none; border-radius:8px; cursor:pointer; font-weight:bold;">Login</button>
                </form>
            <?php endif; ?>
            <?php if (!empty($msg)): ?> <div class="alert-box"><?php echo htmlspecialchars($msg); ?></div> <?php endif; ?>
        </div>
    </div>
<?php else: ?>
    <header>
        <div class="nav-group">
            <a href="index.php" class="nav-icon active-icon" title="Live Stream">📹</a>
            <a href="dashboard.php" class="nav-icon" title="Dashboard">📊</a>
            <a href="settings.php" class="nav-icon" title="Settings">⚙️</a>
        </div>
        <a href="?logout=1" class="logout-btn">Logout</a>
    </header>
    <div class="container">
        <div class="card">
            <h3 style="margin-top:0; color:#7cc7ff;">Live Camera Feed</h3>
            <div class="video-feed">
                <iframe src="<?php echo htmlspecialchars($camera_url, ENT_QUOTES); ?>" allowfullscreen></iframe>
            </div>
        </div>
    </div>
<?php endif; ?>
</body>
</html>
