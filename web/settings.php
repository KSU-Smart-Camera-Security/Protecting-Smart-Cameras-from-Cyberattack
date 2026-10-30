<?php
session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Strict',
    'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
]);
session_start();
if (!isset($_SESSION['user'])) { header("Location: index.php"); exit; }

$config = require __DIR__ . '/config.php';

// CSRF protection for every state-changing POST request
if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(32)); }
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf']) || !hash_equals($_SESSION['csrf'], (string)$_POST['csrf'])) {
        http_response_code(403);
        exit('Invalid CSRF token');
    }
}

$db_path = $config['db_path'];
$db = new PDO("sqlite:$db_path");
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$stmt = $db->prepare("SELECT * FROM users WHERE username = :user");
$stmt->execute([':user' => $_SESSION['user']]);
$user_data = $stmt->fetch(PDO::FETCH_ASSOC);

$is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');

if (isset($_POST['toggle_mfa'])) {
    $new_val = $user_data['mfa_enabled'] ? 0 : 1;
    $db->prepare("UPDATE users SET mfa_enabled = ? WHERE username = ?")->execute([$new_val, $_SESSION['user']]);
    header("Location: settings.php"); exit;
}

if (isset($_POST['toggle_protection'])) {
    $new_val = $user_data['brute_force_enabled'] ? 0 : 1;
    $db->prepare("UPDATE users SET brute_force_enabled = ? WHERE username = ?")->execute([$new_val, $_SESSION['user']]);
    header("Location: settings.php"); exit;
}

if (isset($_POST['enable_https'])) {
    shell_exec("sudo /home/camera/enable_https.sh");
    header("Location: https://" . $_SERVER['HTTP_HOST'] . "/settings.php"); exit;
}

if (isset($_POST['disable_https'])) {
    shell_exec("sudo /home/camera/disable_https.sh");
    header("Location: http://" . $_SERVER['HTTP_HOST'] . "/settings.php"); exit;
}

if (isset($_POST['enable_rtsp'])) {
    shell_exec("sudo /home/camera/enable_rtsp_protection.sh");
    $db->prepare("UPDATE users SET rtsp_protected = 1 WHERE username = ?")->execute([$_SESSION['user']]);
    header("Location: settings.php"); exit;
}

if (isset($_POST['disable_rtsp'])) {
    shell_exec("sudo /home/camera/disable_rtsp_protection.sh");
    $db->prepare("UPDATE users SET rtsp_protected = 0 WHERE username = ?")->execute([$_SESSION['user']]);
    header("Location: settings.php"); exit;
}

$msg = "";
$msg_ok = false;
if (isset($_POST['reset'])) {
    $old_password = (string)($_POST['old_pass'] ?? '');
    $new_password = (string)($_POST['new_pass'] ?? '');

    // The current password must be correct before it can be changed
    $stored = (string)$user_data['password'];
    $old_ok = (strncmp($stored, '$2y$', 4) === 0)
        ? password_verify($old_password, $stored)
        : hash_equals($stored, $old_password);

    if (!$old_ok) {
        $msg = "Current password is incorrect.";
    } elseif (strlen($new_password) < 8) {
        $msg = "Password must be at least 8 characters.";
    } else {
        $stmt = $db->prepare("UPDATE users SET password = :pass WHERE username = :user");
        if ($stmt->execute([':pass' => password_hash($new_password, PASSWORD_DEFAULT), ':user' => $_SESSION['user']])) {
            $msg = "Password Updated Successfully!";
            $msg_ok = true;
        }
    }
}

if (isset($_GET['logout'])) { session_destroy(); header("Location: index.php"); exit; }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Camera Settings</title>
    <style>
        body { margin: 0; font-family: 'Segoe UI', sans-serif; background-color: #0f1115; color: white; }
        header { background: #1a1f29; padding: 15px 30px; display: flex; align-items: center; border-bottom: 2px solid #2c3442; }
        .nav-group { display: flex; gap: 20px; align-items: center; width: 140px; }
        .nav-icon { font-size: 20px; text-decoration: none; color: #555; transition: 0.3s; }
        .active-icon { color: #fff; }
        .header-center-title { flex-grow: 1; text-align: center; color: #7cc7ff; font-weight: bold; font-size: 18px; letter-spacing: 1px; }
        .logout-btn { color: #ff4444; text-decoration: none; font-size: 13px; font-weight: bold; border: 1px solid #ff4444; padding: 6px 18px; border-radius: 8px; transition: 0.3s; width: 80px; text-align: center; }
        .logout-btn:hover { background: #ff4444; color: white; }
        .container { max-width: 1000px !important; margin: 50px auto; padding: 0 20px; }
        .card { background: #1a1f29; border: 1px solid #2c3442; border-radius: 20px; padding: 35px; text-align: center; box-shadow: 0 10px 40px rgba(0,0,0,0.6); width: 900px !important; max-width: 900px !important; }
        h2 { color: #fff; margin-bottom: 25px; font-size: 22px; font-weight: 500; }
        input { width: 100%; padding: 14px; margin-bottom: 15px; background: #0f1115; color: white; border: 1px solid #2c3442; border-radius: 10px; box-sizing: border-box; }
        .btn-save { width: 100%; padding: 14px; background: #4cff88; color: black; border: none; border-radius: 10px; cursor: pointer; font-weight: bold; font-size: 15px; transition: 0.3s; }
        .btn-save:hover { background: #39e676; }
        .device-info { margin-top: 35px; border-top: 1px solid #232b38; padding-top: 20px; text-align: left; }
        .info-title { color: #7cc7ff; font-size: 14px; margin-bottom: 15px; font-weight: bold; text-align: center; }
        .info-row { display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 13px; color: #93a3b8; }
        .info-val { color: #4cff88; }
        .toggle-switch { width: 58px; height: 30px; border-radius: 30px; border: none; cursor: pointer; background: #2c3442; position: relative; transition: 0.3s; }
        .toggle-switch::before { content: ""; position: absolute; width: 24px; height: 24px; background: white; border-radius: 50%; top: 3px; left: 4px; transition: 0.3s; }
        .toggle-on { background: #3b82f6; }
        .toggle-on::before { left: 30px; }
        .security-name { font-size: 16px !important; font-weight: 600; color: white; white-space: normal !important; }
        .security-desc { font-size: 12px !important; color: #7f8ea3; margin-top: 2px; line-height: 1.3; white-space: normal !important; }
        .security-card { margin-top: 30px; background: #101722; border: 1px solid #2c3442; border-radius: 18px; padding: 28px; width: 820px !important; max-width: 820px !important; margin: 30px auto !important; text-align: left !important; }
        .security-table { border: 1px solid #2c3442; border-radius: 14px; overflow: hidden; width: 100% !important; }
        .security-head, .security-row { display: grid !important; grid-template-columns: 1.8fr 0.8fr 0.7fr !important; align-items: center !important; column-gap: 30px !important; padding: 18px 22px; text-align: left !important; }
        .security-head { color: #93a3b8; font-weight: bold; font-size: 14px; background: #121a26; }
        .security-head div:nth-child(2), .security-head div:nth-child(3) { text-align: center; }
        .security-row { border-top: 1px solid #2c3442; }
        .security-row > div:nth-child(2), .security-row > div:nth-child(3) { display: flex !important; justify-content: center !important; align-items: center !important; }
        .status-pill { width: fit-content; padding: 5px 10px !important; border-radius: 9px; font-size: 12px !important; font-weight: bold; min-width: 90px !important; text-align: center !important; margin: 0 auto; }
        .status-on { background: rgba(76,255,136,0.10); color: #4cff88; border: 1px solid #44cc66; }
        .status-off { background: rgba(255,68,68,0.10); color: #ff6666; border: 1px solid #ff4444; }
        .toggle-switch { transform: scale(0.9) !important; }
        .security-row form { margin: 0; }
    </style>
</head>
<body>
    <header>
        <div class="nav-group">
            <a href="index.php" class="nav-icon" title="Live Stream">📹</a>
            <a href="dashboard.php" class="nav-icon" title="Dashboard">📊</a>
            <a href="settings.php" class="nav-icon active-icon" title="Settings">⚙️</a>
        </div>
        <div class="header-center-title">CAMERA SETTINGS</div>
        <a href="?logout=1" class="logout-btn">Logout</a>
    </header>

    <div class="container">
        <div class="card">
            <h2>Change Password</h2>
            <form method="POST">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf']); ?>">
                <input type="password" name="old_pass" placeholder="Current Password" required>
                <input type="password" name="new_pass" placeholder="New Admin Password (min 8 characters)" required>
                <button type="submit" name="reset" class="btn-save">Save Changes</button>
            </form>
            
            <?php if($msg): ?>
                <p style="color:<?php echo $msg_ok ? '#4cff88' : '#ff6666'; ?>; margin-top:15px; font-size:13px;"><?php echo htmlspecialchars($msg); ?></p>
            <?php endif; ?>

            <div class="security-card">
                <div style="margin-bottom:25px;">
                    <div style="font-size:28px; font-weight:bold; color:#7cc7ff;">🛡️ Protection Settings</div>
                    <div style="color:#93a3b8; margin-top:6px; font-size:14px;">Manage system protection and security features</div>
                </div>

                <div class="security-table">
                    <div class="security-head">
                        <div>Feature</div>
                        <div>Status</div>
                        <div>Action</div>
                    </div>

                    <div class="security-row">
                        <div>
                            <div class="security-name">🛡️ Protection (Brute Force)</div>
                            <div class="security-desc">Block suspicious login attempts</div>
                        </div>
                        <div>
                            <span class="status-pill <?php echo $user_data['brute_force_enabled'] ? 'status-on' : 'status-off'; ?>">
                                <?php echo $user_data['brute_force_enabled'] ? '● Enabled' : '● Disabled'; ?>
                            </span>
                        </div>
                        <div>
                            <form method="POST">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf']); ?>">
                                <button type="submit" name="toggle_protection" class="toggle-switch <?php echo $user_data['brute_force_enabled'] ? 'toggle-on' : ''; ?>"></button>
                            </form>
                        </div>
                    </div>

                    <div class="security-row">
                        <div>
                            <div class="security-name">🔒 Protection (HTTPS)</div>
                            <div class="security-desc">Secure connection SSL/TLS</div>
                        </div>
                        <div>
                            <span class="status-pill <?php echo $is_https ? 'status-on' : 'status-off'; ?>">
                                <?php echo $is_https ? '● Enabled' : '● Disabled'; ?>
                            </span>
                        </div>
                        <div>
                            <form method="POST">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf']); ?>">
                                <button type="submit" name="<?php echo $is_https ? 'disable_https' : 'enable_https'; ?>" class="toggle-switch <?php echo $is_https ? 'toggle-on' : ''; ?>"></button>
                            </form>
                        </div>
                    </div>

                    <div class="security-row">
                        <div>
                            <div class="security-name">📹 Protection (RTSP)</div>
                            <div class="security-desc">Protect RTSP stream access</div>
                        </div>
                        <div>
                            <span class="status-pill <?php echo $user_data['rtsp_protected'] ? 'status-on' : 'status-off'; ?>">
                                <?php echo $user_data['rtsp_protected'] ? '● Enabled' : '● Disabled'; ?>
                            </span>
                        </div>
                        <div>
                            <form method="POST">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf']); ?>">
                                <button type="submit" name="<?php echo $user_data['rtsp_protected'] ? 'disable_rtsp' : 'enable_rtsp'; ?>" class="toggle-switch <?php echo $user_data['rtsp_protected'] ? 'toggle-on' : ''; ?>"></button>
                            </form>
                        </div>
                    </div>

                    <div class="security-row">
                        <div>
                            <div class="security-name">📧 Protection (MFA)</div>
                            <div class="security-desc">Two-step verification via email code</div>
                        </div>
                        <div>
                            <span class="status-pill <?php echo $user_data['mfa_enabled'] ? 'status-on' : 'status-off'; ?>">
                                <?php echo $user_data['mfa_enabled'] ? '● Enabled' : '● Disabled'; ?>
                            </span>
                        </div>
                        <div>
                            <form method="POST">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf']); ?>">
                                <button type="submit" name="toggle_mfa" class="toggle-switch <?php echo $user_data['mfa_enabled'] ? 'toggle-on' : ''; ?>"></button>
                            </form>
                        </div>
                    </div>

                </div>
            </div>

            <div class="device-info">
                <div class="info-title">DEVICE INFORMATION</div>
                <div class="info-row"><span>Model:</span> <span class="info-val">5MP Raspberry Pi Camera</span></div>
                <div class="info-row"><span>System IP:</span> <span class="info-val"><?php echo htmlspecialchars($config['camera_ip']); ?></span></div>
            </div>
        </div>
    </div>
</body>
</html>
