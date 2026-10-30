<?php

session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Strict',
    'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
]);
session_start();
if (!isset($_SESSION['user'])) { header("Location: index.php"); exit; }

$config = require __DIR__ . '/config.php';

date_default_timezone_set('Asia/Riyadh');

/* DATABASE */

$db_path = $config['db_path'];

$db = new PDO("sqlite:$db_path");

$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$user_data = $db->query("SELECT * FROM users WHERE username='admin'")
->fetch(PDO::FETCH_ASSOC);


/* SECURITY STATUS */

$brute_enabled = !empty($user_data['brute_force_enabled']);

$rtsp_enabled = !empty($user_data['rtsp_protected']);


/* HTTPS STATUS */

$nginx_conf = @file_get_contents("/etc/nginx/sites-available/default") ?: "";

$https_enabled = (strpos($nginx_conf, 'listen 443 ssl') !== false);


/* CAMERA STATUS */

$camera_ip = $config['camera_ip'];

$camera_port = $config['camera_port'];

$fp = @fsockopen($camera_ip, (int)$camera_port, $errno, $errstr, 1);

$camera_online = ($fp !== false);

if ($fp) { fclose($fp); }

/* ALERTS */

$log_file = $config['event_log'];

$events = [];

if (file_exists($log_file)) {

    $lines = array_reverse(
        file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)
    );

    $events = array_slice($lines, 0, 6);
}

?>

<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<title>Security Monitoring Dashboard</title>

<style>

*{
    margin:0;
    padding:0;
    box-sizing:border-box;
}

body{

    font-family:'Segoe UI',sans-serif;

    background:
    radial-gradient(circle at top left, rgba(0,180,255,0.12), transparent 35%),
    radial-gradient(circle at bottom right, rgba(0,230,118,0.08), transparent 30%),
    #070b14;

    color:white;
}

header{

    width:100%;

    padding:22px 40px;

    background:#0b1020;

    border-bottom:1px solid rgba(255,255,255,0.08);

    display:flex;

    justify-content:space-between;

    align-items:center;
}

.logo{

    font-size:30px;

    font-weight:800;

    color:#7cc7ff;
}

.system-status{

    color:#00e676;

    font-weight:bold;
}

.container{

    width:95%;

    max-width:1700px;

    margin:auto;

    padding:30px;
}

.hero{

    background:#111827;

    padding:35px;

    border-radius:26px;

    margin-bottom:28px;

    border:1px solid rgba(124,199,255,0.12);
}

.hero h1{

    color:#7cc7ff;

    font-size:42px;

    margin-bottom:10px;
}

.hero p{

    color:#94a3b8;

    font-size:16px;
}

.cards{

    display:grid;

    grid-template-columns:repeat(4,1fr);

    gap:20px;

    margin-bottom:25px;
}

.card{

    background:#111827;

    padding:25px;

    border-radius:22px;

    border:1px solid rgba(124,199,255,0.12);
}

.card-title{

    color:#94a3b8;

    font-size:14px;

    margin-bottom:12px;
}

.green{

    color:#00e676;

    font-size:30px;

    font-weight:800;
}

.red{

    color:#ff5c5c;

    font-size:30px;

    font-weight:800;
}

.card-note{

    margin-top:10px;

    color:#94a3b8;

    font-size:13px;

    line-height:1.5;
}

.grid{

    display:grid;

    grid-template-columns:1fr 1fr;

    gap:25px;
}

.panel{

    background:#111827;

    padding:28px;

    border-radius:24px;

    border:1px solid rgba(124,199,255,0.12);
}

.panel h2{

    color:#7cc7ff;

    margin-bottom:22px;
}

.row{

    display:flex;

    justify-content:space-between;

    align-items:center;

    padding:16px 0;

    border-bottom:1px solid rgba(255,255,255,0.08);
}

.row:last-child{

    border-bottom:none;
}

.badge{

    padding:7px 14px;

    border-radius:999px;

    font-size:12px;

    font-weight:bold;
}

.badge-green{

    background:rgba(0,230,118,0.15);

    color:#00e676;
}

.badge-red{

    background:rgba(255,92,92,0.15);

    color:#ff5c5c;
}

.event{

    background:#0b1020;

    padding:18px;

    border-radius:18px;

    margin-bottom:14px;

    border:1px solid rgba(124,199,255,0.08);

    font-size:14px;

    color:#e2e8f0;
}

.full-width{

    grid-column:1 / -1;
}

@media(max-width:1000px){

    .cards{
        grid-template-columns:1fr;
    }

    .grid{
        grid-template-columns:1fr;
    }

}

</style>

</head>

<body>

<header>

<div class="logo">
🛡️ Security Monitoring Dashboard
</div>

<div style="display:flex; gap:22px; align-items:center;">
<a href="index.php" style="color:#7cc7ff; text-decoration:none; font-weight:bold;">📹 Live</a>
<a href="settings.php" style="color:#7cc7ff; text-decoration:none; font-weight:bold;">⚙️ Settings</a>
<div class="system-status">● Monitoring Active</div>
</div>

</header>

<div class="container">

<div class="hero">

<h1>Security Monitoring Dashboard</h1>

<p>
Real-time monitoring dashboard for smart camera protection
and attack detection.
</p>

</div>

<div class="cards">

<div class="card">

<div class="card-title">
HTTPS Protection
</div>

<div class="<?php echo $https_enabled ? 'green' : 'red'; ?>">

<?php echo $https_enabled ? '🟢 ON' : '🔴 OFF'; ?>

</div>

<div class="card-note">

<?php echo $https_enabled
? 'HTTPS/TLS encrypted communication is active.'
: 'HTTP insecure communication is currently active.';
?>

</div>

</div>

<div class="card">

<div class="card-title">
Brute Force Protection
</div>

<div class="<?php echo $brute_enabled ? 'green' : 'red'; ?>">

<?php echo $brute_enabled ? '🟢 ON' : '🔴 OFF'; ?>

</div>

<div class="card-note">

<?php echo $brute_enabled
? 'Login attempts are monitored and limited.'
: 'Brute force protection is disabled.';
?>

</div>

</div>

<div class="card">

<div class="card-title">
RTSP Protection
</div>

<div class="<?php echo $rtsp_enabled ? 'green' : 'red'; ?>">

<?php echo $rtsp_enabled ? '🟢 ON' : '🔴 OFF'; ?>

</div>

<div class="card-note">

<?php echo $rtsp_enabled
? 'RTSP Port 554 is protected and filtered.'
: 'RTSP Port 554 is currently accessible.';
?>

</div>

</div>

<div class="card">

<div class="card-title">
Camera Status
</div>

<div class="<?php echo $camera_online ? 'green' : 'red'; ?>">

<?php echo $camera_online ? '🟢 ONLINE' : '🔴 OFFLINE'; ?>

</div>

<div class="card-note">
Camera availability monitoring status.
</div>

</div>

</div>

<div class="grid">

<div class="panel">

<h2>🔐 Protection Controls Status</h2>

<div class="row">
<span>HTTPS / TLS Encryption</span>

<span class="badge <?php echo $https_enabled ? 'badge-green' : 'badge-red'; ?>">

<?php echo $https_enabled ? 'Enabled' : 'Disabled'; ?>

</span>
</div>

<div class="row">
<span>Brute Force Lockout</span>

<span class="badge <?php echo $brute_enabled ? 'badge-green' : 'badge-red'; ?>">

<?php echo $brute_enabled ? 'Enabled' : 'Disabled'; ?>

</span>
</div>

<div class="row">
<span>RTSP Port 554</span>

<span class="badge <?php echo $rtsp_enabled ? 'badge-green' : 'badge-red'; ?>">

<?php echo $rtsp_enabled ? 'Enabled' : 'Disabled'; ?>

</span>
</div>

<div class="row">
<span>Camera Connectivity</span>

<span class="badge <?php echo $camera_online ? 'badge-green' : 'badge-red'; ?>">

<?php echo $camera_online ? 'Online' : 'Offline'; ?>

</span>
</div>

</div>

<div class="panel">

<h2>🧾 Recent Security Alerts</h2>

<?php if(count($events) > 0): ?>

<?php foreach($events as $event): ?>

<div class="event">

<?php echo htmlspecialchars($event); ?>

</div>

<?php endforeach; ?>

<?php else: ?>

<div class="event">

No security alerts detected yet.

</div>

<?php endif; ?>

</div>

<div class="panel full-width">

<h2>📡 System Details</h2>

<div class="row">
<span>Camera IP Address</span>
<span><?php echo htmlspecialchars($camera_ip); ?></span>
</div>

<div class="row">
<span>Protocol State</span>

<span class="badge <?php echo $https_enabled ? 'badge-green' : 'badge-red'; ?>">

<?php echo $https_enabled ? 'HTTPS Active' : 'HTTP Active'; ?>

</span>
</div>

<div class="row">
<span>RTSP Port</span>

<span class="badge <?php echo $rtsp_enabled ? 'badge-green' : 'badge-red'; ?>">

<?php echo $rtsp_enabled ? 'Protected' : 'Accessible'; ?>

</span>
</div>


</div>

</div>

</div>

</body>
</html>
