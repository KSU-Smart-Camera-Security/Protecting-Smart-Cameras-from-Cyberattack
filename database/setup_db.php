<?php
// Creates the database and the admin account.
// Usage (on the device):  php setup_db.php
if (PHP_SAPI !== 'cli') { exit("Run this script from the command line only.\n"); }

$configFile = __DIR__ . '/../web/config.php';
if (!file_exists($configFile)) { exit("Copy web/config.sample.php to web/config.php first.\n"); }
$config = require $configFile;

$dir = dirname($config['db_path']);
if (!is_dir($dir)) { mkdir($dir, 0750, true); }

$db = new PDO("sqlite:" . $config['db_path']);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec(file_get_contents(__DIR__ . '/schema.sql'));

$exists = $db->query("SELECT COUNT(*) FROM users WHERE username = 'admin'")->fetchColumn();
if ($exists) { exit("Admin user already exists. Nothing changed.\n"); }

echo "Admin email [{$config['alert_email']}]: ";
$email = trim(fgets(STDIN));
if ($email === '') { $email = $config['alert_email']; }

echo "Admin password (min 8 characters): ";
shell_exec('stty -echo');
$pass = trim(fgets(STDIN));
shell_exec('stty echo');
echo "\n";
if (strlen($pass) < 8) { exit("Password too short.\n"); }

$db->prepare("INSERT INTO users (username, password, email) VALUES ('admin', :p, :e)")
   ->execute([':p' => password_hash($pass, PASSWORD_DEFAULT), ':e' => $email]);

echo "Done. Make sure the web server user can read AND write {$config['db_path']} and its folder:\n";
echo "  sudo chown -R www-data:www-data $dir\n";
