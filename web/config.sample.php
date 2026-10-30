<?php
// Copy this file to config.php and fill in your own values.
// config.php is listed in .gitignore and must NEVER be committed.
return [
    'db_path'      => '/var/www/database/system_users.db',
    'event_log'    => '/var/log/camera_security_events.log',
    'alert_email'  => 'your-email@example.com',

    // Camera stream (Raspberry Pi camera)
    'camera_ip'    => '192.168.1.50',
    'camera_port'  => '8888',
    'camera_user'  => 'CAMERA_USER',
    'camera_pass'  => 'CAMERA_PASSWORD',
];
