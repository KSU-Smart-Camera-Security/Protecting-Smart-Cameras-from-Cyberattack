# Protecting Smart Cameras from Cyberattacks

A graduation project (Cybersecurity, King Saud University) that secures a Raspberry Pi smart camera with a web control panel. The panel lets an administrator switch protections on and off, watch the live stream, and see security alerts in real time.

The full project report is in [`docs/`](docs/Protecting_Smart_Cameras_from_Cyberattack.pdf).

## Features

| Protection | How it works |
|---|---|
| **HTTPS / TLS** | Nginx is switched between HTTP and HTTPS (with redirect) by `enable_https.sh` / `disable_https.sh`. An email alert is sent when the panel is opened over plain HTTP. |
| **Brute-force protection** | After 5 failed logins the login is locked for 30 seconds and an alert email is sent. |
| **MFA** | Optional 6-digit email code after the password step. |
| **RTSP protection** | `iptables` drops and logs traffic to port 554. `rtsp_alert.sh` reads the log and emails the attacker's IP. |
| **Dashboard** | `dashboard.php` shows the status of every protection, camera availability and the latest security events. |

## Project structure

```
web/        PHP control panel (index, settings, dashboard) + config.sample.php
scripts/    Bash scripts that change nginx / iptables and send RTSP alerts
database/   schema.sql and setup_db.php (creates the admin account)
docs/       Project report (PDF)
```

## Setup (Raspberry Pi / Debian)

1. Install the requirements: `nginx`, `php-fpm`, `php-sqlite3`, `sqlite3`, `mailutils`, `iptables`.
2. Copy `web/*.php` to `/var/www/html/` and `scripts/*.sh` to `/home/camera/`, then make them root-owned: `sudo chown root:root /home/camera/*.sh && sudo chmod 755 /home/camera/*.sh`. The web server runs them as root through `sudo`, so nobody else must be able to edit them.
3. Create the configuration: `cp web/config.sample.php web/config.php` and edit it (email, camera IP and credentials, database path).
4. Create the database and admin account: `php database/setup_db.php`. The script asks for the password, so it is never stored in the repository. Then copy the configuration next to the web files: `sudo cp web/config.php /var/www/html/config.php`.
5. Allow the web server to run only the control scripts. Add this with `sudo visudo -f /etc/sudoers.d/camera`:
   ```
   www-data ALL=(root) NOPASSWD: /home/camera/enable_https.sh, /home/camera/disable_https.sh, /home/camera/enable_rtsp_protection.sh, /home/camera/disable_rtsp_protection.sh
   ```
6. Run the RTSP alert watcher in the background, for example `ALERT_EMAIL=you@example.com ./rtsp_alert.sh &`, or as a systemd service.
7. Create a self-signed certificate at `/etc/ssl/certs/cert.pem` and `/etc/ssl/private/key.pem` (the paths used by `enable_https.sh`).

> The nginx scripts assume PHP 8.4 (`php8.4-fpm.sock`). Change the socket path if you use another version.

## Security notes

- Passwords are stored as bcrypt hashes. An old plaintext password is upgraded automatically at first login.
- All state-changing actions in the settings page are protected by a CSRF token, and the dashboard requires a login.
- The MFA code expires after 5 minutes and allows at most 5 tries.
- Changing the admin password requires the current password.
- Session cookies are `HttpOnly` and `SameSite=Strict`.
- Secrets (email, camera credentials) live in `web/config.php`, which is excluded from Git.

**Known limitations** (future work):
- Login lockout is tracked per session, so an attacker who drops the cookie can bypass it. Per-IP tracking (the `login_attempts` table) is not wired in yet.
- The camera credentials are placed in the stream URL seen by the logged-in browser. A reverse proxy in front of the stream would hide them.
- The RTSP protection drops all traffic to port 554, including legitimate viewers.
- When HTTPS is enabled the browser may block the camera stream (it is served over plain HTTP inside the page). A reverse proxy would fix this too.
- Intended for lab and educational use. Review it before using it in production.
## Team Members

## Team Members

This graduation project was collaboratively developed by six Cybersecurity students at King Saud University.

- [Alaa Majed Batais](https://github.com/AlaaBTS22)
- [Besan Al Habardi](https://github.com/besanalhabardi-hash)
- [Lujain Harbi](https://github.com/lujainharbicyb-lang)
- [Ghala Al-Qahtani](https://github.com/ghala26)
- [Rawan Al Qahtani](https://github.com/Ra966n)
- [Rana Al Harbi](https://github.com/Rana9717)
