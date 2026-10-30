#!/bin/bash
# Do not touch nginx if the certificate files are missing
if [ ! -f /etc/ssl/certs/cert.pem ] || [ ! -f /etc/ssl/private/key.pem ]; then
    echo "Certificate missing - HTTPS not enabled"
    exit 1
fi

cat > /etc/nginx/sites-available/default <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
return 302 https://$host$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;

    root /var/www/html;
    index index.php;
    server_name _;

    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
    }
}
EOF

nginx -t && systemctl reload nginx

echo "HTTPS Enabled"
