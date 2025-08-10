# Enable HTTPS (SSL/TLS) on Nginx for Two Sites

This guide shows how to enable SSL/TLS (HTTPS) for two hostnames on a single Nginx server using Let's Encrypt (Certbot), add automatic HTTP→HTTPS redirects, enable auto‑renewal, and apply recommended TLS/security headers.

Replace example hostnames with your own:
- `webmail-auth001.academmia.store` (redirect site)
- `webmail-auth001.sbhinjjia.xyz` (main site)

## Prerequisites
- DNS A/AAAA records for each hostname point to your server's public IP
- Inbound ports 80 (HTTP) and 443 (HTTPS) are open in your firewall/cloud security group
- Root or sudo access to the server
- OS: Ubuntu/Debian or RHEL/CentOS/Rocky

If using a CDN (e.g., Cloudflare), set SSL mode to Full (strict). For HTTP‑01 issuance, temporarily disable proxy (grey cloud) or use DNS‑01 with a Certbot DNS plugin.

## 1) Install Nginx and Certbot

Ubuntu/Debian:
```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx
```

RHEL/CentOS/Rocky:
```bash
sudo dnf install -y nginx certbot python3-certbot-nginx
sudo systemctl enable --now nginx
```

## 2) Create minimal HTTP server blocks (so Certbot can detect sites)

Debian/Ubuntu (sites-available/sites-enabled pattern):
```nginx
# /etc/nginx/sites-available/redirect_site
server {
  listen 80;
  server_name webmail-auth001.academmia.store;
  root /var/www/redirect; # optional
}

# /etc/nginx/sites-available/main_site
server {
  listen 80;
  server_name webmail-auth001.sbhinjjia.xyz;
  root /var/www/main; # optional
}
```
Enable and reload:
```bash
sudo mkdir -p /var/www/redirect /var/www/main
sudo ln -s /etc/nginx/sites-available/redirect_site /etc/nginx/sites-enabled/redirect_site
sudo ln -s /etc/nginx/sites-available/main_site /etc/nginx/sites-enabled/main_site
sudo nginx -t && sudo systemctl reload nginx
```

RHEL family (single conf.d directory):
```nginx
# /etc/nginx/conf.d/redirect_site.conf
server {
  listen 80;
  server_name webmail-auth001.academmia.store;
  root /var/www/redirect;
}

# /etc/nginx/conf.d/main_site.conf
server {
  listen 80;
  server_name webmail-auth001.sbhinjjia.xyz;
  root /var/www/main;
}
```
Reload:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

## 3) Get and install certificates (auto-configure HTTPS and redirects)

One certificate covering both hosts:
```bash
sudo certbot --nginx -d webmail-auth001.academmia.store -d webmail-auth001.sbhinjjia.xyz
```
- When prompted, select the option to redirect HTTP to HTTPS
- Certbot will create 443 server blocks and manage certificate paths automatically

Alternatively, run Certbot for each hostname separately (two certs):
```bash
sudo certbot --nginx -d webmail-auth001.academmia.store
sudo certbot --nginx -d webmail-auth001.sbhinjjia.xyz
```

## 4) Verify and set up auto-renewal

Test config and reload:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

Check the renewal timer and dry-run renewal:
```bash
systemctl list-timers | grep certbot || true
sudo certbot renew --dry-run
```

## 5) Harden TLS and add security headers (recommended)

Add these inside each HTTPS server block (Certbot created them). Adjust as needed:
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:sslcache:10m;
ssl_stapling on;
ssl_stapling_verify on;

# Security headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```
Reload after editing:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

## 6) Manual example of final HTTPS server blocks

If you prefer to hand‑write the HTTPS blocks or verify Certbot output, use this as a template (paths are where Certbot places files):

```nginx
# HTTPS for webmail-auth001.sbhinjjia.xyz (main site)
server {
  listen 443 ssl http2;
  server_name webmail-auth001.sbhinjjia.xyz;

  ssl_certificate /etc/letsencrypt/live/webmail-auth001.sbhinjjia.xyz/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/webmail-auth001.sbhinjjia.xyz/privkey.pem;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_stapling on;
  ssl_stapling_verify on;

  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;

  root /var/www/main;
  index index.html;

  location / {
    try_files $uri $uri/ =404;
  }
}

# HTTP redirect + ACME challenge (webmail-auth001.sbhinjjia.xyz)
server {
  listen 80;
  server_name webmail-auth001.sbhinjjia.xyz;

  location /.well-known/acme-challenge/ {
    root /var/www/letsencrypt;
  }

  return 301 https://$host$request_uri;
}

# HTTPS for webmail-auth001.academmia.store (redirect site)
server {
  listen 443 ssl http2;
  server_name webmail-auth001.academmia.store;

  ssl_certificate /etc/letsencrypt/live/webmail-auth001.academmia.store/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/webmail-auth001.academmia.store/privkey.pem;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_stapling on;
  ssl_stapling_verify on;

  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;

  # Example redirecting to main site (optional):
  location / {
    return 301 https://webmail-auth001.sbhinjjia.xyz$request_uri;
  }
}

# HTTP redirect + ACME challenge (webmail-auth001.academmia.store)
server {
  listen 80;
  server_name webmail-auth001.academmia.store;

  location /.well-known/acme-challenge/ {
    root /var/www/letsencrypt;
  }

  return 301 https://$host$request_uri;
}
```

## 7) Validate
- Browse to `https://webmail-auth001.sbhinjjia.xyz` and `https://webmail-auth001.academmia.store`
- Use SSL Labs to verify an A/A+ grade and confirm TLS 1.2/1.3 only

## Troubleshooting
- Ensure port 80 is reachable during issuance (HTTP‑01). If behind a proxy, use DNS‑01 with a Certbot DNS plugin (e.g., Cloudflare)
- If Certbot cannot find your server blocks, ensure `server_name` matches your DNS hostnames and Nginx config is reloaded
- Renewal failures: check `/var/log/letsencrypt/letsencrypt.log`
- Avoid placing secrets in URLs; prefer POST for credentials and clear sensitive query params by redirecting after processing