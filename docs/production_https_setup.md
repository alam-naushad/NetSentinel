# NetSentinel Production HTTPS Deployment Guide (Let's Encrypt IP Certificate)

This guide documents the setup and automated renewal of publicly trusted Let's Encrypt TLS certificates for IP addresses (`13.201.137.162`) on AWS EC2 without domain names or added costs.

---

## 1. Background & Architecture

* **Target Public IP:** `13.201.137.162`
* **Let's Encrypt Profile:** `shortlived` (all Let's Encrypt IP certificates have a ~6-day validity period per policy).
* **Validation Method:** ACME HTTP-01 challenge on port 80 (`/.well-known/acme-challenge/`).
* **Ingress Architecture:**
  * **Port 80:** Public. Unredirected for `/.well-known/acme-challenge/` and `/health`. Redirects all other HTTP traffic to `https://$host$request_uri`.
  * **Port 443:** Public TLS gateway. Terminates TLS using certificates mounted from `/etc/letsencrypt/live/13.201.137.162/`. Proxies `/api/` to backend and serves React SPA on `/`.
  * **Backend (8000) & Postgres (5432):** Isolated on Docker internal network `soc_net`.
  * **Session Security:** `ENABLE_HTTPS=true` enforces `Secure` attribute on HttpOnly session cookies.

---

## 2. Initial Certificate Issuance on EC2

Run these commands on the EC2 instance:

```bash
# 1. Install Certbot
sudo dnf install -y certbot || sudo apt-get update && sudo apt-get install -y certbot

# 2. Create webroot challenge directory
sudo mkdir -p /var/www/certbot

# 3. Stop the current frontend container to free port 80 for standalone ACME challenge
docker compose -f docker-compose.prod.yml stop frontend

# 4. Request the initial shortlived IP certificate via standalone challenge
sudo certbot certonly --standalone \
  --preferred-profile shortlived \
  -d 13.201.137.162 \
  --agree-tos \
  -m admin@netsentinel.local \
  --no-eff-email

# 5. Verify certificate generation
sudo ls -l /etc/letsencrypt/live/13.201.137.162/
# Expected: cert.pem, chain.pem, fullchain.pem, privkey.pem
```

---

## 3. Enable HTTPS and Start Production Stack

```bash
# 1. In your EC2 .env file, update:
# ENABLE_HTTPS=true

# 2. Rebuild and launch the updated production stack
docker compose -f docker-compose.prod.yml up -d --build

# 3. Verify container health status
docker compose -f docker-compose.prod.yml ps
# Both soc_analytics_backend and soc_dashboard_frontend should be (healthy)

# 4. Verify HTTP to HTTPS redirect
curl -I http://13.201.137.162/
# Expected: HTTP/1.1 301 Moved Permanently -> Location: https://13.201.137.162/

# 5. Verify HTTPS access
curl -k -I https://13.201.137.162/
# Expected: HTTP/2 200 (or HTTP/1.1 200) with HSTS headers
```

---

## 4. Automated Certificate Renewal Setup

Because Let's Encrypt IP certificates expire in **6 days (160 hours)**, renewal must run automatically twice daily.

Subsequent renewals will use the **webroot** method (`-w /var/www/certbot`), which does not require stopping Nginx because Nginx serves `/.well-known/acme-challenge/` directly from `/var/www/certbot`.

### Option A: Cron Job (Recommended)

Add a cron job to root's crontab:

```bash
sudo crontab -e
```

Add the following line (runs at 00:00 and 12:00 every day):

```cron
0 0,12 * * * certbot renew --webroot -w /var/www/certbot --post-hook "docker compose -f /home/ec2-user/NetSentinel/docker-compose.prod.yml exec frontend nginx -s reload" >> /var/log/certbot-renew.log 2>&1
```

*(Adjust `/home/ec2-user/NetSentinel/` if your project path differs).*

### Option B: Test Dry Run

To verify that the webroot renewal works without waiting for expiration:

```bash
sudo certbot renew --webroot -w /var/www/certbot --dry-run
```
