import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..', '..');

test('Nginx Config: contains ACME HTTP-01 challenge location with ^~ modifier and webroot', () => {
  const nginxConfPath = path.join(projectRoot, 'frontend', 'nginx.conf');
  assert.ok(fs.existsSync(nginxConfPath), 'frontend/nginx.conf must exist');

  const content = fs.readFileSync(nginxConfPath, 'utf8');

  // Must have explicit ^~ prefix location
  assert.ok(
    content.includes('location ^~ /.well-known/acme-challenge/'),
    'nginx.conf must define "location ^~ /.well-known/acme-challenge/" with ^~ modifier'
  );

  // Must point to /var/www/certbot
  assert.ok(
    content.includes('root /var/www/certbot;'),
    'ACME location must specify root /var/www/certbot;'
  );

  // Must avoid SPA fallback on ACME challenge
  assert.ok(
    content.includes('try_files $uri =404;'),
    'ACME location must specify try_files $uri =404;'
  );

  // Must have unredirected /health endpoint on port 80
  assert.ok(
    content.includes('location /health {'),
    'port 80 server block must contain location /health {'
  );

  // Must have HTTP to HTTPS redirect for general traffic
  assert.ok(
    content.includes('return 301 https://$host$request_uri;'),
    'port 80 server block must redirect normal traffic to HTTPS'
  );

  // Must configure TLS port 443 with Let's Encrypt paths
  assert.ok(content.includes('listen 443 ssl;'), 'Must listen on port 443 with ssl');
  assert.ok(
    content.includes('ssl_certificate /etc/letsencrypt/live/13.201.137.162/fullchain.pem;'),
    "Must specify Let's Encrypt fullchain.pem path"
  );
  assert.ok(
    content.includes('ssl_certificate_key /etc/letsencrypt/live/13.201.137.162/privkey.pem;'),
    "Must specify Let's Encrypt privkey.pem path"
  );
});

test('Docker Compose Prod: mounts nginx.conf, letsencrypt, and certbot volumes', () => {
  const composePath = path.join(projectRoot, 'docker-compose.prod.yml');
  assert.ok(fs.existsSync(composePath), 'docker-compose.prod.yml must exist');

  const content = fs.readFileSync(composePath, 'utf8');

  assert.ok(
    content.includes('./frontend/nginx.conf:/etc/nginx/conf.d/default.conf:ro'),
    'frontend service must bind-mount ./frontend/nginx.conf'
  );
  assert.ok(
    content.includes('/etc/letsencrypt:/etc/letsencrypt:ro'),
    'frontend service must mount /etc/letsencrypt'
  );
  assert.ok(
    content.includes('/var/www/certbot:/var/www/certbot:ro'),
    'frontend service must mount /var/www/certbot'
  );
  assert.ok(content.includes('"80:80"'), 'frontend must expose port 80');
  assert.ok(content.includes('"443:443"'), 'frontend must expose port 443');
});
