import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test('LoginView: contains accessible labels, form structure, and SOC branding', () => {
  const loginViewPath = path.join(__dirname, 'LoginView.tsx');
  assert.ok(fs.existsSync(loginViewPath), 'LoginView.tsx must exist');

  const content = fs.readFileSync(loginViewPath, 'utf8');

  // Accessible labels
  assert.ok(content.includes('htmlFor="soc-username"'), 'Username input must have accessible label binding');
  assert.ok(content.includes('htmlFor="soc-password"'), 'Password input must have accessible label binding');
  assert.ok(content.includes('aria-label='), 'Password toggle button must include aria-label');

  // SOC branding
  assert.ok(content.includes('NetSentinel'), 'Must display NetSentinel brand name');
  assert.ok(content.includes('Security Operations Center'), 'Must display SOC subtitle');

  // Input attributes
  assert.ok(content.includes('autoComplete="username"'), 'Username input must specify autocomplete');
  assert.ok(content.includes('autoComplete="current-password"'), 'Password input must specify autocomplete');
});

test('LoginView: implements password visibility toggle logic', () => {
  const loginViewPath = path.join(__dirname, 'LoginView.tsx');
  const content = fs.readFileSync(loginViewPath, 'utf8');

  // Verify state toggle
  assert.ok(content.includes('const [showPassword, setShowPassword] = useState(false);'));
  assert.ok(content.includes("type={showPassword ? 'text' : 'password'}"));
  assert.ok(content.includes('setShowPassword(!showPassword)'));
});

test('LoginView: validates empty inputs before dispatching request', () => {
  const loginViewPath = path.join(__dirname, 'LoginView.tsx');
  const content = fs.readFileSync(loginViewPath, 'utf8');

  assert.ok(content.includes('!username.trim() || !password'));
  assert.ok(content.includes('Please enter both username and password.'));
});

test('LoginView: renders distinct error states for 401 and 429 throttling', () => {
  const loginViewPath = path.join(__dirname, 'LoginView.tsx');
  const content = fs.readFileSync(loginViewPath, 'utf8');

  // 401 handling
  assert.ok(content.includes('apiErr.status === 401'));
  assert.ok(content.includes('Authentication failed: Invalid username or password.'));

  // 429 throttling
  assert.ok(content.includes('apiErr.status === 429'));
  assert.ok(content.includes('isRateLimited'));
  assert.ok(content.includes('Access Throttled'));

  // Session expired banner
  assert.ok(content.includes('sessionExpired'));
  assert.ok(content.includes('Session Timeout'));
  assert.ok(content.includes('role="alert"'));
});

test('AuthContext & App: guards navigation and routes behind authentication state', () => {
  const authContextPath = path.join(__dirname, '..', '..', 'context', 'AuthContext.tsx');
  const appPath = path.join(__dirname, '..', '..', 'App.tsx');

  assert.ok(fs.existsSync(authContextPath), 'AuthContext.tsx must exist');
  assert.ok(fs.existsSync(appPath), 'App.tsx must exist');

  const authContent = fs.readFileSync(authContextPath, 'utf8');
  const appContent = fs.readFileSync(appPath, 'utf8');

  // AuthContext methods
  assert.ok(authContent.includes('const login = async'));
  assert.ok(authContent.includes('const logout = async'));
  assert.ok(authContent.includes('netsentinel:unauthorized'));

  // App routing
  assert.ok(appContent.includes('<AuthProvider>'));
  assert.ok(appContent.includes('if (!isAuthenticated)'));
  assert.ok(appContent.includes('<LoginView />'));
});
