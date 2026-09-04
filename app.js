'use strict';

const form = document.getElementById('totp-form');
const secretInput = document.getElementById('secret');
const toggleSecretBtn = document.getElementById('toggle-secret');
const result = document.getElementById('result');
const codeEl = document.getElementById('code');
const remainingEl = document.getElementById('remaining');
const timerBar = document.getElementById('timer-bar');
const copyBtn = document.getElementById('copy-code');
const clearBtn = document.getElementById('clear-btn');
const messageEl = document.getElementById('message');
const accountLabel = document.getElementById('account-label');
const issuerLabel = document.getElementById('issuer-label');

let activeSecret = null;
let timerId = null;
let lastCounter = null;

function showMessage(text, type = 'error') {
  messageEl.textContent = text;
  messageEl.className = `message ${type}`;
  messageEl.classList.remove('hidden');
}

function hideMessage() {
  messageEl.textContent = '';
  messageEl.className = 'message hidden';
}

function base32ToBytes(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = input
    .toUpperCase()
    .replace(/\s+/g, '')
    .replace(/-/g, '')
    .replace(/=+$/g, '');

  if (!cleaned) throw new Error('请输入 2FA Secret。');
  if (!/^[A-Z2-7]+$/.test(cleaned)) throw new Error('Secret 不是有效的 Base32 格式。');

  let bits = '';
  for (const char of cleaned) {
    bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  if (bytes.length === 0) throw new Error('Secret 太短或格式无效。');
  return new Uint8Array(bytes);
}

function parseInput(raw) {
  const value = raw.trim();
  if (!value) throw new Error('请输入 2FA Secret。');

  if (value.toLowerCase().startsWith('otpauth://')) {
    let url;
    try { url = new URL(value); } catch { throw new Error('otpauth 链接格式无效。'); }
    if (url.protocol !== 'otpauth:' || url.hostname.toLowerCase() !== 'totp') {
      throw new Error('目前仅支持 TOTP 类型的 otpauth 链接。');
    }
    const secret = url.searchParams.get('secret');
    if (!secret) throw new Error('otpauth 链接里没有 secret 参数。');

    const digits = Number(url.searchParams.get('digits') || '6');
    const period = Number(url.searchParams.get('period') || '30');
    const algorithm = (url.searchParams.get('algorithm') || 'SHA1').toUpperCase();
    if (digits !== 6) throw new Error('此版本仅允许标准 6 位 TOTP。');
    if (period !== 30) throw new Error('此版本仅允许标准 30 秒周期 TOTP。');
    if (algorithm !== 'SHA1') throw new Error('此版本仅允许标准 SHA-1 TOTP。');

    const label = decodeURIComponent(url.pathname.replace(/^\//, '')) || 'TOTP';
    const issuer = url.searchParams.get('issuer') || '';
    return { secret, label, issuer };
  }

  return { secret: value, label: 'TOTP', issuer: '' };
}

function counterBytes(counter) {
  const bytes = new Uint8Array(8);
  let value = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

async function generateTotp(secret, now = Date.now()) {
  const keyBytes = base32ToBytes(secret);
  const counter = Math.floor(now / 1000 / 30);
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes(counter)));
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return { code: String(binary % 1_000_000).padStart(6, '0'), counter };
}

async function refresh() {
  if (!activeSecret) return;
  const now = Date.now();
  const seconds = now / 1000;
  const remaining = 30 - (seconds % 30);
  const shown = Math.max(1, Math.ceil(remaining));
  remainingEl.textContent = `${shown} 秒`;
  timerBar.style.transform = `scaleX(${remaining / 30})`;

  const counter = Math.floor(seconds / 30);
  if (counter !== lastCounter) {
    const generated = await generateTotp(activeSecret, now);
    codeEl.textContent = generated.code;
    lastCounter = generated.counter;
  }
}

function clearAll() {
  activeSecret = null;
  lastCounter = null;
  secretInput.value = '';
  secretInput.type = 'password';
  toggleSecretBtn.textContent = '显示';
  codeEl.textContent = '------';
  accountLabel.textContent = 'TOTP';
  issuerLabel.textContent = '';
  result.classList.add('hidden');
  hideMessage();
  if (timerId) {
    clearInterval(timerId);
    timerId = null;
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  hideMessage();
  try {
    const parsed = parseInput(secretInput.value);
    base32ToBytes(parsed.secret); // validate before storing in runtime state
    activeSecret = parsed.secret;
    accountLabel.textContent = parsed.label;
    issuerLabel.textContent = parsed.issuer;
    result.classList.remove('hidden');
    lastCounter = null;
    await refresh();
    if (timerId) clearInterval(timerId);
    timerId = setInterval(() => refresh().catch(() => showMessage('验证码刷新失败。')), 250);
  } catch (error) {
    clearAll();
    showMessage(error instanceof Error ? error.message : '无法生成验证码。');
  }
});

toggleSecretBtn.addEventListener('click', () => {
  const show = secretInput.type === 'password';
  secretInput.type = show ? 'text' : 'password';
  toggleSecretBtn.textContent = show ? '隐藏' : '显示';
  toggleSecretBtn.setAttribute('aria-label', show ? '隐藏密钥' : '显示密钥');
});

copyBtn.addEventListener('click', async () => {
  const code = codeEl.textContent;
  if (!/^\d{6}$/.test(code)) return;
  try {
    await navigator.clipboard.writeText(code);
    showMessage('验证码已复制。', 'ok');
    setTimeout(hideMessage, 1500);
  } catch {
    showMessage('浏览器未允许自动复制，请手动选择验证码。');
  }
});

clearBtn.addEventListener('click', clearAll);

window.addEventListener('pageshow', (event) => {
  if (event.persisted) clearAll();
});
window.addEventListener('pagehide', clearAll);
window.addEventListener('beforeunload', () => {
  activeSecret = null;
  secretInput.value = '';
});

// Always start from a clean state; never restore secrets from browser storage.
clearAll();
