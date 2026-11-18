export const WORKER_API_URL = 'https://amrs-api.akatsukiakira1102.workers.dev';
export const LOGIN_SITES = {
  old: 'https://akira1102-creat.github.io/amrs-login-transfer/',
  next: 'https://amrs-cloudflare.pages.dev/',
};

const marker = 'amrsLoginTransfer';
const pendingKey = 'amrs.loginTransfer';
const attemptedKey = 'amrs.loginTransferAttempted';
const noncePattern = /^[a-zA-Z0-9_-]{43}$/;
const maxAgeMs = 5 * 60_000;
const genericError = '未能沿用現有登入，請重試或手動登入。';

const base64URL = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const randomNonce = () => base64URL(crypto.getRandomValues(new Uint8Array(32)));
const fingerprint = async value => base64URL(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))));
const claimURL = (target, values) => {
  const url = new URL(target);
  url.hash = new URLSearchParams(values).toString();
  return url.href;
};

export function loginTransferStep(href, sites) {
  const url = new URL(href);
  const params = new URLSearchParams(url.hash.slice(1));
  const oldPage = new URL(sites.old);
  const newPage = new URL(sites.next);
  if (url.origin === oldPage.origin && url.pathname === oldPage.pathname && params.get(marker) === 'start') return 'issue';
  if (url.origin === newPage.origin && url.pathname === newPage.pathname && params.get(marker) === 'return') return 'redeem';
  return '';
}

export async function beginLoginTransfer(href, storage, sites) {
  const url = new URL(href);
  if (url.origin !== new URL(sites.next).origin) throw new Error(genericError);
  const verifier = randomNonce();
  const state = randomNonce();
  const challenge = await fingerprint(verifier);
  storage.setItem(attemptedKey, '1');
  storage.setItem(pendingKey, JSON.stringify({ verifier, state, returnTo: url.href, createdAt: Date.now() }));
  return claimURL(sites.old, { [marker]: 'start', state, challenge });
}

export async function beginAvailableLoginTransfer(href, storage, sites, fetchImpl = globalThis.fetch) {
  let response;
  try {
    response = await fetchImpl(sites.old, {
      method: 'HEAD', cache: 'no-store', credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(2500),
    });
  } catch { return ''; }
  if (!response.ok || !response.headers.get('content-type')?.startsWith('text/html')) return '';
  return beginLoginTransfer(href, storage, sites);
}

export async function beginAutomaticLoginTransfer(href, storage, sites, fetchImpl = globalThis.fetch) {
  const url = new URL(href);
  const target = new URL(sites.next);
  if (url.origin !== target.origin || url.pathname !== target.pathname || loginTransferStep(href, sites)
      || storage.getItem(attemptedKey)) return '';

  storage.setItem(attemptedKey, '1');
  return beginAvailableLoginTransfer(href, storage, sites, fetchImpl);
}

export function readSavedCredential(storage) {
  const text = value => String(value ?? '').trim();
  const personal = text(storage.getItem('_amrs_access_token_v1'));
  if (personal) return personal;
  const company = text(storage.getItem('_ml_company'));
  const direct = text(storage.getItem('_ml_gas_' + company) || storage.getItem('_ml_gas'));
  if (direct) return direct;
  for (let i = 0; i < storage.length; i++) {
    const key = storage.key(i);
    if (key?.startsWith('_ml_gas_') && text(storage.getItem(key))) return text(storage.getItem(key));
  }
  return '';
}

export async function readVerifiedLogin(storage, markerFingerprint) {
  const oldMarker = storage.getItem('_ml_auth');
  return oldMarker && await fingerprint(oldMarker) === markerFingerprint ? readSavedCredential(storage) : '';
}

export async function exchangeLoginTransfer(step, body) {
  const response = await fetch(`${WORKER_API_URL}/login-transfer/${step}`, {
    method: 'POST', cache: 'no-store', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body), signal: AbortSignal.timeout(12_000),
  });
  if (!response.ok) throw new Error(genericError);
  return response.json();
}

export async function issueLoginTransfer(href, readCredential, sites, exchange) {
  if (loginTransferStep(href, sites) !== 'issue') throw new Error(genericError);
  const params = new URLSearchParams(new URL(href).hash.slice(1));
  const state = params.get('state');
  const challenge = params.get('challenge');
  if (!noncePattern.test(state || '') || !noncePattern.test(challenge || '')) throw new Error(genericError);
  const result = { [marker]: 'return', state };
  try {
    const credential = await readCredential();
    if (!credential) return claimURL(sites.next, { ...result, error: 'no-saved-login' });
    const { code } = await exchange('issue', { credential, challenge });
    if (typeof code === 'string' && noncePattern.test(code)) return claimURL(sites.next, { ...result, code });
  } catch {
    // Return the browser to the regular login screen if the original login is unavailable.
  }
  return claimURL(sites.next, { ...result, error: 'unavailable' });
}

export async function finishLoginTransfer(href, storage, sites, exchange, cleanLocation) {
  if (loginTransferStep(href, sites) !== 'redeem') throw new Error(genericError);
  const url = new URL(href);
  const params = new URLSearchParams(url.hash.slice(1));
  url.hash = '';
  let pending;
  try { pending = JSON.parse(storage.getItem(pendingKey)); } catch { /* Storage may be unavailable. */ }
  const matched = noncePattern.test(params.get('state') || '') && pending?.state === params.get('state');
  let returnTo = url;
  if (matched) {
    storage.removeItem(pendingKey);
    const recorded = new URL(pending.returnTo, url);
    if (recorded.origin === url.origin) returnTo = recorded;
  }
  cleanLocation(returnTo.href);
  if (!matched || !noncePattern.test(pending.verifier || '') || !(Date.now() - pending.createdAt < maxAgeMs)) throw new Error(genericError);
  if (params.get('error') === 'no-saved-login') throw new Error('呢個瀏覽器未有可沿用嘅舊站登入，請手動登入。');
  const code = params.get('code');
  if (!noncePattern.test(code || '')) throw new Error(genericError);
  const result = await exchange('redeem', { code, verifier: pending.verifier });
  if (typeof result.credential !== 'string' || !result.credential) throw new Error(genericError);
  return result.credential;
}
