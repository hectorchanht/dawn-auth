// @dawn-studio/auth — PURE primitives. No D1, no fetch, no framework imports.
// Never throws for an expected failure. Edge-safe (Web Crypto only).
//
// Ported from OpenMusic's src/lib/auth/auth-core.ts (quick-261020-acct), generalized:
// every OpenMusic-specific constant (cookie name, deep-link scheme) is now a parameter.

/** The account row every auth route works with. Never carries a token or a hash. */
export interface AccountUser {
	id: string;
	email: string;
}

/** 30 days, in seconds — the default session cookie Max-Age. */
export const SESSION_MAX_AGE_SECONDS = 30 * 24 * 3600;

/** The one shape every token (magic + session) must have before it is hashed or looked up. */
export const TOKEN_RE = /^[0-9a-f]{64}$/;

/** The default 6-digit sign-in code shape (see `codeRe()` for other lengths). */
export const CODE_RE = /^[0-9]{6}$/;

/**
 * Sign-in code shape for a configured length: `codeRe(cfg.codeLength)`.
 * The length itself is validated by `defineAuth()` (4–9, crypto-safe).
 */
export function codeRe(length: number): RegExp {
	return new RegExp(`^[0-9]{${length}}$`);
}

/** A code dies after this many wrong guesses (per code_hash row, in the store). */
export const MAX_CODE_ATTEMPTS = 5;

/**
 * Exact-match allowlist check for the magic-link `scheme` field: the scheme must be
 * one of the app's own native schemes (e.g. 'openmusic://') — never `javascript:`,
 * never `https:`, never a lookalike. Empty allowlist = every scheme is rejected.
 */
export function isAllowedScheme(scheme: unknown, allowed: readonly string[]): scheme is string {
	return typeof scheme === 'string' && allowed.includes(scheme);
}

/** 64 lowercase hex chars from `bytes` random bytes (32 ⇒ the 64-hex token shape). */
export function randomToken(bytes = 32): string {
	const b = crypto.getRandomValues(new Uint8Array(bytes));
	return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

/** Lowercase hex SHA-256 of a string. Async because crypto.subtle is async everywhere. */
export async function sha256hex(s: string): Promise<string> {
	const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
	return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, '0')).join('');
}

/** First `n` lowercase hex chars of SHA-256(s) (hex is per-byte, so truncating the hex
 *  string equals truncating the digest bytes first). */
export async function sha256hexN(s: string, n: number): Promise<string> {
	return (await sha256hex(s)).slice(0, n);
}

/**
 * Crypto-random numeric code of `length` digits (default 6 ⇒ 100000–999999),
 * rejection-sampled off a full uint32 — no modulo bias (the range divides 2^32 with
 * a remainder, so the tail is re-drawn). Lengths 4–9 stay inside uint32; longer is
 * rejected by `defineAuth()` so the bias math always holds.
 */
export function randomCode(length = 6): string {
	const min = 10 ** (length - 1);
	const range = 9 * min;
	const limit = 4294967296 - (4294967296 % range);
	const b = new Uint32Array(1);
	do {
		crypto.getRandomValues(b);
	} while ((b[0] as number) >= limit);
	return String(min + ((b[0] as number) % range));
}

/**
 * Constant-time string equality for credential-hash comparison — a naive `===` leaks
 * the matching prefix length through timing (an oracle for guessing the code hash).
 */
export function timingSafeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return diff === 0;
}

/** Deliberately broad email screen (the Clipbin regex): deliverability is the mail
 *  provider's problem; a stricter screen would lock out real addresses (plus-tags,
 *  IDN domains…). */
export function isValidEmail(email: string): boolean {
	return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/** Raw session token from the session cookie, or null. NOT format-checked here —
 *  TOKEN_RE is applied by getAuthToken, the single gate. */
export function getSessionTokenFromCookie(request: Request, cookieName: string): string | null {
	const cookie = request.headers.get('cookie') || '';
	const m = cookie.match(new RegExp(`(?:^|;\\s*)${cookieName}=([^;]+)`));
	if (!m || m[1] === undefined) return null;
	try {
		return decodeURIComponent(m[1]);
	} catch {
		return null; // a malformed %-escape in a cookie value is not a token
	}
}

/** Raw session token from `Authorization: Bearer <token>`, or null (native seam). */
export function getBearerToken(request: Request): string | null {
	const h = request.headers.get('authorization') || '';
	const m = h.match(/^Bearer\s+(.+)$/i);
	const token = m?.[1];
	return token ? token.trim() : null;
}

/**
 * The request's session token, whichever channel carried it — cookie FIRST (the web
 * client's httpOnly cookie is the canonical credential), bearer second (native only).
 * Returns null when neither channel carries a well-formed token.
 *
 * NATIVE SEAM: a native WebView (e.g. Capacitor, origin https://localhost) cannot rely
 * on a cookie set on the deployed origin, so it persists the session token from the
 * verify response and sends it back as `Authorization: Bearer <token>`. The server must
 * advertise `Authorization` in its CORS allow-headers for this to work.
 */
export function getAuthToken(request: Request, cookieName: string): string | null {
	const cookie = getSessionTokenFromCookie(request, cookieName);
	if (cookie && TOKEN_RE.test(cookie)) return cookie;
	const bearer = getBearerToken(request);
	if (bearer && TOKEN_RE.test(bearer)) return bearer;
	return null;
}

/**
 * Session cookie attributes — every one is user-configurable via
 * `defineAuth({ cookie: { ... } })`. Defaults keep the secure posture:
 * httpOnly, Secure, SameSite=Lax, Path=/.
 */
export interface SessionCookieAttrs {
	/** 'Lax' | 'Strict' | 'None'. Default 'Lax'. */
	sameSite?: 'Lax' | 'Strict' | 'None';
	/** Default true. Set false ONLY for plain-http local dev (never in prod). */
	secure?: boolean;
	/** Default '/'. */
	path?: string;
	/** Optional, e.g. '.app.lol' for subdomain SSO. */
	domain?: string;
	/** Default true. */
	httpOnly?: boolean;
}

/** Resolved cookie attributes — every field concrete except the optional domain. */
export interface ResolvedSessionCookieAttrs {
	sameSite: 'Lax' | 'Strict' | 'None';
	secure: boolean;
	path: string;
	domain?: string;
	httpOnly: boolean;
}

function cookieAttrParts(attrs: SessionCookieAttrs): string[] {
	const parts: string[] = [`Path=${attrs.path ?? '/'}`];
	if (attrs.httpOnly ?? true) parts.push('HttpOnly');
	if (attrs.secure ?? true) parts.push('Secure');
	parts.push(`SameSite=${attrs.sameSite ?? 'Lax'}`);
	if (attrs.domain) parts.push(`Domain=${attrs.domain}`);
	return parts;
}

/** `Set-Cookie` value establishing the session (default 30-day, httpOnly, Secure, SameSite=Lax). */
export function buildSessionCookie(
	token: string,
	cookieName: string,
	maxAgeSeconds = SESSION_MAX_AGE_SECONDS,
	attrs: SessionCookieAttrs = {}
): string {
	return [`${cookieName}=${encodeURIComponent(token)}`, ...cookieAttrParts(attrs), `Max-Age=${maxAgeSeconds}`].join(
		'; '
	);
}

/** `Set-Cookie` value clearing the session (logout) — mirrors the same attrs so the
 *  clear actually overwrites the set cookie (Path/Domain must match). */
export function clearSessionCookie(cookieName: string, attrs: SessionCookieAttrs = {}): string {
	return [`${cookieName}=`, ...cookieAttrParts(attrs), 'Max-Age=0'].join('; ');
}

/** Best-effort client IP for rate-limit keys. Cloudflare sets CF-Connecting-IP on every
 *  edge request; 'unknown' buckets the rest (local dev) under one shared key. */
export function clientIp(request: Request): string {
	return request.headers.get('cf-connecting-ip') || 'unknown';
}

/**
 * One raw diagnostic line for a failed request attempt (the REAL error, not a
 * paraphrase): `attempt 1: TypeError: Failed to fetch @230ms`. A 15s AbortError means
 * the request hung; an instant TypeError means the client never reached the server
 * (DNS/TCP/TLS/CORS-preflight).
 */
export function diagLine(thrown: unknown, attempt: number, elapsedMs: number): string {
	const name = thrown instanceof Error ? thrown.name : 'Unknown';
	const msg = thrown instanceof Error ? thrown.message : String(thrown);
	return `attempt ${attempt + 1}: ${name}: ${msg || '(no message)'} @${elapsedMs}ms`;
}

/**
 * The deep-link URL the magic page offers after a scheme-tagged redeem:
 * `<scheme>auth/callback?token=<64-hex bearer>`. The bearer is the 30-day SESSION
 * token (the same value the verify response carries); the magic token is single-use
 * and already burned by the time this URL is built, so re-tapping is harmless.
 */
export function buildAuthCallbackUrl(scheme: string, bearerToken: string): string {
	return `${scheme}auth/callback?token=${encodeURIComponent(bearerToken)}`;
}

/**
 * Parse an incoming deep link into the auth-callback bearer token, or null.
 *
 * The OS's manifest filter is NOT the gate — a hostile app can hand the activity any
 * VIEW intent, so the payload is re-checked here before it can become a credential:
 * exact `<scheme>:` protocol, exact `auth` host, exact `/callback` path, and a token
 * that passes TOKEN_RE. Anything else is junk, never a credential.
 */
export function parseAuthCallbackUrl(
	raw: string | null | undefined,
	scheme: string
): string | null {
	if (!raw) return null;
	const protocol = scheme.endsWith('://') ? scheme.slice(0, -3) + ':' : scheme + ':';
	try {
		const u = new URL(raw);
		if (u.protocol !== protocol) return null;
		if (u.hostname.toLowerCase() !== 'auth') return null;
		if (u.pathname !== '/callback') return null;
		const token = u.searchParams.get('token') ?? '';
		return TOKEN_RE.test(token) ? token : null;
	} catch {
		// Not a URL — junk or an attack, never a credential.
		return null;
	}
}

/** Minimal HTML-escape for user input interpolated into the email (the footer address). */
export function escapeHtml(s: string): string {
	return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
