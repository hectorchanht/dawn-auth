// @dawn-studio/auth — Google sign-in WITHOUT Firebase and WITHOUT new infra.
//
// Google only proves identity (a signed ID token); the app's own session infra takes
// over from there, exactly like the magic-link verify flow. Same-email Google +
// magic-link sign-ins resolve to ONE user row (upsert by email).
//
// The Web OAuth client ID is the `aud` every ID token must carry — it is a PUBLIC
// identifier (baked into the web bundle + the APK), never a secret.
//
// Ported from OpenMusic's src/lib/auth/auth-core.ts (quick-261020-google); the client
// ID is now a parameter instead of a hardcoded constant.

import { isValidEmail } from './core.js';

/** Google's JWKS endpoint for ID-token verification. */
export const GOOGLE_CERTS_URL = 'https://www.googleapis.com/oauth2/v3/certs';

/** The only two issuers Google ever puts on an ID token. */
export const GOOGLE_ALLOWED_ISSUERS = ['accounts.google.com', 'https://accounts.google.com'];

/** A Google ID token is only ever RS256. Anything else is junk, never a credential. */
const GOOGLE_ID_TOKEN_ALG = 'RS256';

/** How long fetched Google certs are trusted (module scope; the edge isolate reuses it). */
const GOOGLE_CERTS_TTL_MS = 60 * 60 * 1000;

export interface GoogleJwk extends JsonWebKey {
	kid?: string;
}

export interface GoogleJwks {
	keys: GoogleJwk[];
}

let cachedCerts: { keys: GoogleJwk[]; fetchedAt: number } | null = null;

/** TEST-ONLY: drop the cached Google certs so tests control the JWKS deterministically. */
export function __resetGoogleCerts(): void {
	cachedCerts = null;
}

function base64UrlDecode(s: string): Uint8Array<ArrayBuffer> {
	const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
	const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
	const bin = atob(padded);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

async function getGoogleCerts(fetchImpl: typeof fetch): Promise<GoogleJwk[]> {
	const now = Date.now();
	if (cachedCerts && now - cachedCerts.fetchedAt < GOOGLE_CERTS_TTL_MS) return cachedCerts.keys;
	const res = await fetchImpl(GOOGLE_CERTS_URL);
	if (!res.ok) throw new Error(`certs fetch failed: ${res.status}`);
	const jwks = (await res.json()) as GoogleJwks;
	if (!jwks || !Array.isArray(jwks.keys)) throw new Error('certs malformed');
	cachedCerts = { keys: jwks.keys, fetchedAt: now };
	return jwks.keys;
}

/** Never-throw outcome: the verified email, or the precise reason verification failed. */
export type GoogleIdTokenResult = { ok: true; email: string } | { ok: false; reason: string };

export interface VerifyGoogleIdTokenOptions {
	/** The app's Google Web OAuth client ID — every token's `aud` must equal this. */
	clientId: string;
	/** Injects the JWKS for tests. */
	fetchCerts?: () => Promise<GoogleJwks>;
	/** Pins the clock for expiry tests. */
	now?: number;
}

/**
 * Verify a Google ID token (web GIS button or native Play-Services sign-in — both mint
 * JWTs with aud = clientId). Checks, in order: three-part shape, JSON header/payload,
 * alg == RS256, signature against Google's current JWKS (kid-matched), aud, iss, exp,
 * email_verified === true, and a deliverable-looking email.
 *
 * Never throws — every failure is a typed reason the route maps to a status.
 */
export async function verifyGoogleIdToken(
	idToken: string,
	opts: VerifyGoogleIdTokenOptions
): Promise<GoogleIdTokenResult> {
	const parts = typeof idToken === 'string' ? idToken.split('.') : [];
	const [p0, p1, p2] = parts;
	if (!p0 || !p1 || !p2) {
		return { ok: false, reason: 'malformed' };
	}
	if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
		return { ok: false, reason: 'malformed' };
	}
	let header: { alg?: unknown; kid?: unknown };
	let payload: Record<string, unknown>;
	try {
		header = JSON.parse(new TextDecoder().decode(base64UrlDecode(p0)));
		payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(p1)));
	} catch {
		return { ok: false, reason: 'malformed' };
	}
	if (typeof header !== 'object' || header === null) return { ok: false, reason: 'malformed' };
	if (header.alg !== GOOGLE_ID_TOKEN_ALG) return { ok: false, reason: 'bad-alg' };
	if (typeof header.kid !== 'string' || header.kid.length === 0) return { ok: false, reason: 'unknown-kid' };

	let keys: GoogleJwk[];
	try {
		keys = opts?.fetchCerts ? (await opts.fetchCerts()).keys : await getGoogleCerts(fetch);
	} catch {
		return { ok: false, reason: 'certs-unavailable' };
	}
	const jwk = keys.find((k) => k.kty === 'RSA' && k.kid === header.kid);
	if (!jwk) return { ok: false, reason: 'unknown-kid' };

	let valid: boolean;
	try {
		const key = await crypto.subtle.importKey(
			'jwk',
			jwk,
			{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
			false,
			['verify']
		);
		const data = new TextEncoder().encode(p0 + '.' + p1);
		valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, base64UrlDecode(p2), data);
	} catch {
		return { ok: false, reason: 'bad-signature' };
	}
	if (!valid) return { ok: false, reason: 'bad-signature' };

	const nowSec = Math.floor((opts?.now ?? Date.now()) / 1000);
	if (payload.aud !== opts.clientId) return { ok: false, reason: 'bad-aud' };
	if (typeof payload.iss !== 'string' || !GOOGLE_ALLOWED_ISSUERS.includes(payload.iss)) {
		return { ok: false, reason: 'bad-iss' };
	}
	if (typeof payload.exp !== 'number' || payload.exp <= nowSec) return { ok: false, reason: 'expired' };
	// Google emits a real boolean here; a string "true" is not accepted — strict is safer
	// than lenient when the claim gates account creation.
	if (payload.email_verified !== true) return { ok: false, reason: 'email-unverified' };
	const email = typeof payload.email === 'string' ? payload.email.trim().toLowerCase() : '';
	if (!isValidEmail(email)) return { ok: false, reason: 'bad-email' };
	return { ok: true, email };
}
