// @dawn-studio/auth — the service layer: the three sign-in flows + session mgmt.
//
// Every function is a never-throw service (house rule): expected failures come back
// as typed results the route maps to statuses. The route owns the HTTP shape
// (guards, CORS, body parsing); this module owns the semantics.
//
// Flows:
//   1. requestMagicLink — step 1: mint the intent (magic token + 6-digit code), email it.
//   2a. verifyMagicToken — step 2 (link clicked): redeem the 64-hex token.
//   2b. verifyCode — step 2 (code typed in app): redeem the 6-digit code.
//   3. signInWithGoogle — exchange a Google ID token for the app's own session.
// All three converge on issueSessionForEmail: upsert-by-email means Google +
// magic-link + code for one address are ONE user, and the success contract is
// byte-identical: { user, sessionToken, scheme }.

import type { ResolvedAuthConfig } from './config.js';
import {
	CODE_RE,
	MAX_CODE_ATTEMPTS,
	TOKEN_RE,
	buildSessionCookie,
	clearSessionCookie,
	clientIp,
	getAuthToken,
	isAllowedScheme,
	isValidEmail,
	randomCode,
	randomToken,
	sha256hex,
	timingSafeEqual,
	type AccountUser
} from './core.js';
import { buildSignInEmail } from './email.js';
import { verifyGoogleIdToken, type GoogleJwks } from './google.js';
import { rateLimit, type AuthStore } from './store.js';

/** requestMagicLink outcomes — the client maps each to its own message. */
export type RequestLinkResult =
	| 'ok'
	| 'invalid-email'
	| 'invalid-scheme'
	| 'rate-limited'
	| 'not-configured'
	| 'send-failed';

/** verifyCode outcomes. */
export type VerifyCodeResult =
	| 'ok'
	| 'invalid' // malformed email/code shape — client-side, never sent
	| 'invalid-code' // wrong / expired / unknown — one refusal, no oracle
	| 'too-many-attempts' // 5 wrong guesses on this code
	| 'rate-limited';

export interface SessionIssued {
	user: AccountUser;
	/** The 30-day session token: the NATIVE bearer seam. Web clients must use the
	 *  httpOnly cookie and never store this; native clients persist it and send it
	 *  as `Authorization: Bearer <token>`. */
	sessionToken: string;
	/** The native scheme the intent was minted with, or null. */
	scheme: string | null;
}

export type VerifyMagicTokenResult =
	| ({ ok: true } & SessionIssued)
	| { ok: false; reason: 'invalid-token' };

export type VerifyCodeServiceResult =
	| ({ ok: true } & SessionIssued)
	| { ok: false; result: Exclude<VerifyCodeResult, 'ok'> };

export type GoogleSignInResult =
	| ({ ok: true } & SessionIssued)
	| { ok: false; reason: 'invalid-token' | 'rate-limited' | 'not-configured' };

/**
 * Issue the app's own session for an email: upsert the user row by email, mint a
 * 30-day session token, store hex(SHA-256('session:'+token)). Shared by all three
 * sign-in flows.
 */
export async function issueSessionForEmail(
	store: AuthStore,
	email: string,
	sessionTtlMs: number
): Promise<{ user: AccountUser; token: string }> {
	let user = await store.findUserByEmail(email);
	if (!user) user = await store.createUser(email);
	const token = randomToken(32);
	const hash = await sha256hex('session:' + token);
	await store.insertSession({ token_hash: hash, user_id: user.id, expires_at: Date.now() + sessionTtlMs });
	return { user, token };
}

/**
 * Send the sign-in email via the Resend API.
 *
 * The explicit browser User-Agent is load-bearing: Resend's Cloudflare front door
 * rejects bare default UAs with 403 error 1010; a browser UA passes. The header costs
 * nothing on the happy path.
 */
export async function sendViaResend(
	apiKey: string,
	msg: { from: string; to: string; subject: string; html: string; text: string }
): Promise<boolean> {
	try {
		const res = await fetch('https://api.resend.com/emails', {
			method: 'POST',
			headers: {
				Authorization: `Bearer ${apiKey}`,
				'Content-Type': 'application/json',
				'User-Agent':
					'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
			},
			body: JSON.stringify(msg)
		});
		if (!res.ok) {
			// Drain so the connection can be reused; the body is never logged (it may
			// echo the recipient address back).
			await res.body?.cancel().catch(() => {});
			return false;
		}
		return true;
	} catch {
		return false;
	}
}

export interface RequestMagicLinkInput {
	email: string;
	/** Optional native-handoff scheme — STRICT allowlist against cfg.nativeSchemes. */
	scheme?: string;
	/** Request origin, used to build the absolute magic link (e.g. https://app.lol). */
	origin: string;
	/** Client IP for the per-IP rate-limit key. */
	ip: string;
}

/**
 * Sign-in step 1: validate, rate-limit, mint the intent (magic token + 6-digit code),
 * and email it. Gates, cheapest first: shape → scheme → rate limits → key present
 * (fail CLOSED before a token row exists) → send (a failed send deletes the row).
 */
export async function requestMagicLink(
	store: AuthStore,
	cfg: ResolvedAuthConfig,
	input: RequestMagicLinkInput
): Promise<RequestLinkResult> {
	const email = input.email.trim().toLowerCase();
	if (!isValidEmail(email)) return 'invalid-email';
	if (input.scheme !== undefined && !isAllowedScheme(input.scheme, cfg.nativeSchemes)) {
		return 'invalid-scheme';
	}

	const [okEmail, okIp] = await Promise.all([
		rateLimit(store, `ml:email:${email}`, cfg.magicLinkLimits.perEmail.max, cfg.magicLinkLimits.perEmail.windowMs),
		rateLimit(store, `ml:ip:${input.ip}`, cfg.magicLinkLimits.perIp.max, cfg.magicLinkLimits.perIp.windowMs)
	]);
	if (!okEmail || !okIp) return 'rate-limited';

	// Fail CLOSED on a missing key, BEFORE minting anything — a misconfigured deploy
	// never leaves orphan token rows.
	if (!cfg.resendApiKey) return 'not-configured';

	const token = randomToken(32);
	const tokenHash = await sha256hex('magic:' + token);
	// The SECOND credential for this intent: a 6-digit code for the native path (typed
	// into the app, no browser). Stored as hex(SHA-256('code:'+code)); the raw code only
	// ever exists in the email. Either credential burns the intent.
	const code = randomCode();
	const codeHash = await sha256hex('code:' + code);
	await store.insertMagicToken({
		token_hash: tokenHash,
		email,
		expires_at: Date.now() + cfg.magicLinkTtlMs,
		scheme: input.scheme ?? null,
		code_hash: codeHash
	});

	const link = `${input.origin}${cfg.magicPagePath}?token=${token}`;
	const mailer = cfg.mailer ?? ((m) => sendViaResend(cfg.resendApiKey as string, m));
	const sent = await mailer({
		from: cfg.from,
		to: email,
		...buildSignInEmail({
			appName: cfg.appName,
			domain: cfg.domain,
			brandColor: cfg.brandColor,
			link,
			code,
			toEmail: email
		})
	});
	if (!sent) {
		// The email never left — the token must not stay redeemable.
		await store.deleteMagicToken(tokenHash);
		return 'send-failed';
	}
	return 'ok';
}

/**
 * Sign-in step 2a: redeem a magic-link token. One refusal for unknown / used /
 * expired — never say which (no oracle for guessing). Burning the link burns the
 * code too (same row, used=1) — two credentials, one intent.
 */
export async function verifyMagicToken(
	store: AuthStore,
	cfg: ResolvedAuthConfig,
	token: string
): Promise<VerifyMagicTokenResult> {
	if (!TOKEN_RE.test(token)) return { ok: false, reason: 'invalid-token' };
	const hash = await sha256hex('magic:' + token);
	const row = await store.findMagicToken(hash);
	if (!row || row.used || row.expires_at < Date.now()) {
		return { ok: false, reason: 'invalid-token' };
	}
	await store.burnMagicToken(hash);
	const { user, token: sessionToken } = await issueSessionForEmail(store, row.email, cfg.sessionTtlMs);
	return { ok: true, user, sessionToken, scheme: row.scheme };
}

export interface VerifyCodeInput {
	email: string;
	code: string;
	ip: string;
}

/**
 * Sign-in step 2b: the 6-digit CODE path (native: typed into the app, no browser).
 * The code is looked up by EMAIL (latest live intent) — never by code hash, because a
 * 6-digit space is enumerable and there is no code→row index to scan.
 */
export async function verifyCode(
	store: AuthStore,
	cfg: ResolvedAuthConfig,
	input: VerifyCodeInput
): Promise<VerifyCodeServiceResult> {
	const email = input.email.trim().toLowerCase();
	const code = input.code.trim();
	if (!isValidEmail(email) || !CODE_RE.test(code)) {
		return { ok: false, result: 'invalid' };
	}

	// Guess-rate limit BEFORE touching the token row (defense in depth over the
	// per-code 5-attempt rule).
	const [okEmail, okIp] = await Promise.all([
		rateLimit(store, `vc:email:${email}`, cfg.verifyCodeLimits.perEmail.max, cfg.verifyCodeLimits.perEmail.windowMs),
		rateLimit(store, `vc:ip:${input.ip}`, cfg.verifyCodeLimits.perIp.max, cfg.verifyCodeLimits.perIp.windowMs)
	]);
	if (!okEmail || !okIp) return { ok: false, result: 'rate-limited' };

	// Latest live intent for this email. `used = 1` covers link-burned rows too —
	// either credential consumes the intent.
	const row = await store.findLiveMagicTokenByEmail(email, Date.now());
	// One refusal for unknown / expired / code-less rows — never say which.
	if (!row || !row.code_hash) return { ok: false, result: 'invalid-code' };
	if (row.code_attempts >= MAX_CODE_ATTEMPTS) return { ok: false, result: 'too-many-attempts' };

	const guessHash = await sha256hex('code:' + code);
	if (!timingSafeEqual(guessHash, row.code_hash)) {
		await store.bumpCodeAttempts(row.token_hash);
		return { ok: false, result: 'invalid-code' };
	}

	// Correct code — burn the intent (the link dies with it) and issue the session.
	await store.burnMagicToken(row.token_hash);
	const { user, token: sessionToken } = await issueSessionForEmail(store, email, cfg.sessionTtlMs);
	return { ok: true, user, sessionToken, scheme: row.scheme };
}

export interface GoogleSignInInput {
	idToken: string;
	ip: string;
	fetchCerts?: () => Promise<GoogleJwks>;
	now?: number;
}

/**
 * Google sign-in: verify the ID token (RS256 vs Google's JWKS, then aud/iss/exp/
 * email_verified), upsert BY EMAIL so a same-email Google + magic-link sign-in is ONE
 * user, and issue the app's own 30-day session. The success contract is byte-identical
 * to the other flows: { user, sessionToken, scheme } (`scheme` always null here).
 */
export async function signInWithGoogle(
	store: AuthStore,
	cfg: ResolvedAuthConfig,
	input: GoogleSignInInput
): Promise<GoogleSignInResult> {
	if (!cfg.googleClientId) return { ok: false, reason: 'not-configured' };
	const idToken = input.idToken;
	if (!idToken || idToken.length > 8192) return { ok: false, reason: 'invalid-token' };

	// Pre-verification rate limit by IP (the email is only known after verification).
	// A Google sign-in attempt is cheap for an attacker to mint (no email round-trip).
	if (!(await rateLimit(store, `google:ip:${input.ip}`, cfg.googleLimits.perIp.max, cfg.googleLimits.perIp.windowMs))) {
		return { ok: false, reason: 'rate-limited' };
	}

	const verified = await verifyGoogleIdToken(idToken, {
		clientId: cfg.googleClientId,
		fetchCerts: input.fetchCerts,
		now: input.now
	});
	// One refusal for every verification failure — never say which (no oracle).
	if (!verified.ok) return { ok: false, reason: 'invalid-token' };

	// Post-verification rate limit by email — a verified identity is the stable key.
	if (
		!(await rateLimit(
			store,
			`google:email:${verified.email}`,
			cfg.googleLimits.perEmail.max,
			cfg.googleLimits.perEmail.windowMs
		))
	) {
		return { ok: false, reason: 'rate-limited' };
	}

	const { user, token: sessionToken } = await issueSessionForEmail(store, verified.email, cfg.sessionTtlMs);
	return { ok: true, user, sessionToken, scheme: null };
}

/**
 * Who is signed in on this request: accepts EITHER the httpOnly session cookie (web)
 * OR an `Authorization: Bearer <token>` header (native) — getAuthToken owns that seam.
 */
export async function getSessionUser(
	store: AuthStore,
	cfg: ResolvedAuthConfig,
	request: Request
): Promise<AccountUser | null> {
	const token = getAuthToken(request, cfg.cookieName);
	if (!token) return null;
	const hash = await sha256hex('session:' + token);
	return store.findSessionUser(hash, Date.now());
}

/**
 * Destroy the session for whichever credential the request carried (cookie OR bearer).
 * Returns the clearing Set-Cookie value; the route always answers 200 — signing out
 * must succeed from the client's point of view even when the session was already gone.
 */
export async function destroySession(
	store: AuthStore,
	cfg: ResolvedAuthConfig,
	request: Request
): Promise<{ clearCookie: string }> {
	const token = getAuthToken(request, cfg.cookieName);
	if (token) {
		await store.deleteSession(await sha256hex('session:' + token));
	}
	return { clearCookie: clearSessionCookie(cfg.cookieName) };
}

/** `Set-Cookie` header value establishing a session — the route sets it on verify. */
export function sessionCookie(sessionToken: string, cfg: ResolvedAuthConfig): string {
	const maxAge = Math.floor(cfg.sessionTtlMs / 1000);
	return buildSessionCookie(sessionToken, cfg.cookieName, maxAge);
}

/** Best-effort client IP for rate-limit keys (Cloudflare CF-Connecting-IP, else 'unknown'). */
export function requestIp(request: Request): string {
	return clientIp(request);
}
