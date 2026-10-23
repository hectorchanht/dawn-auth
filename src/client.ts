// @dawn-studio/auth — framework-agnostic browser client.
//
// The same session semantics as OpenMusic's Svelte runes store, without the Svelte:
// a plain class with subscribe/onChange, usable from React, Vue, Svelte, or vanilla.
// Credential channels:
//   - WEB: the httpOnly session cookie. Every request carries credentials:'include'
//     and the client NEVER sees — let alone stores — the token. The verify() response
//     body also contains the token (the native seam); on web it is ignored.
//   - NATIVE (e.g. Capacitor WebView): cookies for the deployed origin are unreliable,
//     so the bearer token from verify() is persisted (injected storage) and sent as
//     `Authorization: Bearer <token>` on every authed request.

import {
	TOKEN_RE,
	codeRe,
	diagLine,
	isValidEmail,
	type AccountUser
} from './core.js';
import type { RequestLinkResult, VerifyCodeResult } from './service.js';

/**
 * Client-side requestLink outcomes: the service union plus the two client-only
 * cases — 'network' (fetch threw / timed out, after one retry) and 'error'
 * (the server answered a failure the union doesn't name).
 */
export type ClientRequestLinkResult = RequestLinkResult | 'network' | 'error';

/** Client-side verifyCode outcomes: the service union plus 'network'. */
export type ClientVerifyCodeResult = VerifyCodeResult | 'network';

/** What the magic-link redeem returns: the scheme for the deep-link handoff + the
 *  native bearer token (null on web, where the cookie is the credential). */
export interface VerifyResult {
	ok: boolean;
	scheme: string | null;
	token: string | null;
}

export interface AuthSnapshot {
	user: AccountUser | null;
	ready: boolean;
	/** Raw diagnostic from the last requestLink network failure (the real error). */
	lastLinkDiag: string | null;
}

export interface DawnAuthClientOptions {
	/** API base, e.g. '' (same origin) or 'https://api.app.lol'. Default ''. */
	baseUrl?: string;
	/** fetch implementation. Default globalThis.fetch. */
	fetchImpl?: typeof fetch;
	/** True on native (Capacitor etc.) — enables the bearer seam. Default false. */
	isNative?: boolean | (() => boolean);
	/** Where the native bearer persists. Default: guarded localStorage. */
	storage?: {
		getItem(key: string): string | null;
		setItem(key: string, value: string): void;
		removeItem(key: string): void;
	};
	/** Key for the persisted native bearer. Default '<slug>:auth-token:v1'. */
	tokenStorageKey?: string;
	/** Sign-in code length in digits — must match the server's `codeLength`. Default 6. */
	codeLength?: number;
	/** Timeout for sign-in POSTs. Default 15000ms. */
	requestTimeoutMs?: number;
	/** Timeout for the post-failure differential probe. Default 8000ms. */
	probeTimeoutMs?: number;
	/** Optional Google sign-out hook (native): release the Play-Services identity so
	 *  the next "Sign in with Google" re-prompts the account chooser. */
	onNativeGoogleSignOut?: () => Promise<void>;
}

const FAILED: VerifyResult = { ok: false, scheme: null, token: null };

function defaultStorage(): DawnAuthClientOptions['storage'] {
	try {
		const ls = globalThis.localStorage;
		if (!ls) return undefined;
		return {
			getItem: (k) => ls.getItem(k),
			setItem: (k, v) => ls.setItem(k, v),
			removeItem: (k) => ls.removeItem(k)
		};
	} catch {
		return undefined;
	}
}

export class DawnAuthClient {
	private opts: Required<
		Pick<DawnAuthClientOptions, 'baseUrl' | 'fetchImpl' | 'tokenStorageKey' | 'codeLength' | 'requestTimeoutMs' | 'probeTimeoutMs'>
	> &
		Pick<DawnAuthClientOptions, 'storage' | 'onNativeGoogleSignOut'> & { isNative: () => boolean };
	private listeners = new Set<(snap: AuthSnapshot) => void>();
	private bearer: string | null = null;
	private loaded = false;

	user: AccountUser | null = null;
	ready = false;
	lastLinkDiag: string | null = null;

	constructor(opts: DawnAuthClientOptions = {}) {
		const isNative = opts.isNative ?? false;
		this.opts = {
			baseUrl: opts.baseUrl ?? '',
			fetchImpl: opts.fetchImpl ?? fetch.bind(globalThis),
			tokenStorageKey: opts.tokenStorageKey ?? 'dawn:auth-token:v1',
			codeLength: opts.codeLength ?? 6,
			requestTimeoutMs: opts.requestTimeoutMs ?? 15_000,
			probeTimeoutMs: opts.probeTimeoutMs ?? 8_000,
			isNative: typeof isNative === 'function' ? isNative : () => isNative,
			storage: opts.storage ?? defaultStorage(),
			onNativeGoogleSignOut: opts.onNativeGoogleSignOut
		};
	}

	/** Subscribe to state changes; returns an unsubscribe function. */
	subscribe(fn: (snap: AuthSnapshot) => void): () => void {
		this.listeners.add(fn);
		return () => {
			this.listeners.delete(fn);
		};
	}

	private emit(): void {
		const snap: AuthSnapshot = { user: this.user, ready: this.ready, lastLinkDiag: this.lastLinkDiag };
		for (const fn of this.listeners) {
			try {
				fn(snap);
			} catch {
				/* listener bugs must not break auth */
			}
		}
	}

	private authedFetch(path: string, init: RequestInit = {}): Promise<Response> {
		const headers = new Headers(init.headers);
		if (init.body != null && !headers.has('content-type')) {
			headers.set('content-type', 'application/json');
		}
		if (this.opts.isNative() && this.bearer) {
			headers.set('authorization', `Bearer ${this.bearer}`);
		}
		return this.opts.fetchImpl(this.opts.baseUrl + path, { ...init, credentials: 'include', headers });
	}

	/** Boot probe: GET /api/auth/session. Fire-and-forget from the app shell; idempotent. */
	async load(): Promise<void> {
		if (this.loaded) return;
		this.loaded = true;
		try {
			if (this.opts.isNative()) {
				try {
					const raw = this.opts.storage?.getItem(this.opts.tokenStorageKey);
					const parsed = raw ? (JSON.parse(raw) as { token?: unknown }) : null;
					this.bearer = typeof parsed?.token === 'string' ? parsed.token : null;
				} catch {
					this.bearer = null;
				}
			}
			const res = await this.authedFetch('/api/auth/session');
			const body = (await res.json().catch(() => null)) as { user: AccountUser | null } | null;
			this.user = body?.user ?? null;
			// A native token the server no longer knows is dead weight — drop it so the
			// next sign-in starts clean instead of sending a stale bearer forever.
			if (!this.user && this.bearer) this.dropBearer();
		} catch {
			this.user = null;
		}
		this.ready = true;
		this.emit();
	}

	/**
	 * Sign-in step 1: ask the server to email a magic link. Never throws.
	 *
	 * Honest errors, one retry: a NETWORK failure (fetch threw, timeout, DNS) retries
	 * ONCE (2 attempts total) before reporting 'network'. A 4xx/5xx from the server
	 * NEVER retries — the server already decided, and a blind retry could re-send the
	 * mail the first attempt already queued.
	 */
	async requestLink(email: string, opts?: { scheme?: string }): Promise<ClientRequestLinkResult> {
		const clean = email.trim().toLowerCase();
		if (!isValidEmail(clean)) return 'invalid-email';
		this.lastLinkDiag = null;
		const diagParts: string[] = [];
		for (let attempt = 0; attempt < 2; attempt++) {
			const t0 = Date.now();
			try {
				const res = await this.authedFetch('/api/auth/magic-link', {
					method: 'POST',
					body: JSON.stringify({ email: clean, ...(opts?.scheme ? { scheme: opts.scheme } : {}) }),
					signal: AbortSignal.timeout(this.opts.requestTimeoutMs)
				});
				if (res.ok) return 'ok';
				const err = ((await res.json().catch(() => null)) as { err?: string } | null)?.err;
				if (err === 'rate-limited') return 'rate-limited';
				if (err === 'invalid-email') return 'invalid-email';
				if (err === 'invalid-scheme') return 'invalid-scheme';
				if (err === 'not-configured') return 'not-configured';
				if (err === 'send-failed') return 'send-failed';
				return 'error';
			} catch (e) {
				// The REAL failure, per attempt — never a paraphrase.
				diagParts.push(diagLine(e, attempt, Date.now() - t0));
				if (attempt === 0) continue; // retry once, on network failure only
				this.lastLinkDiag = diagParts.join(' | ') + (await this.probeDiag());
				this.emit();
				return 'network';
			}
		}
		return 'network'; // unreachable — every loop path returns above
	}

	/**
	 * Differential probe after a failed requestLink: can the client reach the API AT
	 * ALL? A plain GET /api/auth/session (no preflight, trivial store read) answers it.
	 * Probe reachable + POST failed → the POST itself is the problem (preflight /
	 * timeout); probe failed too → the client↔server path is down.
	 */
	private async probeDiag(): Promise<string> {
		const t0 = Date.now();
		try {
			const res = await this.authedFetch('/api/auth/session', {
				signal: AbortSignal.timeout(this.opts.probeTimeoutMs)
			});
			return ` || probe: HTTP ${res.status} @${Date.now() - t0}ms`;
		} catch (e) {
			const name = e instanceof Error ? e.name : 'Unknown';
			const msg = e instanceof Error ? e.message : String(e);
			return ` || probe: ${name}: ${msg || '(no message)'} @${Date.now() - t0}ms`;
		}
	}

	/** Sign-in step 2 (called by the magic-link landing page): redeem the token. */
	async verify(token: string): Promise<VerifyResult> {
		try {
			const res = await this.authedFetch('/api/auth/verify', {
				method: 'POST',
				body: JSON.stringify({ token })
			});
			if (!res.ok) return FAILED;
			const body = (await res.json().catch(() => null)) as {
				user: AccountUser;
				token: string;
				scheme?: string | null;
			} | null;
			if (!body?.user) return FAILED;
			const scheme = typeof body.scheme === 'string' ? body.scheme : null;
			const bearer = typeof body.token === 'string' ? body.token : null;
			this.establishSession(body.user, bearer);
			return { ok: true, scheme, token: bearer };
		} catch {
			return FAILED;
		}
	}

	/**
	 * Google sign-in: exchange a Google ID token for the app's own session. The token
	 * comes from the web's Google Identity Services button or the native Play-Services
	 * sign-in; the server verifies the JWT and upserts by email.
	 */
	async signInWithGoogle(idToken: string): Promise<VerifyResult> {
		if (!idToken) return FAILED;
		try {
			const res = await this.authedFetch('/api/auth/google', {
				method: 'POST',
				body: JSON.stringify({ idToken })
			});
			if (!res.ok) return FAILED;
			const body = (await res.json().catch(() => null)) as {
				user: AccountUser;
				token: string;
				scheme?: string | null;
			} | null;
			if (!body?.user) return FAILED;
			const bearer = typeof body.token === 'string' ? body.token : null;
			this.establishSession(body.user, bearer);
			return { ok: true, scheme: null, token: bearer };
		} catch {
			return FAILED;
		}
	}

	/** Sign-in step 2b: verify the numeric code from the sign-in email (native path). */
	async verifyCode(email: string, code: string): Promise<ClientVerifyCodeResult> {
		const cleanEmail = email.trim().toLowerCase();
		if (!isValidEmail(cleanEmail) || !codeRe(this.opts.codeLength).test(code.trim())) return 'invalid';
		try {
			const res = await this.authedFetch('/api/auth/verify-code', {
				method: 'POST',
				body: JSON.stringify({ email: cleanEmail, code: code.trim() })
			});
			if (res.status === 429) return 'rate-limited';
			if (!res.ok) {
				const err = (await res.json().catch(() => null)) as { err?: string } | null;
				return err?.err === 'too-many-attempts' ? 'too-many-attempts' : 'invalid-code';
			}
			const body = (await res.json().catch(() => null)) as {
				user: AccountUser;
				token: string | null;
			} | null;
			if (!body?.user) return 'invalid-code';
			const bearer = typeof body.token === 'string' ? body.token : null;
			this.establishSession(body.user, bearer);
			return 'ok';
		} catch {
			return 'network';
		}
	}

	/**
	 * Adopt the session bearer that crossed on the deep link
	 * (`<scheme>auth/callback?token=…`), after the system browser burned the magic
	 * token. The intent payload is attacker-reachable, so the 64-hex screen is the gate
	 * here too. Idempotent — a duplicate delivery re-probes, it never re-burns anything.
	 */
	async adoptNativeToken(token: string): Promise<boolean> {
		if (!this.opts.isNative()) return false;
		if (!TOKEN_RE.test(token)) return false;
		this.bearer = token;
		this.persistBearer();
		try {
			const res = await this.authedFetch('/api/auth/session');
			const body = (await res.json().catch(() => null)) as { user: AccountUser | null } | null;
			this.user = body?.user ?? null;
		} catch {
			this.user = null;
		}
		// A bearer the server doesn't know is dead weight — drop it, same as load()'s
		// stale-token path, so the next sign-in starts clean.
		if (!this.user) this.dropBearer();
		this.ready = true;
		this.emit();
		return this.user !== null;
	}

	/** Sign out: delete the server session (best-effort), drop every local credential. */
	async logout(): Promise<void> {
		try {
			await this.authedFetch('/api/auth/logout', { method: 'POST' });
		} catch {
			/* unreachable server — the local sign-out below still applies */
		}
		this.user = null;
		this.dropBearer();
		this.lastLinkDiag = null;
		if (this.opts.isNative()) {
			// Release the native Google identity too, so the next "Sign in with Google"
			// re-prompts the account chooser instead of silently reusing the previous
			// account. Best-effort: our own sign-out above already applied.
			try {
				await this.opts.onNativeGoogleSignOut?.();
			} catch {
				/* nothing to release */
			}
		}
		this.emit();
	}

	/** The post-login path verify() / signInWithGoogle() / verifyCode() share. */
	private establishSession(user: AccountUser, bearer: string | null): void {
		this.user = user;
		this.ready = true;
		// Native ONLY: persist the bearer. On web the token in this body is ignored on
		// purpose — the httpOnly cookie is already set and JS must not hold it.
		if (this.opts.isNative() && bearer) {
			this.bearer = bearer;
			this.persistBearer();
		}
		this.emit();
	}

	private persistBearer(): void {
		if (!this.bearer) return;
		try {
			this.opts.storage?.setItem(this.opts.tokenStorageKey, JSON.stringify({ token: this.bearer }));
		} catch {
			/* quota — the in-memory bearer still covers this session */
		}
	}

	private dropBearer(): void {
		this.bearer = null;
		try {
			this.opts.storage?.removeItem(this.opts.tokenStorageKey);
		} catch {
			/* ignore */
		}
	}
}
