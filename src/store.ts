// @dawn-studio/auth — storage layer.
//
// `AuthStore` is the seam between the auth service and the database. The lib ships
// `createD1Store()` (Cloudflare D1 — the house backend); any other backend implements
// the same interface. The service never issues SQL itself, so swapping stores never
// touches auth semantics.

import type { AccountUser } from './core.js';

/** One login intent row: the magic-link hash + the 6-digit code hash are TWO
 *  CREDENTIALS FOR ONE INTENT — burning either invalidates the other. */
export interface MagicTokenRow {
	token_hash: string;
	email: string;
	expires_at: number;
	used: number;
	scheme: string | null;
	code_hash: string | null;
	code_attempts: number;
}

export interface SessionInsert {
	token_hash: string;
	user_id: string;
	expires_at: number;
}

export interface RateRow {
	count: number;
	window_start: number;
}

export interface AuthStore {
	// -- users ---------------------------------------------------------------
	findUserByEmail(email: string): Promise<AccountUser | null>;
	createUser(email: string): Promise<AccountUser>;
	// -- magic tokens (login intents) ----------------------------------------
	insertMagicToken(row: Omit<MagicTokenRow, 'used' | 'code_attempts'>): Promise<void>;
	findMagicToken(tokenHash: string): Promise<MagicTokenRow | null>;
	/** Latest live (unused, unexpired) intent for an email — the code path looks the
	 *  intent up BY EMAIL because a 6-digit space is enumerable (no code→row index). */
	findLiveMagicTokenByEmail(email: string, now: number): Promise<MagicTokenRow | null>;
	/** Burn the intent: the link AND the code die together (used=1). */
	burnMagicToken(tokenHash: string): Promise<void>;
	bumpCodeAttempts(tokenHash: string): Promise<void>;
	deleteMagicToken(tokenHash: string): Promise<void>;
	// -- sessions --------------------------------------------------------------
	insertSession(s: SessionInsert): Promise<void>;
	/** Resolve a session hash to its user (null when unknown/expired). The join means
	 *  a deleted user invalidates their sessions for free. */
	findSessionUser(tokenHash: string, now: number): Promise<AccountUser | null>;
	deleteSession(tokenHash: string): Promise<void>;
	// -- fixed-window rate limits ----------------------------------------------
	getRate(key: string): Promise<RateRow | null>;
	resetRate(key: string, now: number): Promise<void>;
	bumpRate(key: string): Promise<void>;
}

/**
 * Fixed-window rate limiter (the Clipbin _lib.js pattern). Returns true when the call
 * is ALLOWED. The window is anchored at the first hit; once `windowMs` has passed
 * since `window_start`, the counter restarts at 1.
 */
export async function rateLimit(
	store: AuthStore,
	key: string,
	max: number,
	windowMs: number
): Promise<boolean> {
	const now = Date.now();
	const row = await store.getRate(key);
	if (!row || now - row.window_start > windowMs) {
		await store.resetRate(key, now);
		return true;
	}
	if (row.count >= max) return false;
	await store.bumpRate(key);
	return true;
}

// -- D1 implementation -----------------------------------------------------------

/** Minimal structural type for a D1 database — no @cloudflare/workers-types needed. */
export interface D1Like {
	prepare(query: string): {
		bind(...args: unknown[]): {
			first<T = Record<string, unknown>>(column?: string): Promise<T | null>;
			run(): Promise<unknown>;
		};
	};
}

function rowToMagicToken(r: Record<string, unknown>): MagicTokenRow {
	return {
		token_hash: String(r['token_hash']),
		email: String(r['email']),
		expires_at: Number(r['expires_at']),
		used: Number(r['used']),
		scheme: (r['scheme'] as string | null) ?? null,
		code_hash: (r['code_hash'] as string | null) ?? null,
		code_attempts: Number(r['code_attempts'])
	};
}

/** The house backend: Cloudflare D1 over schema.sql. */
export function createD1Store(db: D1Like): AuthStore {
	return {
		async findUserByEmail(email) {
			return db
				.prepare('SELECT id, email FROM users WHERE email = ?')
				.bind(email)
				.first<AccountUser>();
		},
		async createUser(email) {
			const id = crypto.randomUUID();
			await db.prepare('INSERT INTO users (id, email) VALUES (?, ?)').bind(id, email).run();
			return { id, email };
		},
		async insertMagicToken(row) {
			await db
				.prepare(
					'INSERT INTO magic_tokens (token_hash, email, expires_at, scheme, code_hash) VALUES (?, ?, ?, ?, ?)'
				)
				.bind(row.token_hash, row.email, row.expires_at, row.scheme, row.code_hash)
				.run();
		},
		async findMagicToken(tokenHash) {
			const r = await db
				.prepare('SELECT token_hash, email, expires_at, used, scheme, code_hash, code_attempts FROM magic_tokens WHERE token_hash = ?')
				.bind(tokenHash)
				.first<Record<string, unknown>>();
			return r ? rowToMagicToken(r) : null;
		},
		async findLiveMagicTokenByEmail(email, now) {
			const r = await db
				.prepare(
					'SELECT token_hash, email, expires_at, used, scheme, code_hash, code_attempts FROM magic_tokens WHERE email = ? AND used = 0 AND expires_at > ? ORDER BY rowid DESC LIMIT 1'
				)
				.bind(email, now)
				.first<Record<string, unknown>>();
			return r ? rowToMagicToken(r) : null;
		},
		async burnMagicToken(tokenHash) {
			await db.prepare('UPDATE magic_tokens SET used = 1 WHERE token_hash = ?').bind(tokenHash).run();
		},
		async bumpCodeAttempts(tokenHash) {
			await db
				.prepare('UPDATE magic_tokens SET code_attempts = code_attempts + 1 WHERE token_hash = ?')
				.bind(tokenHash)
				.run();
		},
		async deleteMagicToken(tokenHash) {
			await db.prepare('DELETE FROM magic_tokens WHERE token_hash = ?').bind(tokenHash).run();
		},
		async insertSession(s) {
			await db
				.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
				.bind(s.token_hash, s.user_id, s.expires_at)
				.run();
		},
		async findSessionUser(tokenHash, now) {
			return db
				.prepare(
					'SELECT s.user_id AS id, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?'
				)
				.bind(tokenHash, now)
				.first<AccountUser>();
		},
		async deleteSession(tokenHash) {
			await db.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run();
		},
		async getRate(key) {
			return db
				.prepare('SELECT count, window_start FROM rate_limits WHERE key = ?')
				.bind(key)
				.first<RateRow>();
		},
		async resetRate(key, now) {
			await db
				.prepare('INSERT OR REPLACE INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)')
				.bind(key, now)
				.run();
		},
		async bumpRate(key) {
			await db.prepare('UPDATE rate_limits SET count = count + 1 WHERE key = ?').bind(key).run();
		}
	};
}
