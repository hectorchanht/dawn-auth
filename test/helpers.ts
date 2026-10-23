// In-memory AuthStore for tests — Map semantics, no SQL.
import type { AccountUser } from '../src/core.js';
import type { AuthStore, MagicTokenRow, RateRow, SessionInsert } from '../src/store.js';

export function memStore(): AuthStore & {
	users: Map<string, AccountUser>;
	tokens: Map<string, MagicTokenRow>;
	sessions: Map<string, { user_id: string; expires_at: number }>;
	rates: Map<string, RateRow>;
	lastCode: { email: string; code: string } | null;
} {
	const users = new Map<string, AccountUser>();
	const tokens = new Map<string, MagicTokenRow>();
	const sessions = new Map<string, { user_id: string; expires_at: number }>();
	const rates = new Map<string, RateRow>();
	let n = 0;
	const store: AuthStore = {
		async findUserByEmail(email) {
			for (const u of users.values()) if (u.email === email) return u;
			return null;
		},
		async createUser(email) {
			const u = { id: `u${++n}`, email };
			users.set(u.id, u);
			return u;
		},
		async insertMagicToken(row) {
			tokens.set(row.token_hash, { ...row, used: 0, code_attempts: 0 });
		},
		async findMagicToken(tokenHash) {
			return tokens.get(tokenHash) ?? null;
		},
		async findLiveMagicTokenByEmail(email, now) {
			let best: MagicTokenRow | null = null;
			for (const t of tokens.values()) {
				if (t.email === email && !t.used && t.expires_at > now) best = t;
			}
			return best;
		},
		async burnMagicToken(tokenHash) {
			const t = tokens.get(tokenHash);
			if (t) t.used = 1;
		},
		async bumpCodeAttempts(tokenHash) {
			const t = tokens.get(tokenHash);
			if (t) t.code_attempts++;
		},
		async deleteMagicToken(tokenHash) {
			tokens.delete(tokenHash);
		},
		async insertSession(s: SessionInsert) {
			sessions.set(s.token_hash, { user_id: s.user_id, expires_at: s.expires_at });
		},
		async findSessionUser(tokenHash, now) {
			const s = sessions.get(tokenHash);
			if (!s || s.expires_at <= now) return null;
			return users.get(s.user_id) ?? null;
		},
		async deleteSession(tokenHash) {
			sessions.delete(tokenHash);
		},
		async getRate(key) {
			return rates.get(key) ?? null;
		},
		async resetRate(key, now) {
			rates.set(key, { count: 1, window_start: now });
		},
		async bumpRate(key) {
			const r = rates.get(key);
			if (r) r.count++;
		}
	};
	return Object.assign(store, { users, tokens, sessions, rates, lastCode: null });
}

/** A mailer stand-in that captures the sent code/link instead of sending. */
export function captureMailer(captured: { code?: string; link?: string; subject?: string; to?: string }) {
	return async (msg: { from: string; to: string; subject: string; html: string; text: string }) => {
		captured.to = msg.to;
		captured.subject = msg.subject;
		const m = msg.text.match(/Sign-in code: (\d{6})/);
		if (m?.[1]) captured.code = m[1];
		const l = msg.text.match(/https?:\/\/\S+/);
		if (l?.[0]) captured.link = l[0];
		return true;
	};
}

export function req(url = 'https://app.test/', init: RequestInit = {}): Request {
	return new Request(url, init);
}
