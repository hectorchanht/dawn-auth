// DawnAuthClient over a fake fetch: boot probe, requestLink (ok + retry + diag),
// verify / verifyCode / Google, the native bearer seam, and logout.
import { describe, expect, it, vi } from 'vitest';
import { DawnAuthClient } from '../src/index.js';

type Handler = (path: string, init: RequestInit) => Response | Promise<Response>;

function fakeFetch(handler: Handler): typeof fetch {
	return (async (url: string | URL | Request, init?: RequestInit) => {
		const u = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
		const path = new URL(u, 'https://base/').pathname;
		return handler(path, init ?? {});
	}) as typeof fetch;
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'content-type': 'application/json', ...headers }
	});
}

const USER = { id: 'u1', email: 'a@b.co' };
const BEARER = 'e'.repeat(64);

function memStorage() {
	const m = new Map<string, string>();
	return {
		getItem: (k: string) => m.get(k) ?? null,
		setItem: (k: string, v: string) => m.set(k, v),
		removeItem: (k: string) => void m.delete(k)
	};
}

describe('DawnAuthClient', () => {
	it('load() probes the session and emits', async () => {
		const seen: string[] = [];
		const client = new DawnAuthClient({
			fetchImpl: fakeFetch((p) => {
				seen.push(p);
				return json({ user: USER });
			})
		});
		const snaps: unknown[] = [];
		client.subscribe((s) => snaps.push({ ...s }));
		await client.load();
		expect(client.user).toEqual(USER);
		expect(client.ready).toBe(true);
		expect(seen).toEqual(['/api/auth/session']);
		expect(snaps.length).toBeGreaterThan(0);
		// idempotent
		await client.load();
		expect(seen.length).toBe(1);
	});

	it('requestLink returns ok and maps server errors', async () => {
		const okClient = new DawnAuthClient({ fetchImpl: fakeFetch(() => json({ ok: true })) });
		expect(await okClient.requestLink('a@b.co')).toBe('ok');
		expect(await okClient.requestLink('bad')).toBe('invalid-email');

		const rlClient = new DawnAuthClient({
			fetchImpl: fakeFetch(() => json({ ok: false, err: 'rate-limited' }, 429))
		});
		expect(await rlClient.requestLink('a@b.co')).toBe('rate-limited');
	});

	it('requestLink retries once on network failure, then reports network + diag', async () => {
		const paths: string[] = [];
		const client = new DawnAuthClient({
			fetchImpl: fakeFetch((p) => {
				paths.push(p);
				throw new TypeError('Failed to fetch');
			})
		});
		const r = await client.requestLink('a@b.co');
		expect(r).toBe('network');
		// 2 POST attempts + 1 differential probe
		expect(paths).toEqual(['/api/auth/magic-link', '/api/auth/magic-link', '/api/auth/session']);
		expect(client.lastLinkDiag).toContain('attempt 1: TypeError: Failed to fetch');
		expect(client.lastLinkDiag).toContain('attempt 2: TypeError: Failed to fetch');
		expect(client.lastLinkDiag).toContain('probe: TypeError');
	});

	it('requestLink never retries a server 4xx/5xx', async () => {
		let calls = 0;
		const client = new DawnAuthClient({
			fetchImpl: fakeFetch(() => {
				calls++;
				return json({ ok: false, err: 'send-failed' }, 500);
			})
		});
		expect(await client.requestLink('a@b.co')).toBe('send-failed');
		expect(calls).toBe(1);
	});

	it('verify() establishes the session; web ignores the token body', async () => {
		const storage = memStorage();
		const client = new DawnAuthClient({
			storage,
			fetchImpl: fakeFetch((p) => {
				if (p === '/api/auth/verify') return json({ user: USER, token: BEARER, scheme: null });
				return json({ user: null });
			})
		});
		const r = await client.verify('f'.repeat(64));
		expect(r).toEqual({ ok: true, scheme: null, token: BEARER });
		expect(client.user).toEqual(USER);
		// web: nothing persisted
		expect(storage.getItem('dawn:auth-token:v1')).toBeNull();
	});

	it('native: bearer is persisted and sent as Authorization', async () => {
		const storage = memStorage();
		const seenAuth: (string | null)[] = [];
		const client = new DawnAuthClient({
			isNative: true,
			storage,
			fetchImpl: fakeFetch((p, init) => {
				seenAuth.push(new Headers(init.headers).get('authorization'));
				if (p === '/api/auth/verify') return json({ user: USER, token: BEARER, scheme: 'testapp://' });
				return json({ user: USER });
			})
		});
		const r = await client.verify('f'.repeat(64));
		expect(r.scheme).toBe('testapp://');
		expect(storage.getItem('dawn:auth-token:v1')).toContain(BEARER);
		// next authed call carries the bearer
		await client.load();
		expect(seenAuth[seenAuth.length - 1]).toBe(`Bearer ${BEARER}`);
	});

	it('adoptNativeToken validates the shape and drops unknown bearers', async () => {
		const client = new DawnAuthClient({
			isNative: true,
			storage: memStorage(),
			fetchImpl: fakeFetch(() => json({ user: null }))
		});
		expect(await client.adoptNativeToken('short')).toBe(false);
		expect(await client.adoptNativeToken(BEARER)).toBe(false); // server doesn't know it
		expect(client.user).toBeNull();
	});

	it('verifyCode + signInWithGoogle establish the session', async () => {
		const client = new DawnAuthClient({
			fetchImpl: fakeFetch((p) => {
				if (p === '/api/auth/verify-code') return json({ user: USER, token: null });
				if (p === '/api/auth/google') return json({ user: USER, token: null, scheme: null });
				return json({ user: null });
			})
		});
		expect(await client.verifyCode('a@b.co', '123456')).toBe('ok');
		expect(client.user).toEqual(USER);
		await client.logout();
		expect(client.user).toBeNull();
		const g = await client.signInWithGoogle('id-token');
		expect(g.ok).toBe(true);
	});

	it('verifyCode maps too-many-attempts and 429', async () => {
		const mk = (status: number, err: string) =>
			new DawnAuthClient({ fetchImpl: fakeFetch(() => json({ ok: false, err }, status)) });
		expect(await mk(401, 'too-many-attempts').verifyCode('a@b.co', '123456')).toBe('too-many-attempts');
		expect(await mk(429, 'rate-limited').verifyCode('a@b.co', '123456')).toBe('rate-limited');
		expect(await mk(401, 'invalid-code').verifyCode('a@b.co', '123456')).toBe('invalid-code');
		expect(await mk(500, 'x').verifyCode('a@b.co', '12')).toBe('invalid'); // client-side shape
	});

	it('logout calls the server best-effort and clears state', async () => {
		const logoutCalls: string[] = [];
		const client = new DawnAuthClient({
			fetchImpl: fakeFetch((p) => {
				logoutCalls.push(p);
				if (p === '/api/auth/logout') throw new TypeError('down');
				return json({ user: USER });
			})
		});
		await client.load();
		await client.logout(); // server threw — local sign-out still applies
		expect(client.user).toBeNull();
		expect(logoutCalls).toContain('/api/auth/logout');
	});

	it('onNativeGoogleSignOut hook runs on native logout', async () => {
		const hook = vi.fn(async () => {});
		const client = new DawnAuthClient({
			isNative: true,
			storage: memStorage(),
			onNativeGoogleSignOut: hook,
			fetchImpl: fakeFetch(() => json({ ok: true }))
		});
		await client.logout();
		expect(hook).toHaveBeenCalledTimes(1);
	});
});
