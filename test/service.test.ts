// End-to-end service flows over the in-memory store: the three sign-in paths,
// session management, rate limits, and the two-credentials-one-intent rule.
import { beforeAll, describe, expect, it } from 'vitest';
import {
	defineAuth,
	requestMagicLink,
	verifyMagicToken,
	verifyCode,
	signInWithGoogle,
	getSessionUser,
	destroySession,
	sessionCookie,
	sha256hex,
	type ResolvedAuthConfig
} from '../src/index.js';
import { memStore, captureMailer, req } from './helpers.js';

function testCfg(over: Record<string, unknown> = {}): ResolvedAuthConfig {
	return defineAuth({
		appName: 'TestApp',
		domain: 'testapp.lol',
		from: 'TestApp <login@testapp.lol>',
		resendApiKey: 're_test_key',
		googleClientId: 'test-client-id.apps.googleusercontent.com',
		cookieName: 'testapp_session',
		nativeSchemes: ['testapp://'],
		...over
	});
}

describe('defineAuth', () => {
	it('throws without a from (fail closed at boot)', () => {
		expect(() => defineAuth({ appName: 'X', domain: 'x.lol', from: '' })).toThrow();
	});
	it('derives the cookie name from the app name', () => {
		expect(defineAuth({ appName: 'Clip Bin', domain: 'c.lol', from: 'C <l@c.lol>' }).cookieName).toBe(
			'clipbin_session'
		);
	});
});

describe('requestMagicLink', () => {
	it('rejects a bad email before anything else', async () => {
		const store = memStore();
		const captured: Record<string, string> = {};
		const cfg = testCfg({ mailer: captureMailer(captured) });
		expect(await requestMagicLink(store, cfg, { email: 'nope', origin: 'https://t.lol', ip: '1.1.1.1' })).toBe(
			'invalid-email'
		);
		expect(store.tokens.size).toBe(0);
	});

	it('rejects a non-allowlisted scheme', async () => {
		const store = memStore();
		const cfg = testCfg();
		expect(
			await requestMagicLink(store, cfg, { email: 'a@b.co', scheme: 'evil://', origin: 'https://t.lol', ip: '1.1.1.1' })
		).toBe('invalid-scheme');
	});

	it('fails closed without a resend key and mints nothing', async () => {
		const store = memStore();
		const cfg = testCfg({ resendApiKey: undefined });
		expect(await requestMagicLink(store, cfg, { email: 'a@b.co', origin: 'https://t.lol', ip: '1.1.1.1' })).toBe(
			'not-configured'
		);
		expect(store.tokens.size).toBe(0);
	});

	it('mints the intent and emails the code + link', async () => {
		const store = memStore();
		const captured: { code?: string; link?: string } = {};
		const cfg = testCfg({ mailer: captureMailer(captured) });
		const r = await requestMagicLink(store, cfg, {
			email: 'A@B.co',
			scheme: 'testapp://',
			origin: 'https://t.lol',
			ip: '1.1.1.1'
		});
		expect(r).toBe('ok');
		expect(store.tokens.size).toBe(1);
		const row = [...store.tokens.values()][0]!;
		expect(row.email).toBe('a@b.co'); // normalized
		expect(row.scheme).toBe('testapp://');
		expect(row.code_hash).toMatch(/^[0-9a-f]{64}$/);
		expect(row.token_hash).toMatch(/^[0-9a-f]{64}$/);
		expect(captured.code).toMatch(/^\d{6}$/);
		expect(captured.link).toContain('https://t.lol/auth/magic?token=');
	});

	it('deletes the row when the send fails', async () => {
		const store = memStore();
		const cfg = testCfg({ mailer: async () => false });
		const r = await requestMagicLink(store, cfg, { email: 'a@b.co', origin: 'https://t.lol', ip: '1.1.1.1' });
		expect(r).toBe('send-failed');
		expect(store.tokens.size).toBe(0);
	});

	it('rate-limits at 3 per email per 10 min', async () => {
		const store = memStore();
		const captured: Record<string, string> = {};
		const cfg = testCfg({ mailer: captureMailer(captured) });
		const input = { email: 'a@b.co', origin: 'https://t.lol', ip: '1.1.1.1' };
		expect(await requestMagicLink(store, cfg, input)).toBe('ok');
		expect(await requestMagicLink(store, cfg, input)).toBe('ok');
		expect(await requestMagicLink(store, cfg, input)).toBe('ok');
		expect(await requestMagicLink(store, cfg, input)).toBe('rate-limited');
	});
});

describe('verifyMagicToken', () => {
	async function minted(scheme?: string) {
		const store = memStore();
		const captured: { link?: string } = {};
		const cfg = testCfg({ mailer: captureMailer(captured) });
		await requestMagicLink(store, cfg, {
			email: 'a@b.co',
			...(scheme ? { scheme } : {}),
			origin: 'https://t.lol',
			ip: '1.1.1.1'
		});
		const token = captured.link!.split('token=')[1]!;
		return { store, cfg, token };
	}

	it('redeems the link: user + session token + scheme', async () => {
		const { store, cfg, token } = await minted('testapp://');
		const r = await verifyMagicToken(store, cfg, token);
		expect(r.ok).toBe(true);
		if (r.ok) {
			expect(r.user.email).toBe('a@b.co');
			expect(r.sessionToken).toMatch(/^[0-9a-f]{64}$/);
			expect(r.scheme).toBe('testapp://');
			// the session resolves back to the user
			const hash = await sha256hex('session:' + r.sessionToken);
			expect(await store.findSessionUser(hash, Date.now())).toEqual(r.user);
		}
	});

	it('is single-use and refuses unknown/expired with one shape', async () => {
		const { store, cfg, token } = await minted();
		expect((await verifyMagicToken(store, cfg, token)).ok).toBe(true);
		expect(await verifyMagicToken(store, cfg, token)).toEqual({ ok: false, reason: 'invalid-token' });
		expect(await verifyMagicToken(store, cfg, 'f'.repeat(64))).toEqual({ ok: false, reason: 'invalid-token' });
		expect(await verifyMagicToken(store, cfg, 'short')).toEqual({ ok: false, reason: 'invalid-token' });
	});
});

describe('verifyCode', () => {
	async function minted() {
		const store = memStore();
		const captured: { code?: string } = {};
		const cfg = testCfg({ mailer: captureMailer(captured) });
		await requestMagicLink(store, cfg, { email: 'a@b.co', origin: 'https://t.lol', ip: '9.9.9.9' });
		return { store, cfg, code: captured.code! };
	}

	it('redeems the code and burns the link with it', async () => {
		const { store, cfg, code } = await minted();
		const r = await verifyCode(store, cfg, { email: 'a@b.co', code, ip: '9.9.9.9' });
		expect(r.ok).toBe(true);
		if (r.ok) expect(r.user.email).toBe('a@b.co');
		// the intent is burned — a second code attempt fails
		expect(await verifyCode(store, cfg, { email: 'a@b.co', code, ip: '9.9.9.9' })).toEqual({
			ok: false,
			result: 'invalid-code'
		});
	});

	it('wrong guesses bump attempts; the 5th kills the code', async () => {
		const { store, cfg, code } = await minted();
		for (let i = 0; i < 5; i++) {
			expect(await verifyCode(store, cfg, { email: 'a@b.co', code: '000000', ip: '9.9.9.9' })).toEqual({
				ok: false,
				result: 'invalid-code'
			});
		}
		// the code is now dead — even the right code is refused as too-many-attempts
		expect(await verifyCode(store, cfg, { email: 'a@b.co', code, ip: '9.9.9.9' })).toEqual({
			ok: false,
			result: 'too-many-attempts'
		});
	});

	it('rejects malformed shapes without touching the store', async () => {
		const { store, cfg } = await minted();
		expect(await verifyCode(store, cfg, { email: 'bad', code: '123456', ip: '1.1.1.1' })).toEqual({
			ok: false,
			result: 'invalid'
		});
		expect(await verifyCode(store, cfg, { email: 'a@b.co', code: '12', ip: '1.1.1.1' })).toEqual({
			ok: false,
			result: 'invalid'
		});
	});
});

describe('signInWithGoogle', () => {
	let keyPair: CryptoKeyPair;
	let jwk: { kid?: string } & Record<string, unknown>;
	const KID = 'k1';
	const b64url = (s: string) => Buffer.from(s, 'utf8').toString('base64url');

	beforeAll(async () => {
		keyPair = await crypto.subtle.generateKey(
			{ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
			true,
			['sign', 'verify']
		);
		jwk = { ...(await crypto.subtle.exportKey('jwk', keyPair.publicKey)), kid: KID };
	});

	async function mintIdToken(email: string): Promise<string> {
		const nowSec = Math.floor(Date.now() / 1000);
		const hb = b64url(JSON.stringify({ alg: 'RS256', kid: KID, typ: 'JWT' }));
		const pb = b64url(
			JSON.stringify({
				iss: 'accounts.google.com',
				aud: 'test-client-id.apps.googleusercontent.com',
				exp: nowSec + 3600,
				iat: nowSec,
				email,
				email_verified: true,
				sub: '1'
			})
		);
		const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', keyPair.privateKey, new TextEncoder().encode(`${hb}.${pb}`));
		return `${hb}.${pb}.${Buffer.from(new Uint8Array(sig)).toString('base64url')}`;
	}

	const fetchCerts = async () => ({ keys: [jwk] });

	it('signs in and upserts by email (one user across Google + magic link)', async () => {
		const store = memStore();
		const cfg = testCfg();
		// magic-link first
		const captured: { link?: string } = {};
		const cfgMail = testCfg({ mailer: captureMailer(captured) });
		await requestMagicLink(store, cfgMail, { email: 'same@x.co', origin: 'https://t.lol', ip: '1.1.1.1' });
		const magicUser = (await verifyMagicToken(store, cfg, captured.link!.split('token=')[1]!)) as { ok: true; user: { id: string } };
		// then Google with the same email
		const g = await signInWithGoogle(store, cfg, {
			idToken: await mintIdToken('same@x.co'),
			ip: '2.2.2.2',
			fetchCerts
		});
		expect(g.ok).toBe(true);
		if (g.ok) {
			expect(g.user.id).toBe(magicUser.user.id); // ONE user row
			expect(g.scheme).toBeNull();
		}
	});

	it('refuses a bad token with one shape', async () => {
		const store = memStore();
		const cfg = testCfg();
		expect(await signInWithGoogle(store, cfg, { idToken: 'junk', ip: '1.1.1.1', fetchCerts })).toEqual({
			ok: false,
			reason: 'invalid-token'
		});
	});

	it('fails closed without a google client id', async () => {
		const store = memStore();
		const cfg = testCfg({ googleClientId: undefined });
		expect(await signInWithGoogle(store, cfg, { idToken: 'x.y.z', ip: '1.1.1.1', fetchCerts })).toEqual({
			ok: false,
			reason: 'not-configured'
		});
	});
});

describe('sessions', () => {
	it('getSessionUser reads the cookie; destroySession clears it', async () => {
		const store = memStore();
		const cfg = testCfg();
		const captured: { link?: string } = {};
		await requestMagicLink(store, testCfg({ mailer: captureMailer(captured) }), {
			email: 'a@b.co',
			origin: 'https://t.lol',
			ip: '1.1.1.1'
		});
		const v = await verifyMagicToken(store, cfg, captured.link!.split('token=')[1]!);
		if (!v.ok) throw new Error('setup failed');
		const cookie = sessionCookie(v.sessionToken, cfg);
		const setVal = cookie.split(';')[0]!;

		const authed = req('https://t.lol/', { headers: { cookie: setVal } });
		expect(await getSessionUser(store, cfg, authed)).toEqual(v.user);
		expect(await getSessionUser(store, cfg, req('https://t.lol/'))).toBeNull();

		// bearer also works (native seam)
		const viaBearer = req('https://t.lol/', { headers: { authorization: `Bearer ${v.sessionToken}` } });
		expect(await getSessionUser(store, cfg, viaBearer)).toEqual(v.user);

		const { clearCookie } = await destroySession(store, cfg, authed);
		expect(clearCookie).toContain('Max-Age=0');
		expect(await getSessionUser(store, cfg, authed)).toBeNull();
	});
});
