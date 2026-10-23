// v0.2.0: max-config knobs — codeLength, maxCodeAttempts, cookie attrs, email copy,
// onEvent lifecycle, client timeouts/codeLength.
import { describe, expect, it } from 'vitest';
import {
	defineAuth,
	buildSignInEmail,
	buildSessionCookie,
	clearSessionCookie,
	codeRe,
	randomCode,
	ttlText,
	requestMagicLink,
	verifyCode,
	verifyMagicToken,
	destroySession,
	DawnAuthClient,
	type AuthEvent,
	type ResolvedAuthConfig
} from '../src/index.js';
import { memStore, req } from './helpers.js';

function testCfg(over: Record<string, unknown> = {}): ResolvedAuthConfig {
	return defineAuth({
		appName: 'TestApp',
		domain: 'testapp.lol',
		from: 'TestApp <login@testapp.lol>',
		resendApiKey: 're_test_key',
		googleClientId: 'test-client-id.apps.googleusercontent.com',
		...over
	});
}

function capture(captured: { code?: string; subject?: string }) {
	return async (msg: { from: string; to: string; subject: string; html: string; text: string }) => {
		captured.subject = msg.subject;
		const m = msg.text.match(/Sign-in code: (\d+)/);
		if (m?.[1]) captured.code = m[1];
		return true;
	};
}

describe('defineAuth validation', () => {
	it('defaults: codeLength 6, maxCodeAttempts 5, secure cookie attrs', () => {
		const cfg = testCfg();
		expect(cfg.codeLength).toBe(6);
		expect(cfg.maxCodeAttempts).toBe(5);
		expect(cfg.cookie).toEqual({ sameSite: 'Lax', secure: true, path: '/', domain: undefined, httpOnly: true });
		expect(cfg.googleCertsTtlMs).toBe(3600000);
	});
	it('rejects bad codeLength / maxCodeAttempts / sameSite at boot', () => {
		expect(() => testCfg({ codeLength: 3 })).toThrow();
		expect(() => testCfg({ codeLength: 10 })).toThrow();
		expect(() => testCfg({ codeLength: 6.5 })).toThrow();
		expect(() => testCfg({ maxCodeAttempts: 0 })).toThrow();
		expect(() => testCfg({ cookie: { sameSite: 'Bogus' } })).toThrow();
	});
	it('accepts custom cookie attrs + codeLength', () => {
		const cfg = testCfg({ codeLength: 8, cookie: { sameSite: 'Strict', domain: '.testapp.lol' } });
		expect(cfg.codeLength).toBe(8);
		expect(cfg.cookie.sameSite).toBe('Strict');
		expect(cfg.cookie.domain).toBe('.testapp.lol');
		expect(cfg.cookie.secure).toBe(true); // untouched default
	});
});

describe('code length primitives', () => {
	it('codeRe matches the configured length only', () => {
		expect(codeRe(8).test('12345678')).toBe(true);
		expect(codeRe(8).test('123456')).toBe(false);
		expect(codeRe(4).test('1234')).toBe(true);
	});
	it('randomCode honors the length', () => {
		for (const n of [4, 6, 8, 9]) {
			const c = randomCode(n);
			expect(c).toHaveLength(n);
			expect(codeRe(n).test(c)).toBe(true);
		}
	});
});

describe('session cookie attrs', () => {
	it('default stays the secure posture', () => {
		const c = buildSessionCookie('tok', 's');
		expect(c).toContain('HttpOnly');
		expect(c).toContain('Secure');
		expect(c).toContain('SameSite=Lax');
		expect(c).toContain('Path=/');
	});
	it('custom attrs are honored', () => {
		const c = buildSessionCookie('tok', 's', 60, {
			sameSite: 'Strict',
			secure: false,
			path: '/app',
			domain: '.testapp.lol',
			httpOnly: false
		});
		expect(c).toContain('SameSite=Strict');
		expect(c).toContain('Path=/app');
		expect(c).toContain('Domain=.testapp.lol');
		expect(c).toContain('Max-Age=60');
		expect(c).not.toContain('Secure');
		expect(c).not.toContain('HttpOnly');
	});
	it('clear mirrors path/domain so the clear actually overwrites', () => {
		const c = clearSessionCookie('s', { path: '/app', domain: '.testapp.lol' });
		expect(c).toContain('Path=/app');
		expect(c).toContain('Domain=.testapp.lol');
		expect(c).toContain('Max-Age=0');
	});
});

describe('email copy overrides', () => {
	const P = {
		appName: 'Clipbin',
		domain: 'clipbin.lol',
		brandColor: '#00c2b8',
		link: 'https://clipbin.lol/auth/magic?token=abc',
		code: '123456',
		toEmail: 'user@example.com'
	};
	it('defaults keep the house copy (back-compat)', () => {
		const { subject } = buildSignInEmail(P);
		expect(subject).toBe('Use code 123456 to sign in to Clipbin');
	});
	it('subject + body fields are overridable with placeholders', () => {
		const { subject, html, text } = buildSignInEmail({
			...P,
			copy: { subject: '登入碼 {code} — {app}', greeting: '你好，' }
		});
		expect(subject).toBe('登入碼 123456 — Clipbin');
		expect(html).toContain('你好，');
		expect(text).toContain('你好，');
	});
	it('{ttl} and {attempts} derive from config', () => {
		const { html } = buildSignInEmail({ ...P, ttlMs: 3600000, maxAttempts: 3 });
		expect(html).toContain('1 hour');
		expect(html).toContain('3 wrong tries');
	});
	it('ttlText formats minutes/hours/days', () => {
		expect(ttlText(15 * 60000)).toBe('15 minutes');
		expect(ttlText(3600000)).toBe('1 hour');
		expect(ttlText(2 * 3600000)).toBe('2 hours');
		expect(ttlText(30 * 86400000)).toBe('30 days');
	});
});

describe('service honors the knobs', () => {
	it('maxCodeAttempts=2 kills the code after 2 wrong guesses', async () => {
		const store = memStore();
		const captured: { code?: string } = {};
		const cfg = testCfg({ mailer: capture(captured), maxCodeAttempts: 2 });
		expect(await requestMagicLink(store, cfg, { email: 'a@b.co', origin: 'https://t.lol', ip: '1.1.1.1' })).toBe('ok');
		expect(await verifyCode(store, cfg, { email: 'a@b.co', code: '000000', ip: '1.1.1.1' })).toEqual({
			ok: false,
			result: 'invalid-code'
		});
		expect(await verifyCode(store, cfg, { email: 'a@b.co', code: '000000', ip: '1.1.1.1' })).toEqual({
			ok: false,
			result: 'invalid-code'
		});
		// 3rd attempt: the code is dead even with the right code
		expect(await verifyCode(store, cfg, { email: 'a@b.co', code: captured.code!, ip: '1.1.1.1' })).toEqual({
			ok: false,
			result: 'too-many-attempts'
		});
	});
	it('codeLength=8 mints and accepts 8-digit codes', async () => {
		const store = memStore();
		const captured: { code?: string } = {};
		const cfg = testCfg({ mailer: capture(captured), codeLength: 8 });
		expect(await requestMagicLink(store, cfg, { email: 'a@b.co', origin: 'https://t.lol', ip: '1.1.1.1' })).toBe('ok');
		expect(captured.code).toHaveLength(8);
		// a 6-digit guess fails the SHAPE check (never reaches the store)
		expect(await verifyCode(store, cfg, { email: 'a@b.co', code: '123456', ip: '1.1.1.1' })).toEqual({
			ok: false,
			result: 'invalid'
		});
		const r = await verifyCode(store, cfg, { email: 'a@b.co', code: captured.code!, ip: '1.1.1.1' });
		expect(r.ok).toBe(true);
	});
	it('email carries the configured copy + derived ttl/attempts', async () => {
		const store = memStore();
		const captured: { subject?: string; code?: string } = {};
		const cfg = testCfg({
			mailer: capture(captured),
			emailCopy: { subject: '你的登入碼 {code}' },
			magicLinkTtlMs: 3600000,
			maxCodeAttempts: 3
		});
		await requestMagicLink(store, cfg, { email: 'a@b.co', origin: 'https://t.lol', ip: '1.1.1.1' });
		expect(captured.subject).toBe(`你的登入碼 ${captured.code}`);
	});
	it('onEvent fires across the lifecycle and never breaks auth', async () => {
		const events: AuthEvent[] = [];
		const store = memStore();
		const captured: { code?: string } = {};
		const cfg = testCfg({
			mailer: capture(captured),
			onEvent: (e) => {
				events.push(e);
				if (e.type === 'link.requested') throw new Error('listener bug must not break auth');
			}
		});
		expect(await requestMagicLink(store, cfg, { email: 'bad', origin: 'https://t.lol', ip: '1.1.1.1' })).toBe(
			'invalid-email'
		);
		expect(await requestMagicLink(store, cfg, { email: 'a@b.co', origin: 'https://t.lol', ip: '1.1.1.1' })).toBe('ok');
		const vr = await verifyCode(store, cfg, { email: 'a@b.co', code: '000000', ip: '1.1.1.1' });
		expect(vr).toEqual({ ok: false, result: 'invalid-code' });
		const ok = await verifyCode(store, cfg, { email: 'a@b.co', code: captured.code!, ip: '1.1.1.1' });
		expect(ok.ok).toBe(true);
		if (ok.ok) {
			await destroySession(
				store,
				cfg,
				req('https://t.lol/', { headers: { cookie: `${cfg.cookieName}=${ok.sessionToken}` } })
			);
		}
		const types = events.map((e) => e.type);
		expect(types).toEqual([
			'link.failed',
			'link.requested',
			'code.failed',
			'code.verified',
			'session.destroyed'
		]);
	});
	it('onEvent fires link.verified for the magic-link path', async () => {
		const events: AuthEvent[] = [];
		const store = memStore();
		const captured: { link?: string } = {};
		const cfg = testCfg({
			mailer: async (msg: { text: string }) => {
				const l = msg.text.match(/https?:\/\/\S+/);
				if (l?.[0]) captured.link = l[0];
				return true;
			},
			onEvent: (e) => events.push(e)
		});
		await requestMagicLink(store, cfg, { email: 'a@b.co', origin: 'https://t.lol', ip: '1.1.1.1' });
		const token = new URL(captured.link!).searchParams.get('token')!;
		const r = await verifyMagicToken(store, cfg, token);
		expect(r.ok).toBe(true);
		expect(events.map((e) => e.type)).toContain('link.verified');
	});
});

describe('DawnAuthClient honors codeLength', () => {
	function fakeFetch(handler: (path: string) => Response): typeof fetch {
		return (async (url: string | URL | Request) => {
			const u = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
			return handler(new URL(u, 'https://base/').pathname);
		}) as typeof fetch;
	}
	const json = (body: unknown, status = 200) =>
		new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

	it('default client rejects a non-6-digit code as invalid', async () => {
		const c = new DawnAuthClient({ fetchImpl: fakeFetch(() => json({ ok: false, err: 'invalid-code' }, 400)) });
		expect(await c.verifyCode('a@b.co', '12345678')).toBe('invalid');
	});
	it('codeLength=8 passes an 8-digit code through to the server', async () => {
		const seen: string[] = [];
		const c = new DawnAuthClient({
			codeLength: 8,
			fetchImpl: ((async (url: string | URL | Request, init?: RequestInit) => {
				const u = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
				seen.push(`${new URL(u, 'https://base/').pathname}:${init?.body ?? ''}`);
				return json({ user: { id: 'u1', email: 'a@b.co' }, token: null });
			}) as typeof fetch)
		});
		expect(await c.verifyCode('a@b.co', '12345678')).toBe('ok');
		expect(seen[0]).toContain('"code":"12345678"');
	});
});
