// Ported from OpenMusic's src/lib/auth/auth-core.test.ts — the pure primitives.
import { describe, expect, it } from 'vitest';
import {
	TOKEN_RE,
	CODE_RE,
	MAX_CODE_ATTEMPTS,
	buildAuthCallbackUrl,
	buildSessionCookie,
	clearSessionCookie,
	getAuthToken,
	getBearerToken,
	getSessionTokenFromCookie,
	isAllowedScheme,
	isValidEmail,
	parseAuthCallbackUrl,
	randomCode,
	randomToken,
	sha256hex,
	sha256hexN,
	timingSafeEqual,
	diagLine,
	escapeHtml
} from '../src/index.js';
import { rateLimit } from '../src/index.js';
import { memStore } from './helpers.js';

const COOKIE = 'testapp_session';

describe('tokens', () => {
	it('randomToken is 64 lowercase hex', () => {
		const t = randomToken();
		expect(t).toMatch(TOKEN_RE);
		expect(new Set([randomToken(), randomToken(), randomToken()]).size).toBe(3);
	});

	it('randomCode is 6 digits in 100000–999999', () => {
		for (let i = 0; i < 50; i++) {
			const c = randomCode();
			expect(c).toMatch(CODE_RE);
			expect(Number(c)).toBeGreaterThanOrEqual(100000);
		}
	});

	it('sha256hex is stable hex', async () => {
		const h = await sha256hex('magic:abc');
		expect(h).toMatch(/^[0-9a-f]{64}$/);
		expect(await sha256hex('magic:abc')).toBe(h);
		expect(await sha256hex('magic:abd')).not.toBe(h);
	});

	it('sha256hexN truncates', async () => {
		expect(await sha256hexN('x', 8)).toBe((await sha256hex('x')).slice(0, 8));
	});

	it('timingSafeEqual', () => {
		expect(timingSafeEqual('abc', 'abc')).toBe(true);
		expect(timingSafeEqual('abc', 'abd')).toBe(false);
		expect(timingSafeEqual('abc', 'abcd')).toBe(false);
	});
});

describe('email screen', () => {
	it('accepts normal + tagged addresses', () => {
		expect(isValidEmail('a@b.co')).toBe(true);
		expect(isValidEmail('a+b@b.co')).toBe(true);
		expect(isValidEmail('not-an-email')).toBe(false);
		expect(isValidEmail('a@b')).toBe(false);
	});
});

describe('scheme allowlist', () => {
	it('exact match only', () => {
		expect(isAllowedScheme('myapp://', ['myapp://'])).toBe(true);
		expect(isAllowedScheme('myapp://', [])).toBe(false);
		expect(isAllowedScheme('javascript:', ['myapp://'])).toBe(false);
		expect(isAllowedScheme('myapp://evil', ['myapp://'])).toBe(false);
		expect(isAllowedScheme(undefined, ['myapp://'])).toBe(false);
	});
});

describe('cookies + bearer', () => {
	it('builds and clears the session cookie', () => {
		const set = buildSessionCookie('tok', COOKIE);
		expect(set).toContain(`${COOKIE}=tok`);
		expect(set).toContain('HttpOnly');
		expect(set).toContain('Max-Age=2592000');
		expect(clearSessionCookie(COOKIE)).toContain('Max-Age=0');
	});

	it('extracts the token from cookie or bearer, cookie first', () => {
		const hex = 'a'.repeat(64);
		const fromCookie = new Request('https://x/', {
			headers: { cookie: `${COOKIE}=${hex}; other=1`, authorization: `Bearer ${'b'.repeat(64)}` }
		});
		expect(getSessionTokenFromCookie(fromCookie, COOKIE)).toBe(hex);
		expect(getAuthToken(fromCookie, COOKIE)).toBe(hex); // cookie wins

		const bearerOnly = new Request('https://x/', { headers: { authorization: 'Bearer ' + 'c'.repeat(64) } });
		expect(getBearerToken(bearerOnly)).toBe('c'.repeat(64));
		expect(getAuthToken(bearerOnly, COOKIE)).toBe('c'.repeat(64));

		const junk = new Request('https://x/', { headers: { authorization: 'Bearer nope' } });
		expect(getAuthToken(junk, COOKIE)).toBeNull();
		expect(getAuthToken(new Request('https://x/'), COOKIE)).toBeNull();
	});
});

describe('deep links', () => {
	it('builds and parses the auth callback URL', () => {
		const token = 'd'.repeat(64);
		const url = buildAuthCallbackUrl('myapp://', token);
		expect(url).toBe(`myapp://auth/callback?token=${token}`);
		expect(parseAuthCallbackUrl(url, 'myapp://')).toBe(token);
		expect(parseAuthCallbackUrl(url, 'other://')).toBeNull();
		expect(parseAuthCallbackUrl('myapp://auth/callback?token=short', 'myapp://')).toBeNull();
		expect(parseAuthCallbackUrl('javascript:alert(1)', 'myapp://')).toBeNull();
		expect(parseAuthCallbackUrl(null, 'myapp://')).toBeNull();
	});
});

describe('rateLimit', () => {
	it('allows max hits then blocks, then resets after the window', async () => {
		const store = memStore();
		expect(await rateLimit(store, 'k', 2, 1000)).toBe(true);
		expect(await rateLimit(store, 'k', 2, 1000)).toBe(true);
		expect(await rateLimit(store, 'k', 2, 1000)).toBe(false);
		await new Promise((r) => setTimeout(r, 1100));
		expect(await rateLimit(store, 'k', 2, 1000)).toBe(true);
	});
});

describe('diagLine + escapeHtml', () => {
	it('formats the raw failure', () => {
		expect(diagLine(new TypeError('boom'), 0, 12)).toBe('attempt 1: TypeError: boom @12ms');
		expect(diagLine('str', 1, 3)).toBe('attempt 2: Unknown: str @3ms');
	});
	it('escapes html', () => {
		expect(escapeHtml('<a href="x">&')).toBe('&lt;a href=&quot;x&quot;&gt;&amp;');
	});
	it('MAX_CODE_ATTEMPTS is 5', () => {
		expect(MAX_CODE_ATTEMPTS).toBe(5);
	});
});
