// The branded sign-in email: identity is parameterized, structure is the house design.
import { describe, expect, it } from 'vitest';
import { buildSignInEmail } from '../src/index.js';

const P = {
	appName: 'Clipbin',
	domain: 'clipbin.lol',
	brandColor: '#00c2b8',
	link: 'https://clipbin.lol/auth/magic?token=abc',
	code: '123456',
	toEmail: 'user@example.com'
};

describe('buildSignInEmail', () => {
	it('leads with the code in the subject', () => {
		const { subject } = buildSignInEmail(P);
		expect(subject).toBe('Use code 123456 to sign in to Clipbin');
	});

	it('html carries the app name, big code box, CTA link, and footer', () => {
		const { html } = buildSignInEmail(P);
		expect(html).toContain('Clipbin');
		expect(html).toContain('123456');
		expect(html).toContain('user-select:all');
		expect(html).toContain('href="https://clipbin.lol/auth/magic?token=abc"');
		expect(html).toContain('Sign in to Clipbin');
		expect(html).toContain('#00c2b8');
		expect(html).toContain('Clipbin &middot; Dawn Studio &middot; clipbin.lol');
		expect(html).toContain('This message was sent to user@example.com at your request.');
	});

	it('text fallback carries code + link', () => {
		const { text } = buildSignInEmail(P);
		expect(text).toContain('Sign-in code: 123456');
		expect(text).toContain(P.link);
	});

	it('escapes the recipient address in html', () => {
		const { html } = buildSignInEmail({ ...P, toEmail: '<b>x@y.z</b>' });
		expect(html).not.toContain('<b>x@y.z</b>');
		expect(html).toContain('&lt;b&gt;x@y.z&lt;/b&gt;');
	});
});
