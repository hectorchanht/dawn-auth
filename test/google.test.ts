// Ported from OpenMusic's auth-core.test.ts google section — the JWKS below is
// genuinely signature-checked by verifyGoogleIdToken, not stubbed around.
// The client ID is now a parameter (was a hardcoded constant in OpenMusic).
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { verifyGoogleIdToken, __resetGoogleCerts, type GoogleJwk } from '../src/index.js';

const CLIENT_ID = 'test-client-id.apps.googleusercontent.com';

describe('verifyGoogleIdToken', () => {
	let keyPair: CryptoKeyPair;
	let jwk: GoogleJwk;
	const KID = 'test-kid-1';

	const b64url = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
	const b64urlBytes = (b: Uint8Array) => Buffer.from(b).toString('base64url');

	beforeAll(async () => {
		keyPair = await crypto.subtle.generateKey(
			{
				name: 'RSASSA-PKCS1-v1_5',
				modulusLength: 2048,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: 'SHA-256'
			},
			true,
			['sign', 'verify']
		);
		jwk = { ...(await crypto.subtle.exportKey('jwk', keyPair.publicKey)), kid: KID };
	});

	afterEach(() => {
		__resetGoogleCerts();
	});

	const fetchCerts = async () => ({ keys: [jwk] });

	function claims(over: Record<string, unknown> = {}) {
		const nowSec = Math.floor(Date.now() / 1000);
		return {
			iss: 'accounts.google.com',
			aud: CLIENT_ID,
			exp: nowSec + 3600,
			iat: nowSec,
			email: 'Tester@Example.com',
			email_verified: true,
			sub: '12345',
			...over
		};
	}

	async function mint(
		payload: Record<string, unknown>,
		header: Record<string, unknown> = { alg: 'RS256', kid: KID, typ: 'JWT' },
		signer: CryptoKey = keyPair.privateKey
	): Promise<string> {
		const hb = b64url(JSON.stringify(header));
		const pb = b64url(JSON.stringify(payload));
		const data = new TextEncoder().encode(hb + '.' + pb);
		const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', signer, data);
		return `${hb}.${pb}.${b64urlBytes(new Uint8Array(sig))}`;
	}

	const verify = (t: Promise<string>) => t.then((tok) => verifyGoogleIdToken(tok, { clientId: CLIENT_ID, fetchCerts }));

	it('accepts a well-formed token and lowercases the email', async () => {
		expect(await verify(mint(claims()))).toEqual({ ok: true, email: 'tester@example.com' });
	});

	it('accepts the https:// issuer variant', async () => {
		expect((await verify(mint(claims({ iss: 'https://accounts.google.com' })))).ok).toBe(true);
	});

	it('rejects a wrong aud', async () => {
		expect(await verify(mint(claims({ aud: 'evil.apps.googleusercontent.com' })))).toEqual({
			ok: false,
			reason: 'bad-aud'
		});
	});

	it('rejects an expired token', async () => {
		const past = Math.floor(Date.now() / 1000) - 10;
		expect(await verify(mint(claims({ exp: past })))).toEqual({ ok: false, reason: 'expired' });
	});

	it('rejects a wrong iss', async () => {
		expect(await verify(mint(claims({ iss: 'evil.example.com' })))).toEqual({ ok: false, reason: 'bad-iss' });
	});

	it('rejects email_verified !== true (a string "true" is not enough)', async () => {
		expect(await verify(mint(claims({ email_verified: 'true' })))).toEqual({
			ok: false,
			reason: 'email-unverified'
		});
	});

	it('rejects a tampered payload (bad signature)', async () => {
		const good = await mint(claims());
		const [h, p, s] = good.split('.');
		const evil = JSON.parse(Buffer.from(p as string, 'base64url').toString('utf8'));
		evil.email = 'attacker@example.com';
		const tampered = `${h}.${b64url(JSON.stringify(evil))}.${s}`;
		expect(await verifyGoogleIdToken(tampered, { clientId: CLIENT_ID, fetchCerts })).toEqual({
			ok: false,
			reason: 'bad-signature'
		});
	});

	it('rejects a token signed by an unknown key', async () => {
		const other = await crypto.subtle.generateKey(
			{ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
			true,
			['sign', 'verify']
		);
		const res = await verify(mint(claims(), { alg: 'RS256', kid: KID, typ: 'JWT' }, other.privateKey));
		expect(res).toEqual({ ok: false, reason: 'bad-signature' });
	});

	it('rejects a non-RS256 alg', async () => {
		const res = await verify(mint(claims(), { alg: 'HS256', kid: KID, typ: 'JWT' }));
		expect(res).toEqual({ ok: false, reason: 'bad-alg' });
	});

	it('rejects malformed tokens', async () => {
		expect(await verifyGoogleIdToken('not-a-jwt', { clientId: CLIENT_ID, fetchCerts })).toEqual({
			ok: false,
			reason: 'malformed'
		});
		expect(await verifyGoogleIdToken('', { clientId: CLIENT_ID, fetchCerts })).toEqual({
			ok: false,
			reason: 'malformed'
		});
	});

	it('rejects an unknown kid', async () => {
		const res = await verify(mint(claims(), { alg: 'RS256', kid: 'nope', typ: 'JWT' }));
		expect(res).toEqual({ ok: false, reason: 'unknown-kid' });
	});

	it('maps cert fetch failures to certs-unavailable', async () => {
		const res = await verifyGoogleIdToken(await mint(claims()), {
			clientId: CLIENT_ID,
			fetchCerts: async () => {
				throw new Error('down');
			}
		});
		expect(res).toEqual({ ok: false, reason: 'certs-unavailable' });
	});
});
