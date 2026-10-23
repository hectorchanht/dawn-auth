// @dawn-studio/auth — app configuration. Every OpenMusic-specific value is a field
// here; nothing about one app's identity is baked into the lib.

import type { ResolvedSessionCookieAttrs, SessionCookieAttrs } from './core.js';
import type { EmailCopy, SignInEmail, SignInEmailParams } from './email.js';
import type { AuthEvent } from './service.js';

/** Rate-limit knobs for one guarded operation. */
export interface RateLimitConfig {
	/** Max hits per key per window (default per operation — see DEFAULTS below). */
	max: number;
	/** Window length in ms (default 10 min). */
	windowMs: number;
}

export interface MagicLinkRateLimits {
	perEmail: RateLimitConfig;
	perIp: RateLimitConfig;
}

export interface VerifyCodeRateLimits {
	perEmail: RateLimitConfig;
	perIp: RateLimitConfig;
}

export interface GoogleRateLimits {
	perIp: RateLimitConfig;
	perEmail: RateLimitConfig;
}

export interface AuthConfig {
	/** Display name used in the email + UI copy, e.g. 'OpenMusic'. */
	appName: string;
	/** Public domain for the email footer, e.g. 'openmusic.lol'. */
	domain: string;
	/**
	 * OWN-DOMAIN RULE (standing): every app sends from its OWN domain, never a
	 * borrowed one. e.g. 'OpenMusic <login@openmusic.lol>'. REQUIRED — there is no
	 * default, so a misconfigured app fails closed instead of sending from a
	 * stranger's domain.
	 */
	from: string;
	/** Resend API key (sending-only, domain-scoped). REQUIRED for requestMagicLink. */
	resendApiKey?: string;
	/**
	 * Google Web OAuth client ID (the `aud` every ID token must carry). PUBLIC —
	 * baked into the web bundle + APK, never a secret. REQUIRED for signInWithGoogle.
	 */
	googleClientId?: string;
	/** Session cookie name, e.g. 'openmusic_session'. Defaults to '<slug>_session'. */
	cookieName?: string;
	/**
	 * Native deep-link scheme(s) for the post-redeem handoff, e.g. ['openmusic://'].
	 * STRICT exact-match allowlist — never `javascript:`, never `https:`. Empty =
	 * the scheme field is rejected outright (web-only app).
	 */
	nativeSchemes?: string[];
	/** Path of the magic-link landing page, e.g. '/auth/magic'. Default '/auth/magic'. */
	magicPagePath?: string;
	/** Brand color for the email CTA. Default Dawn teal '#00c2b8'. */
	brandColor?: string;
	/** Magic-link/code lifetime in ms. Default 15 min (matches the email copy). */
	magicLinkTtlMs?: number;
	/** Session lifetime in ms. Default 30 days. */
	sessionTtlMs?: number;
	/**
	 * Sign-in code length in digits. Default 6. Validated 4–9 at boot (the
	 * rejection-sampling math in randomCode needs the range inside uint32).
	 */
	codeLength?: number;
	/**
	 * A code dies after this many wrong guesses (per code_hash row, in the store).
	 * Default 5 (matches the APP AUTH STANDARD; the email copy reflects it).
	 */
	maxCodeAttempts?: number;
	/**
	 * Session cookie attributes beyond the name: sameSite / secure / path /
	 * domain / httpOnly. Defaults: HttpOnly, Secure, SameSite=Lax, Path=/.
	 */
	cookie?: SessionCookieAttrs;
	/**
	 * Email copy overrides (subject + body strings, {app}/{code}/{email}/{domain}/
	 * {ttl}/{attempts} placeholders). Only the fields you set are replaced; the
	 * rest keep the house design. {ttl} and {attempts} are computed from
	 * magicLinkTtlMs / maxCodeAttempts automatically.
	 */
	emailCopy?: EmailCopy;
	/**
	 * Full email-builder escape hatch: replaces buildSignInEmail entirely.
	 * Receives the same params (plus the resolved copy); returns { subject, html, text }.
	 */
	buildEmail?: (p: SignInEmailParams) => SignInEmail;
	/**
	 * Lifecycle hook: link.requested / link.failed / link.verified / code.verified /
	 * code.failed / google.signed-in / google.failed / session.destroyed.
	 * Fire-and-forget — throwing inside the hook never breaks auth.
	 */
	onEvent?: (event: AuthEvent) => void;
	/**
	 * How long fetched Google certs are trusted (module-scope cache). Default 1 hour.
	 */
	googleCertsTtlMs?: number;
	/** requestMagicLink limits. Defaults: 3/email + 10/IP per 10 min. */
	magicLinkLimits?: MagicLinkRateLimits;
	/** verifyCode limits. Defaults: 10/email + 50/IP per 10 min. */
	verifyCodeLimits?: VerifyCodeRateLimits;
	/** signInWithGoogle limits. Defaults: 10/IP + 10/email per 10 min. */
	googleLimits?: GoogleRateLimits;
	/**
	 * Optional mailer override. Default sends via the Resend API. Signature mirrors
	 * the Resend /emails payload so swapping senders never changes call sites.
	 */
	mailer?: (msg: {
		from: string;
		to: string;
		subject: string;
		html: string;
		text: string;
	}) => Promise<boolean>;
}

const TEN_MIN = 10 * 60 * 1000;

/** Resolved config — every field concrete. `defineAuth()` returns this. */
export interface ResolvedAuthConfig {
	appName: string;
	domain: string;
	from: string;
	resendApiKey?: string;
	googleClientId?: string;
	cookieName: string;
	cookie: ResolvedSessionCookieAttrs;
	nativeSchemes: string[];
	magicPagePath: string;
	brandColor: string;
	magicLinkTtlMs: number;
	sessionTtlMs: number;
	codeLength: number;
	maxCodeAttempts: number;
	emailCopy?: EmailCopy;
	buildEmail?: (p: SignInEmailParams) => SignInEmail;
	onEvent?: (event: AuthEvent) => void;
	googleCertsTtlMs: number;
	magicLinkLimits: MagicLinkRateLimits;
	verifyCodeLimits: VerifyCodeRateLimits;
	googleLimits: GoogleRateLimits;
	mailer?: AuthConfig['mailer'];
}

/**
 * Validate + fill defaults. Throws on a missing `from` (fail closed at boot, not
 * at the first sign-in attempt).
 */
export function defineAuth(cfg: AuthConfig): ResolvedAuthConfig {
	if (!cfg.from || !cfg.from.includes('@')) {
		throw new Error(
			`[@dawn-studio/auth] config.from is required (own-domain rule, e.g. '${cfg.appName} <login@${cfg.domain}>')`
		);
	}
	const slug = cfg.appName.toLowerCase().replace(/[^a-z0-9]+/g, '');
	const codeLength = cfg.codeLength ?? 6;
	if (!Number.isInteger(codeLength) || codeLength < 4 || codeLength > 9) {
		throw new Error(
			`[@dawn-studio/auth] config.codeLength must be an integer 4–9 (got ${cfg.codeLength})`
		);
	}
	const maxCodeAttempts = cfg.maxCodeAttempts ?? 5;
	if (!Number.isInteger(maxCodeAttempts) || maxCodeAttempts < 1) {
		throw new Error(
			`[@dawn-studio/auth] config.maxCodeAttempts must be an integer >= 1 (got ${cfg.maxCodeAttempts})`
		);
	}
	const sameSite = cfg.cookie?.sameSite ?? 'Lax';
	if (sameSite !== 'Lax' && sameSite !== 'Strict' && sameSite !== 'None') {
		throw new Error(
			`[@dawn-studio/auth] config.cookie.sameSite must be 'Lax' | 'Strict' | 'None' (got ${sameSite})`
		);
	}
	return {
		appName: cfg.appName,
		domain: cfg.domain,
		from: cfg.from,
		resendApiKey: cfg.resendApiKey,
		googleClientId: cfg.googleClientId,
		cookieName: cfg.cookieName ?? `${slug}_session`,
		cookie: {
			sameSite,
			secure: cfg.cookie?.secure ?? true,
			path: cfg.cookie?.path ?? '/',
			domain: cfg.cookie?.domain,
			httpOnly: cfg.cookie?.httpOnly ?? true
		},
		codeLength,
		maxCodeAttempts,
		emailCopy: cfg.emailCopy,
		buildEmail: cfg.buildEmail,
		onEvent: cfg.onEvent,
		googleCertsTtlMs: cfg.googleCertsTtlMs ?? 60 * 60 * 1000,
		nativeSchemes: cfg.nativeSchemes ?? [],
		magicPagePath: cfg.magicPagePath ?? '/auth/magic',
		brandColor: cfg.brandColor ?? '#00c2b8',
		magicLinkTtlMs: cfg.magicLinkTtlMs ?? 15 * 60 * 1000,
		sessionTtlMs: cfg.sessionTtlMs ?? 30 * 24 * 3600 * 1000,
		magicLinkLimits: cfg.magicLinkLimits ?? {
			perEmail: { max: 3, windowMs: TEN_MIN },
			perIp: { max: 10, windowMs: TEN_MIN }
		},
		verifyCodeLimits: cfg.verifyCodeLimits ?? {
			perEmail: { max: 10, windowMs: TEN_MIN },
			perIp: { max: 50, windowMs: TEN_MIN }
		},
		googleLimits: cfg.googleLimits ?? {
			perIp: { max: 10, windowMs: TEN_MIN },
			perEmail: { max: 10, windowMs: TEN_MIN }
		},
		mailer: cfg.mailer
	};
}
