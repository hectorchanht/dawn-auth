// @dawn-studio/auth — the Dawn Studio app-auth standard.
//
// Magic link + 6-digit code + Google sign-in. Edge-safe, zero dependencies.
//
// Quick start:
//   import { defineAuth, createD1Store, requestMagicLink } from '@dawn-studio/auth';
//   const auth = defineAuth({ appName: 'Clipbin', domain: 'clipbin.lol',
//     from: 'Clipbin <login@clipbin.lol>', resendApiKey: process.env.RESEND_API_KEY,
//     googleClientId: '…' });
//   const store = createD1Store(env.ACCOUNTS_DB);
//   const result = await requestMagicLink(store, auth, { email, origin, ip });

export { defineAuth } from './config.js';
export type {
	AuthConfig,
	ResolvedAuthConfig,
	RateLimitConfig,
	MagicLinkRateLimits,
	VerifyCodeRateLimits,
	GoogleRateLimits
} from './config.js';

export {
	TOKEN_RE,
	CODE_RE,
	MAX_CODE_ATTEMPTS,
	SESSION_MAX_AGE_SECONDS,
	isAllowedScheme,
	randomToken,
	randomCode,
	sha256hex,
	sha256hexN,
	timingSafeEqual,
	isValidEmail,
	getSessionTokenFromCookie,
	getBearerToken,
	getAuthToken,
	buildSessionCookie,
	clearSessionCookie,
	clientIp,
	diagLine,
	buildAuthCallbackUrl,
	parseAuthCallbackUrl,
	escapeHtml
} from './core.js';
export type { AccountUser } from './core.js';

export {
	GOOGLE_CERTS_URL,
	GOOGLE_ALLOWED_ISSUERS,
	verifyGoogleIdToken,
	__resetGoogleCerts
} from './google.js';
export type { GoogleJwk, GoogleJwks, GoogleIdTokenResult, VerifyGoogleIdTokenOptions } from './google.js';

export { buildSignInEmail } from './email.js';
export type { SignInEmailParams, SignInEmail } from './email.js';

export { createD1Store, rateLimit } from './store.js';
export type { AuthStore, MagicTokenRow, SessionInsert, RateRow, D1Like } from './store.js';

export {
	issueSessionForEmail,
	sendViaResend,
	requestMagicLink,
	verifyMagicToken,
	verifyCode,
	signInWithGoogle,
	getSessionUser,
	destroySession,
	sessionCookie,
	requestIp
} from './service.js';
export type {
	RequestLinkResult,
	VerifyCodeResult,
	SessionIssued,
	VerifyMagicTokenResult,
	VerifyCodeServiceResult,
	GoogleSignInResult,
	RequestMagicLinkInput,
	VerifyCodeInput,
	GoogleSignInInput
} from './service.js';

export { DawnAuthClient } from './client.js';
export type {
	VerifyResult,
	AuthSnapshot,
	DawnAuthClientOptions,
	ClientRequestLinkResult,
	ClientVerifyCodeResult
} from './client.js';

export { requestLinkMessages, verifyCodeMessages, googleSignInMessages } from './messages.js';
