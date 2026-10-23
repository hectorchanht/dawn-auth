// @dawn-studio/auth — default English UI copy for the result unions.
//
// The lib stays i18n-free (it returns closed unions); the app localizes. This module
// is the default mapping apps can use as-is or replace with their own locale tables
// (the OpenMusic pattern: the Account page maps each outcome to an `account.*` key).

import type { ClientRequestLinkResult, ClientVerifyCodeResult } from './client.js';

export const requestLinkMessages: Record<ClientRequestLinkResult, string> = {
	ok: 'Check your inbox — the sign-in email is on its way.',
	'invalid-email': 'That email address doesn\u2019t look right.',
	'invalid-scheme': 'This sign-in request came from an unsupported app version.',
	'rate-limited': 'Too many attempts — please wait a few minutes and try again.',
	'not-configured': 'Sign-in email isn\u2019t configured yet. Please tell the developer.',
	'send-failed': 'The email couldn\u2019t be sent. Please try again.',
	network: 'Network error — check your connection and try again.',
	error: 'Something went wrong. Please try again.'
};

export const verifyCodeMessages: Record<ClientVerifyCodeResult, string> = {
	ok: 'Signed in.',
	invalid: 'Enter the 6-digit code from the email.',
	'invalid-code': 'Wrong or expired code. Check the email and try again.',
	'too-many-attempts': 'Too many wrong tries — request a new code.',
	'rate-limited': 'Too many attempts — please wait a few minutes and try again.',
	network: 'Network error — check your connection and try again.'
};

export const googleSignInMessages: Record<'invalid-token' | 'rate-limited' | 'not-configured', string> = {
	'invalid-token': 'Google sign-in failed. Please try again.',
	'rate-limited': 'Too many attempts — please wait a few minutes and try again.',
	'not-configured': 'Google sign-in isn\u2019t configured yet. Please tell the developer.'
};
