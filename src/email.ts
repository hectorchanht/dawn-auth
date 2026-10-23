// @dawn-studio/auth — the formal branded sign-in email.
//
// The house design: branded header, "Hi there,", a solid CTA BUTTON (a real table
// button, not a colored text link — bulletproof for mail clients), a divider, "Or enter
// this code in the app:" with the code BIG in a box (monospace + letter-spacing +
// user-select:all, prominent enough that Gmail offers its own "Copy code" chip), and a
// formal footer. HTML + plain-text fallback.
//
// The CODE leads (subject + body, mirroring the shape of Meta's OTP emails so Gmail's
// "Copy code" detector fires) while the magic link rides below as the instant path.
// Whether Gmail shows its pill is still its own detector's call — this is the closest
// sender-side mirror.
//
// Ported from OpenMusic's buildSignInEmail (quick-261020-code); app identity is now
// parameters.

import { escapeHtml } from './core.js';

export interface SignInEmailParams {
	/** e.g. 'OpenMusic' */
	appName: string;
	/** e.g. 'openmusic.lol' — used in the footer line. */
	domain: string;
	/** e.g. '#00c2b8' (Dawn teal). */
	brandColor: string;
	/** The absolute magic-link URL. */
	link: string;
	/** The 6-digit code. */
	code: string;
	/** Recipient address (HTML-escaped in the footer). */
	toEmail: string;
}

export interface SignInEmail {
	subject: string;
	html: string;
	text: string;
}

export function buildSignInEmail(p: SignInEmailParams): SignInEmail {
	const { appName, domain, brandColor, link, code, toEmail } = p;
	const safeEmail = escapeHtml(toEmail);
	const safeLink = escapeHtml(link);
	const html = `<!doctype html><html><body style="margin:0;padding:0;background-color:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
<div style="max-width:480px;margin:0 auto;padding:32px 24px;">
<div style="text-align:center;margin-bottom:24px;">
<span style="font-size:22px;font-weight:700;color:#ffffff;letter-spacing:0.5px;">${escapeHtml(appName)}</span>
</div>
<div style="background-color:#141414;border:1px solid #2a2a2a;border-radius:16px;padding:32px 28px;">
<p style="color:#ffffff;font-size:16px;margin:0 0 16px;">Hi there,</p>
<p style="color:#b3b3b3;font-size:14px;line-height:1.6;margin:0 0 12px;">You can sign in to ${escapeHtml(appName)} by entering the following code.</p>
<p style="color:#b3b3b3;font-size:14px;margin:0 0 8px;">Sign-in code</p>
<div style="background-color:#0a0a0a;border:1px dashed ${brandColor};border-radius:12px;padding:20px 12px;text-align:center;margin:0 0 8px;">
<span style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:28px;font-weight:700;letter-spacing:6px;text-indent:6px;color:#ffffff;user-select:all;-webkit-user-select:all;white-space:nowrap;">${escapeHtml(code)}</span>
</div>
<p style="color:#737373;font-size:12px;margin:0 0 24px;">The code expires in 15 minutes and stops working after 5 wrong tries. Long-press the code to copy it.</p>
<div style="border-top:1px solid #2a2a2a;margin:0 0 24px;"></div>
<p style="color:#b3b3b3;font-size:14px;line-height:1.6;margin:0 0 16px;">Or tap the button below to sign in instantly.</p>
<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:0 auto 8px;"><tr><td style="border-radius:999px;background-color:${brandColor};">
<a href="${safeLink}" style="display:inline-block;padding:14px 36px;font-size:16px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:999px;">Sign in to ${escapeHtml(appName)}</a>
</td></tr></table>
<p style="color:#737373;font-size:12px;margin:16px 0 0;">The link expires in 15 minutes and can only be used once.</p>
</div>
<p style="color:#737373;font-size:12px;line-height:1.6;text-align:center;margin:24px 0 8px;">This message was sent to ${safeEmail} at your request.</p>
<p style="color:#525252;font-size:12px;text-align:center;margin:0;">${escapeHtml(appName)} &middot; Dawn Studio &middot; ${escapeHtml(domain)}</p>
</div>
</body></html>`;
	const text = `Hi there,

You can sign in to ${appName} by entering the following code.

Sign-in code: ${code}

The code expires in 15 minutes and stops working after 5 wrong tries.

Or sign in instantly with this link (expires in 15 minutes, one-time use):
${link}

This message was sent to ${toEmail} at your request.
${appName} · Dawn Studio · ${domain}`;
	// The email carries BOTH credentials — the code leads (subject + body, Gmail "Copy
	// code" detector mirror) while the link rides below as the instant path.
	return { subject: `Use code ${code} to sign in to ${appName}`, html, text };
}
