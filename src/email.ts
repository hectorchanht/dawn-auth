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

/**
 * Overridable email copy. Placeholders: {app} {code} {email} {domain} {ttl} {attempts}.
 * Pass only the fields you want to change — the rest keep the house defaults.
 * (For a full redesign, pass `buildEmail` in `defineAuth()` instead.)
 */
export interface EmailCopy {
	/** Subject line. Default 'Use code {code} to sign in to {app}'. */
	subject?: string;
	/** 'Hi there,' */
	greeting?: string;
	/** 'You can sign in to {app} by entering the following code.' */
	codeIntro?: string;
	/** 'Sign-in code' */
	codeLabel?: string;
	/** 'The code expires in {ttl} and stops working after {attempts} wrong tries. Long-press the code to copy it.' */
	codeNote?: string;
	/** 'Or tap the button below to sign in instantly.' */
	linkIntro?: string;
	/** CTA button label. Default 'Sign in to {app}'. */
	ctaLabel?: string;
	/** 'The link expires in {ttl} and can only be used once.' */
	linkNote?: string;
	/** 'This message was sent to {email} at your request.' */
	footerSent?: string;
	/** '{app} · Dawn Studio · {domain}' */
	footerBrand?: string;
}

export const DEFAULT_EMAIL_COPY: Required<EmailCopy> = {
	subject: 'Use code {code} to sign in to {app}',
	greeting: 'Hi there,',
	codeIntro: 'You can sign in to {app} by entering the following code.',
	codeLabel: 'Sign-in code',
	codeNote: 'The code expires in {ttl} and stops working after {attempts} wrong tries. Long-press the code to copy it.',
	linkIntro: 'Or tap the button below to sign in instantly.',
	ctaLabel: 'Sign in to {app}',
	linkNote: 'The link expires in {ttl} and can only be used once.',
	footerSent: 'This message was sent to {email} at your request.',
	footerBrand: '{app} · Dawn Studio · {domain}'
};

/** Merge user overrides over the house defaults. */
export function resolveEmailCopy(overrides?: EmailCopy): Required<EmailCopy> {
	return { ...DEFAULT_EMAIL_COPY, ...(overrides ?? {}) };
}

/** '15 minutes' / '1 hour' / '30 days' — from a TTL in ms, for the email copy. */
export function ttlText(ms: number): string {
	const mins = Math.round(ms / 60000);
	if (mins < 60) return `${mins} minute${mins === 1 ? '' : 's'}`;
	const hours = Math.round(mins / 60);
	if (hours < 48) return `${hours} hour${hours === 1 ? '' : 's'}`;
	const days = Math.round(hours / 24);
	return `${days} day${days === 1 ? '' : 's'}`;
}

function fill(tpl: string, vars: Record<string, string>): string {
	return tpl.replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? `{${k}}`);
}

export interface SignInEmailParams {
	/** e.g. 'OpenMusic' */
	appName: string;
	/** e.g. 'openmusic.lol' — used in the footer line. */
	domain: string;
	/** e.g. '#00c2b8' (Dawn teal). */
	brandColor: string;
	/** The absolute magic-link URL. */
	link: string;
	/** The sign-in code (length = cfg.codeLength). */
	code: string;
	/** Recipient address (HTML-escaped in the footer). */
	toEmail: string;
	/** Copy overrides (see EmailCopy). Default: the house copy. */
	copy?: EmailCopy;
	/** Feeds the {ttl} placeholder. Default 15 min. */
	ttlMs?: number;
	/** Feeds the {attempts} placeholder. Default 5. */
	maxAttempts?: number;
}

export interface SignInEmail {
	subject: string;
	html: string;
	text: string;
}

export function buildSignInEmail(p: SignInEmailParams): SignInEmail {
	const { appName, domain, brandColor, link, code, toEmail } = p;
	const copy = resolveEmailCopy(p.copy);
	const vars = {
		app: appName,
		code,
		email: toEmail,
		domain,
		ttl: ttlText(p.ttlMs ?? 15 * 60 * 1000),
		attempts: String(p.maxAttempts ?? 5)
	};
	const safeEmail = escapeHtml(toEmail);
	const safeLink = escapeHtml(link);
	const html = `<!doctype html><html><body style="margin:0;padding:0;background-color:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
<div style="max-width:480px;margin:0 auto;padding:32px 24px;">
<div style="text-align:center;margin-bottom:24px;">
<span style="font-size:22px;font-weight:700;color:#ffffff;letter-spacing:0.5px;">${escapeHtml(appName)}</span>
</div>
<div style="background-color:#141414;border:1px solid #2a2a2a;border-radius:16px;padding:32px 28px;">
<p style="color:#ffffff;font-size:16px;margin:0 0 16px;">${escapeHtml(fill(copy.greeting, vars))}</p>
<p style="color:#b3b3b3;font-size:14px;line-height:1.6;margin:0 0 12px;">${escapeHtml(fill(copy.codeIntro, vars))}</p>
<p style="color:#b3b3b3;font-size:14px;margin:0 0 8px;">${escapeHtml(fill(copy.codeLabel, vars))}</p>
<div style="background-color:#0a0a0a;border:1px dashed ${brandColor};border-radius:12px;padding:20px 12px;text-align:center;margin:0 0 8px;">
<span style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:28px;font-weight:700;letter-spacing:6px;text-indent:6px;color:#ffffff;user-select:all;-webkit-user-select:all;white-space:nowrap;">${escapeHtml(code)}</span>
</div>
<p style="color:#737373;font-size:12px;margin:0 0 24px;">${escapeHtml(fill(copy.codeNote, vars))}</p>
<div style="border-top:1px solid #2a2a2a;margin:0 0 24px;"></div>
<p style="color:#b3b3b3;font-size:14px;line-height:1.6;margin:0 0 16px;">${escapeHtml(fill(copy.linkIntro, vars))}</p>
<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:0 auto 8px;"><tr><td style="border-radius:999px;background-color:${brandColor};">
<a href="${safeLink}" style="display:inline-block;padding:14px 36px;font-size:16px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:999px;">${escapeHtml(fill(copy.ctaLabel, vars))}</a>
</td></tr></table>
<p style="color:#737373;font-size:12px;margin:16px 0 0;">${escapeHtml(fill(copy.linkNote, vars))}</p>
</div>
<p style="color:#737373;font-size:12px;line-height:1.6;text-align:center;margin:24px 0 8px;">${escapeHtml(fill(copy.footerSent, vars))}</p>
<p style="color:#525252;font-size:12px;text-align:center;margin:0;">${escapeHtml(fill(copy.footerBrand, vars)).replace(/·/g, '&middot;')}</p>
</div>
</body></html>`;
	const text = `${fill(copy.greeting, vars)}

${fill(copy.codeIntro, vars)}

${fill(copy.codeLabel, vars)}: ${code}

${fill(copy.codeNote, vars)}

${fill(copy.linkIntro, vars)} (${fill(copy.linkNote, vars)})
${link}

${fill(copy.footerSent, vars)}
${fill(copy.footerBrand, vars)}`;
	// The email carries BOTH credentials — the code leads (subject + body, Gmail "Copy
	// code" detector mirror) while the link rides below as the instant path.
	return { subject: fill(copy.subject, vars), html, text };
}
