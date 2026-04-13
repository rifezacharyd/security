# Hardening a Static Site with Security Headers

Static sites are not immune to attack. They ship HTML, CSS, and JavaScript to every visitor's browser — and without the right headers, that browser will happily execute injected scripts, render your page inside a malicious iframe, or MIME-sniff a `.txt` file into a `.js` file. This guide walks through the security headers we added to a Jekyll site hosted on GitHub Pages and explains why each one matters even when there is no backend.

---

## The Problem

New developers often assume that "static" means "safe." The logic sounds reasonable: there is no database to inject, no login form to brute-force, no server-side code to exploit. But the browser does not know your site is static. It will obey whatever instructions it receives — or in the absence of instructions, fall back to permissive defaults. That gap between "no server-side risk" and "no client-side risk" is where real attacks live.

---

## What We Added

### Content-Security-Policy (CSP)

The CSP header tells the browser exactly which origins are allowed to load scripts, styles, fonts, images, and frames on your page. Without it, the browser trusts everything.

```html
<meta http-equiv="Content-Security-Policy" content="
  default-src 'self';
  script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://www.google-analytics.com;
  style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
  font-src 'self' https://fonts.gstatic.com;
  img-src 'self' data: https:;
  connect-src 'self' https://www.google-analytics.com https://analytics.google.com;
  frame-src 'self' https://www.youtube.com https://www.youtube-nocookie.com;
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
">
```

**Why it matters:** If an attacker manages to inject a `<script>` tag (through a compromised CDN, a browser extension, or a stored XSS vector in user-generated content), the CSP blocks execution from any origin you have not explicitly allowed.

**The fallback trap:** Three CSP directives — `base-uri`, `form-action`, and `frame-ancestors` — do *not* fall back to `default-src`. Omitting them is the same as setting them to `*`, which allows anything. This is the single most common CSP mistake and it leaves three attack surfaces wide open:

| Directive | What it controls | Attack if missing |
|-----------|-----------------|-------------------|
| `base-uri` | Allowed values for `<base href>` | Attacker injects `<base>` tag, hijacks every relative URL on the page |
| `form-action` | Where `<form>` elements can submit | Forms can be redirected to attacker-controlled endpoints to steal input |
| `frame-ancestors` | Who can embed your page in an iframe | Clickjacking — your page rendered invisibly under a decoy UI |

---

### X-Frame-Options

```html
<meta http-equiv="X-Frame-Options" content="DENY">
```

Prevents any site from embedding your page in an `<iframe>`, `<frame>`, or `<object>`. This is the classic anti-clickjacking defense. The CSP `frame-ancestors 'none'` directive does the same thing, but `X-Frame-Options` provides backward compatibility with older browsers that do not support CSP Level 2.

---

### X-Content-Type-Options

```html
<meta http-equiv="X-Content-Type-Options" content="nosniff">
```

Stops the browser from MIME-sniffing a response away from the declared `Content-Type`. Without this, a browser might interpret a plaintext file as JavaScript and execute it — a vector known as MIME confusion.

---

### Cache-Control

```html
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
```

Forces the browser to revalidate every request with the server rather than serving a stale cached copy. On a security-focused site, this prevents scenarios where a visitor sees outdated content after you have patched a vulnerability or rotated credentials displayed in documentation.

---

## How to Implement on Jekyll / GitHub Pages

GitHub Pages does not let you set HTTP response headers directly. The workaround is `<meta http-equiv>` tags in your `_includes/head.html`. These are not identical to real HTTP headers — a server-side `Content-Security-Policy` header is stronger because it cannot be stripped by an intermediary — but for a static site on GitHub Pages, meta tags are the available mechanism and browsers respect them.

```
_includes/head.html
├── <meta http-equiv="X-Frame-Options" ...>
├── <meta http-equiv="X-Content-Type-Options" ...>
├── <meta http-equiv="Cache-Control" ...>
└── <meta http-equiv="Content-Security-Policy" ...>
```

Place them early in `<head>`, before any `<script>` or `<link>` tags, so the browser enforces the policy before loading any resources.

---

## Testing Your Headers

You can verify your headers are working with:

```bash
# Check what the browser actually receives
curl -sI https://yoursite.github.io | grep -iE "content-security|x-frame|x-content|cache"

# Use a scanner
# https://securityheaders.com — grades your response headers A through F
# https://csp-evaluator.withgoogle.com — analyzes your CSP for weaknesses
```

---

## Key Takeaways

1. **Static does not mean safe.** The browser still executes JavaScript, renders iframes, and follows redirects. Headers are how you constrain that behavior.
2. **CSP directives without a `default-src` fallback must be set explicitly.** `base-uri`, `form-action`, and `frame-ancestors` default to allowing everything if you do not include them.
3. **Defense in depth applies.** `X-Frame-Options` and `frame-ancestors` overlap — keep both for backward compatibility.
4. **Meta tags are a viable path on GitHub Pages.** They are not as strong as HTTP headers, but they are what the platform supports and browsers honor them.

---

## References

- MDN Web Docs. (n.d.). *Content-Security-Policy*. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
- OWASP. (n.d.). *Clickjacking defense cheat sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
- OWASP. (n.d.). *HTTP security response headers cheat sheet*. https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
