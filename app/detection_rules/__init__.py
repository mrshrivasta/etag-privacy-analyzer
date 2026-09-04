"""
Detection Rules — ETag Privacy Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects REAL HTTP response headers collected from a live GET
request to a target URL you provide. No sample HTTP data is ever
generated — every header value comes from the actual server response at
scan time.

ETags are a validation-caching mechanism, but they carry real privacy and
information-disclosure risks: they can act as tracking tokens that survive
cookie clearing, they can leak internal server metadata (inode numbers),
and — combined with missing Vary headers — they can cause shared caches to
serve one user's cached representation to another.
"""
import re

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

SENSITIVE_PATH_MARKERS = (
    "login", "signin", "account", "admin", "checkout", "profile",
    "dashboard", "cart", "payment", "settings", "session", "token",
)

# Classic Apache/nginx inode-based ETag format: "<hex>-<hex>-<hex>"
# (inode-size-mtime or similar), a long-standing information-disclosure
# pattern (leaks internal filesystem inode numbers).
_INODE_ETAG_RE = re.compile(r'^"?[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"?$', re.IGNORECASE)

# Heuristic for an ETag value that looks like it embeds a long opaque
# token (UUID-like or session-id-like) rather than a short content hash.
_LONG_TOKEN_RE = re.compile(r'[0-9a-f]{24,}', re.IGNORECASE)


def _looks_sensitive(response):
    path = response["url"].lower()
    has_marker = any(marker in path for marker in SENSITIVE_PATH_MARKERS)
    has_cookie = "set-cookie" in response["headers_lower"]
    return has_marker or has_cookie


def _etag_raw(response):
    return response["headers_lower"].get("etag", "")


def rule_etag_on_sensitive_response(response):
    """EPA-001: A sensitive-looking response (session cookie and/or
    sensitive URL path) returns an ETag. Because ETags are sent back by
    the client on every subsequent conditional GET (If-None-Match), they
    can function as a semi-persistent tracking token independent of
    cookies, and can survive a user clearing cookies but not cache."""
    etag = _etag_raw(response)
    if etag and _looks_sensitive(response):
        return {
            "rule_id": "EPA-001",
            "rule_name": "ETag Present on Sensitive/Personalized Response",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"{response['url']} looks sensitive (session cookie and/or "
                f"sensitive path segment) and returns ETag: {etag}. "
                f"Conditional requests using this token can persist "
                f"identifying state across cache clears."
            ),
        }
    return None


def rule_inode_based_etag_format(response):
    """EPA-002: The ETag value matches the classic Apache/nginx
    inode-size-mtime hex format, which discloses internal filesystem
    metadata (inode numbers) to any client — useful reconnaissance
    information for an attacker mapping the server's filesystem."""
    etag = _etag_raw(response).strip()
    stripped = etag.lstrip("W/").strip('"')
    if stripped and _INODE_ETAG_RE.match(stripped):
        return {
            "rule_id": "EPA-002",
            "rule_name": "Inode-Based ETag Format (Filesystem Metadata Leak)",
            "severity": SEVERITY_HIGH,
            "description": (
                f"{response['url']} returns ETag: {etag}, which matches the "
                f"classic inode-size-mtime hex pattern used by some web "
                f"servers. This can disclose internal filesystem metadata "
                f"such as inode numbers to any client."
            ),
        }
    return None


def rule_etag_with_cookie_missing_vary(response):
    """EPA-003: The response sets a cookie AND returns an ETag, but has no
    Vary header naming Cookie/Authorization/Cookie. Shared/CDN caches that
    key purely on URL + ETag (ignoring the cookie) may validate a stale,
    previously-cached representation via a 304 and serve one user's cached
    body to a different user — a serious cross-user data leak risk."""
    headers_lower = response["headers_lower"]
    etag = _etag_raw(response)
    vary = headers_lower.get("vary", "").lower()
    if etag and "set-cookie" in headers_lower and "cookie" not in vary and "authorization" not in vary and "*" not in vary:
        return {
            "rule_id": "EPA-003",
            "rule_name": "ETag + Cookie Response Missing Vary Header",
            "severity": SEVERITY_CRITICAL,
            "description": (
                f"{response['url']} returns ETag: {etag} and sets a cookie, "
                f"but the Vary header is '{vary or '(missing)'}' — it does "
                f"not include Cookie or Authorization. A shared cache keyed "
                f"only on URL+ETag could serve one user's cached response "
                f"to another user."
            ),
        }
    return None


def rule_weak_etag_on_sensitive_response(response):
    """EPA-004: A weak ETag validator (the 'W/' prefix) is used on a
    sensitive-looking response. Weak validators only assert semantic
    equivalence, not byte-for-byte identity, which increases the risk of
    the server treating two different users' personalized responses as
    'equivalent' and returning a shared cached body."""
    etag = _etag_raw(response)
    if etag.startswith("W/") and _looks_sensitive(response):
        return {
            "rule_id": "EPA-004",
            "rule_name": "Weak ETag Validator on Sensitive Response",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"{response['url']} is sensitive-looking and returns a weak "
                f"ETag ({etag}). Weak validators assert semantic equivalence "
                f"only, increasing the risk of cross-response/cross-user "
                f"cache confusion for personalized content."
            ),
        }
    return None


def rule_etag_without_cache_control(response):
    """EPA-005: An ETag is present but there is no Cache-Control header at
    all. Relying on conditional-GET validation alone, with no explicit
    caching policy, leaves privacy-relevant caching behavior undefined and
    inconsistent across browsers, proxies, and CDNs."""
    etag = _etag_raw(response)
    if etag and "cache-control" not in response["headers_lower"]:
        return {
            "rule_id": "EPA-005",
            "rule_name": "ETag Present Without Cache-Control Policy",
            "severity": SEVERITY_LOW,
            "description": (
                f"{response['url']} returns ETag: {etag} but no "
                f"Cache-Control header. Caching/privacy behavior for this "
                f"response is left undefined across intermediaries."
            ),
        }
    return None


def rule_etag_looks_like_long_opaque_token(response):
    """EPA-006: The ETag value contains a long opaque hex/token sequence
    (24+ hex characters), resembling a UUID or session identifier rather
    than a short content hash. Such tokens are prime candidates for reuse
    as a covert, cookie-independent tracking identifier."""
    etag = _etag_raw(response)
    stripped = etag.lstrip("W/").strip('"')
    if stripped and _LONG_TOKEN_RE.search(stripped) and not _INODE_ETAG_RE.match(stripped):
        return {
            "rule_id": "EPA-006",
            "rule_name": "ETag Resembles a Long Opaque Tracking Token",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"{response['url']} returns ETag: {etag}, which contains a "
                f"long opaque hex sequence resembling a UUID/session "
                f"identifier rather than a short content hash. This could "
                f"double as a cookie-independent tracking token."
            ),
        }
    return None


ALL_RULES = [
    rule_etag_on_sensitive_response,
    rule_inode_based_etag_format,
    rule_etag_with_cookie_missing_vary,
    rule_weak_etag_on_sensitive_response,
    rule_etag_without_cache_control,
    rule_etag_looks_like_long_opaque_token,
]
