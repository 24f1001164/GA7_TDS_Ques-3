from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from html import unescape
from urllib.parse import unquote, urlparse
import re
import codecs

app = FastAPI(title="LLM Output Handling Gate")


# ============================================================
# CONFIGURATION
# ============================================================

ALLOWED_HOSTS = {
    "cdn-69nym3m.example",
    "app-lsr9xkn.example",
}

VALID_CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell",
}

MAX_OUTPUT_LENGTH = 20000


# ============================================================
# RESPONSE HELPERS
# ============================================================

def result(safe: bool, reason: str):
    return JSONResponse(
        status_code=200,
        content={
            "safe": safe,
            "reason": reason
        }
    )


# ============================================================
# RULE 1: SCHEMA
# ============================================================

def valid_schema(data):
    if not isinstance(data, dict):
        return False

    # Require the two expected fields.
    if "channel" not in data:
        return False

    if "output" not in data:
        return False

    channel = data["channel"]
    output = data["output"]

    if channel not in VALID_CHANNELS:
        return False

    if not isinstance(output, str):
        return False

    if len(output) > MAX_OUTPUT_LENGTH:
        return False

    return True


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_html_urls(text):
    """
    Extract values of quoted src= and href= attributes.
    """
    pattern = re.compile(
        r"""(?:src|href)\s*=\s*(["'])(.*?)\1""",
        re.IGNORECASE | re.DOTALL
    )

    return [match.group(2) for match in pattern.finditer(text)]


def extract_markdown_urls(text):
    """
    Extract target inside ](...).

    Handles normal markdown links/images:
        [text](https://example.com)
        ![alt](https://example.com)
    """
    pattern = re.compile(
        r"""\]\(\s*([^)]+?)\s*\)""",
        re.DOTALL
    )

    values = []

    for match in pattern.finditer(text):
        target = match.group(1).strip()

        # Remove optional markdown title:
        # (url "title")
        # (url 'title')
        # (url (title))
        if target.startswith("<"):
            end = target.find(">")
            if end != -1:
                target = target[1:end]

        else:
            parts = re.split(r'\s+(?=["\'])', target, maxsplit=1)
            target = parts[0]

        values.append(target)

    return values


def extract_urls(channel, output):
    if channel == "html":
        return extract_html_urls(output)

    if channel == "markdown":
        return extract_markdown_urls(output)

    if channel == "url":
        return [output.strip()]

    return []


# ============================================================
# DANGEROUS SCHEME
# ============================================================

DANGEROUS_SCHEME_RE = re.compile(
    r"(?i)\b(?:javascript|data|vbscript)\s*:"
)


def has_dangerous_scheme_text(text):
    return bool(DANGEROUS_SCHEME_RE.search(text))


def url_has_dangerous_scheme(url):
    """
    Returns True if an extracted URL uses a scheme other than
    http/https.

    Relative URLs are safe from this specific scheme check.
    Protocol-relative URLs (//host/path) are treated as https.
    """

    value = url.strip()

    # Protocol-relative reference
    if value.startswith("//"):
        return False

    parsed = urlparse(value)

    # No scheme => relative URL
    if parsed.scheme == "":
        return False

    # Only HTTP and HTTPS are permitted
    return parsed.scheme.lower() not in {"http", "https"}


# ============================================================
# EXTERNAL EXFILTRATION
# ============================================================

def url_is_external(url):
    """
    Check absolute/protocol-relative URLs.

    Only the parsed hostname is compared.

    Allowed:
        https://cdn-69nym3m.example/file
        https://app-lsr9xkn.example/file

    Not allowed:
        https://evil-cdn-69nym3m.example
        https://cdn-69nym3m.example.attacker.example
        https://cdn-69nym3m.example@attacker.example
    """

    value = url.strip()

    # Protocol-relative URL is absolute and resolved as HTTPS.
    if value.startswith("//"):
        value = "https:" + value

    parsed = urlparse(value)

    # Relative references are allowed.
    if parsed.scheme == "":
        return False

    # This function is normally called after dangerous-scheme
    # checking, but keep it defensive.
    if parsed.scheme.lower() not in {"http", "https"}:
        return True

    hostname = parsed.hostname

    if hostname is None:
        return True

    hostname = hostname.lower()

    # EXACT hostname comparison.
    return hostname not in ALLOWED_HOSTS


# ============================================================
# HTML RULES
# ============================================================

SCRIPT_TAG_RE = re.compile(
    r"<\s*(?:script|iframe|object|embed)\b",
    re.IGNORECASE
)


EVENT_HANDLER_RE = re.compile(
    r"\bon[a-zA-Z0-9_-]+\s*=",
    re.IGNORECASE
)


def html_rules(output):
    # 1. SCRIPT_TAG
    if SCRIPT_TAG_RE.search(output):
        return "SCRIPT_TAG"

    # 2. EVENT_HANDLER
    if EVENT_HANDLER_RE.search(output):
        return "EVENT_HANDLER"

    # 3. DANGEROUS_SCHEME
    if has_dangerous_scheme_text(output):
        return "DANGEROUS_SCHEME"

    # Check schemes in extracted URLs.
    urls = extract_html_urls(output)

    for url in urls:
        if url_has_dangerous_scheme(url):
            return "DANGEROUS_SCHEME"

    # 4. EXTERNAL_EXFIL
    for url in urls:
        if url_is_external(url):
            return "EXTERNAL_EXFIL"

    return None


# ============================================================
# MARKDOWN RULES
# ============================================================

def markdown_rules(output):
    # 1. DANGEROUS_SCHEME
    if has_dangerous_scheme_text(output):
        return "DANGEROUS_SCHEME"

    urls = extract_markdown_urls(output)

    for url in urls:
        if url_has_dangerous_scheme(url):
            return "DANGEROUS_SCHEME"

    # 2. EXTERNAL_EXFIL
    for url in urls:
        if url_is_external(url):
            return "EXTERNAL_EXFIL"

    return None


# ============================================================
# URL RULES
# ============================================================

def url_rules(output):
    value = output.strip()

    # 1. DANGEROUS_SCHEME
    if has_dangerous_scheme_text(value):
        return "DANGEROUS_SCHEME"

    if url_has_dangerous_scheme(value):
        return "DANGEROUS_SCHEME"

    # 2. EXTERNAL_EXFIL
    if url_is_external(value):
        return "EXTERNAL_EXFIL"

    return None


# ============================================================
# SQL RULES
# ============================================================

def sql_rules(output):
    # Single quote
    if "'" in output:
        return "SQL_METACHAR"

    # Double quote
    if '"' in output:
        return "SQL_METACHAR"

    # Semicolon
    if ";" in output:
        return "SQL_METACHAR"

    # SQL comment --
    if "--" in output:
        return "SQL_METACHAR"

    # SQL comment /*
    if "/*" in output:
        return "SQL_METACHAR"

    # Word UNION, case insensitive
    if re.search(r"\bunion\b", output, re.IGNORECASE):
        return "SQL_METACHAR"

    # OR 1=1, case insensitive
    if re.search(r"\bor\s*1\s*=\s*1\b", output, re.IGNORECASE):
        return "SQL_METACHAR"

    return None


# ============================================================
# SHELL RULES
# ============================================================

def shell_rules(output):
    # Any of:
    # ; & | ` < >
    if re.search(r"[;&|`<>]", output):
        return "SHELL_METACHAR"

    # $(
    if "$(" in output:
        return "SHELL_METACHAR"

    # ${
    if "${" in output:
        return "SHELL_METACHAR"

    return None


# ============================================================
# APPLY CHANNEL RULES
# ============================================================

def channel_rules(channel, output):

    if channel == "html":
        return html_rules(output)

    if channel == "markdown":
        return markdown_rules(output)

    if channel == "url":
        return url_rules(output)

    if channel == "sql":
        return sql_rules(output)

    if channel == "shell":
        return shell_rules(output)

    return "INVALID_SCHEMA"


# ============================================================
# ONE-TIME DECODING
# ============================================================

def decode_once(output):
    """
    Required order:

    1. Percent escapes
    2. HTML entities
    3. \\uXXXX escapes

    Each transformation is performed once.
    """

    decoded = output

    # --------------------------------------------------------
    # 1. Percent decoding
    # --------------------------------------------------------
    decoded = unquote(decoded)

    # --------------------------------------------------------
    # 2. HTML entity decoding
    #
    # html.unescape handles:
    #   &lt;
    #   &gt;
    #   &quot;
    #   &apos;
    #   &amp;
    #   &#NN;
    #   &#xNN;
    # --------------------------------------------------------
    decoded = unescape(decoded)

    # --------------------------------------------------------
    # 3. Unicode \uXXXX escapes
    #
    # Decode only literal \uXXXX sequences.
    # Avoid interpreting unrelated escape sequences.
    # --------------------------------------------------------
    def unicode_replace(match):
        try:
            return chr(int(match.group(1), 16))
        except Exception:
            return match.group(0)

    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        unicode_replace,
        decoded
    )

    return decoded


# ============================================================
# MAIN ENDPOINT
# ============================================================

@app.post("/sanitize-output")
async def sanitize_output(request: Request):

    # --------------------------------------------------------
    # RULE 1: INVALID_SCHEMA
    # --------------------------------------------------------

    try:
        data = await request.json()
    except Exception:
        return result(False, "INVALID_SCHEMA")

    if not valid_schema(data):
        return result(False, "INVALID_SCHEMA")

    channel = data["channel"]
    output = data["output"]

    # --------------------------------------------------------
    # RULE 2: ENCODED_PAYLOAD
    # --------------------------------------------------------

    decoded = decode_once(output)

    if decoded != output:

        decoded_reason = channel_rules(channel, decoded)

        if decoded_reason is not None:
            return result(False, "ENCODED_PAYLOAD")

    # --------------------------------------------------------
    # RULE 3: ORIGINAL OUTPUT CHANNEL RULES
    # --------------------------------------------------------

    reason = channel_rules(channel, output)

    if reason is not None:
        return result(False, reason)

    # --------------------------------------------------------
    # SAFE
    # --------------------------------------------------------

    return result(True, "SAFE")


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
async def root():
    return {
        "service": "LLM Output Handling Gate",
        "status": "ok"
    }
