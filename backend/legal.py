"""Server-rendered imprint and privacy pages from operator settings and HTML fragment templates."""

import html
import logging
import re
from pathlib import Path

from .cache import RETENTION_DAYS
from .settings import ROOT

logger = logging.getLogger("isitfixed.legal")
TEMPLATES = ROOT / "legal" / "templates"
SHELL = ROOT / "legal" / "page.html"
PAGES = {
    "imprint": "Impressum / Imprint",
    "privacy": "Datenschutzerklärung / Privacy policy",
}
_BLOCK = re.compile(r"<!--\s*if:(\w+)\s*-->(.*?)<!--\s*endif:\1\s*-->", re.S)
_PLACEHOLDER = re.compile(r"\{\{\s*(\w+)\s*\}\}")
# Template notes for operators (plain HTML comments) are not published.
_COMMENT = re.compile(r"<!--(?!\s*(?:if|endif):).*?-->\s*", re.S)


def render(template, values, raw=None):
    """Fill ``{{name}}`` placeholders (HTML-escaped, newlines → <br>) and drop ``if:name`` blocks of empty values.

    ``raw`` values are inserted verbatim (the page body); inserted text is not scanned again.
    """
    raw = raw or {}

    def block(match):
        name = match[1]
        return match[2] if values.get(name) or raw.get(name) else ""

    template = _COMMENT.sub("", template)
    previous = None
    while previous != template:  # nested blocks
        previous, template = template, _BLOCK.sub(block, template)

    def placeholder(match):
        name = match[1]
        if name in raw:
            return raw[name]
        return html.escape(str(values.get(name) or "")).replace("\n", "<br>\n")

    return _PLACEHOLDER.sub(placeholder, template)


class LegalPages:
    def __init__(self, settings, stylesheet="/style.css"):
        self.settings, self.stylesheet = settings, stylesheet
        self.custom = Path(settings.legal_dir) if settings.legal_dir else None
        self.configured = all(
            (settings.legal_operator_name, settings.legal_operator_address, settings.legal_operator_email)
        )
        self.values = {
            "operator_name": settings.legal_operator_name,
            "operator_address": settings.legal_operator_address,
            "operator_email": settings.legal_operator_email,
            "operator_phone": settings.legal_operator_phone,
            "responsible_person": settings.legal_responsible_person,
            "hosting_provider": settings.legal_hosting_provider,
            "site_url": settings.site_url,
            "source_url": settings.source_url,
            "log_retention_days": str(settings.log_retention_days),
            "cache_retention_days": str(RETENTION_DAYS),
            "workspace_ttl_days": str(settings.workspace_ttl_days),
            "last_updated": settings.legal_last_updated,
            # Non-empty enables the access-log paragraph of the privacy policy.
            "access_logs": "yes" if settings.legal_access_logs else "",
        }

    def fragment_path(self, page):
        if self.custom and (self.custom / f"{page}.html").is_file():
            return self.custom / f"{page}.html"
        if self.configured and (TEMPLATES / f"{page}.html").is_file():
            return TEMPLATES / f"{page}.html"
        return None

    def enabled(self):
        return {page: self.fragment_path(page) is not None for page in PAGES}

    def warn_if_unconfigured(self):
        missing = [page for page, enabled in self.enabled().items() if not enabled]
        if missing:
            logger.warning(
                "Legal pages not configured (%s): set LEGAL_OPERATOR_NAME, LEGAL_OPERATOR_ADDRESS and "
                "LEGAL_OPERATOR_EMAIL or provide them in LEGAL_DIR; they return 404 until then",
                ", ".join(missing),
            )

    def page(self, page):
        """The complete HTML document, or None when the page is not enabled."""
        path = self.fragment_path(page)
        if path is None:
            return None
        enabled = self.enabled()
        body = render(path.read_text(encoding="utf-8"), self.values)
        values = {
            **self.values,
            "title": f"{PAGES[page]} – Is It Fixed",
            "heading": PAGES[page],
            "stylesheet": self.stylesheet,
            "imprint_page": enabled["imprint"],
            "privacy_page": enabled["privacy"],
        }
        return render(SHELL.read_text(encoding="utf-8"), values, raw={"content": body})
