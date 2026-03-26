"""
Gmail Agent — connects to Gmail via IMAP, reads emails, and downloads attachments.

Authentication: uses an App Password set via the GMAIL_APP_PASSWORD environment variable.
  - Enable 2-Step Verification on your Google account.
  - Generate an App Password at: myaccount.google.com → Security → App passwords.
  - Export it: export GMAIL_APP_PASSWORD="xxxx xxxx xxxx xxxx"
"""

import email
import imaplib
import os
from email.header import decode_header
from pathlib import Path


def _decode_header_value(value: str) -> str:
    """Decode a potentially encoded email header value."""
    parts = decode_header(value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return "".join(decoded)


def _safe_filename(name: str) -> str:
    """Strip characters that are unsafe in file names."""
    keepchars = (" ", ".", "_", "-")
    return "".join(c for c in name if c.isalnum() or c in keepchars).rstrip()


class GmailAgent:
    def __init__(self, config: dict):
        gmail_cfg = config["gmail"]
        self.email_address = gmail_cfg["email"]
        # Gmail shows app passwords with spaces (xxxx xxxx xxxx xxxx) — strip them
        self.app_password = os.environ.get("GMAIL_APP_PASSWORD", "").replace(" ", "").strip()
        self.imap_host = gmail_cfg["imap_host"]
        self.imap_port = gmail_cfg["imap_port"]

        search_cfg = gmail_cfg.get("search", {})
        self.folder = search_cfg.get("folder", "INBOX")
        self.subject_filter = search_cfg.get("subject_filter", "")
        self.unread_only = search_cfg.get("unread_only", False)
        self.max_emails = search_cfg.get("max_emails", 20)

        attach_cfg = gmail_cfg.get("attachments", {})
        self.download_dir = Path(attach_cfg.get("download_dir", "downloads/attachments"))
        raw_ext = attach_cfg.get("allowed_extensions", [])
        self.allowed_extensions = {e.lower().lstrip(".") for e in raw_ext} if raw_ext else set()
        self.max_size_bytes = int(attach_cfg.get("max_size_mb", 0)) * 1024 * 1024

        self._imap: imaplib.IMAP4_SSL | None = None

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> None:
        if not self.app_password:
            raise EnvironmentError(
                "GMAIL_APP_PASSWORD environment variable is not set.\n"
                "Generate one at: myaccount.google.com → Security → App passwords"
            )
        print(f"[gmail] Connecting to {self.imap_host}:{self.imap_port} …")
        self._imap = imaplib.IMAP4_SSL(self.imap_host, self.imap_port)
        try:
            self._imap.login(self.email_address, self.app_password)
        except imaplib.IMAP4.error as e:
            raise RuntimeError(
                f"Gmail login failed: {e}\n\n"
                "Checklist:\n"
                "  1. IMAP must be enabled in Gmail:\n"
                "     Gmail → Settings → See all settings → Forwarding and POP/IMAP → Enable IMAP\n"
                "  2. Use an App Password (not your regular Gmail password):\n"
                "     myaccount.google.com → Security → App passwords\n"
                "  3. Export without spaces: export GMAIL_APP_PASSWORD=\"xxxxxxxxxxxxxxxx\"\n"
                f"  4. Password length received: {len(self.app_password)} chars (should be 16)"
            ) from e
        print(f"[gmail] Logged in as {self.email_address}")

    def disconnect(self) -> None:
        if self._imap:
            try:
                self._imap.logout()
            except Exception:
                pass
            self._imap = None
        print("[gmail] Disconnected.")

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def _build_search_criteria(self) -> str:
        parts = []
        if self.unread_only:
            parts.append("UNSEEN")
        if self.subject_filter:
            parts.append(f'SUBJECT "{self.subject_filter}"')
        return " ".join(parts) if parts else "ALL"

    def fetch_email_ids(self) -> list[bytes]:
        assert self._imap, "Not connected — call connect() first."
        self._imap.select(self.folder)
        criteria = self._build_search_criteria()
        print(f"[gmail] Searching folder '{self.folder}' with: {criteria!r}")
        status, data = self._imap.search(None, criteria)
        if status != "OK":
            raise RuntimeError(f"IMAP search failed: {data}")
        ids = data[0].split()
        # Most-recent-first, limited to max_emails
        ids = ids[::-1][: self.max_emails]
        print(f"[gmail] Found {len(ids)} email(s).")
        return ids

    # ------------------------------------------------------------------
    # Download attachments
    # ------------------------------------------------------------------

    def _should_download(self, filename: str, size: int) -> bool:
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if self.allowed_extensions and ext not in self.allowed_extensions:
            return False
        if self.max_size_bytes and size > self.max_size_bytes:
            print(f"  [skip] {filename} ({size // 1024} KB) exceeds size limit.")
            return False
        return True

    def download_attachments_from_message(self, msg_id: bytes) -> list[Path]:
        assert self._imap
        status, data = self._imap.fetch(msg_id, "(RFC822)")
        if status != "OK":
            print(f"[gmail] Failed to fetch message id {msg_id}")
            return []

        raw = data[0][1]
        msg = email.message_from_bytes(raw)

        subject = _decode_header_value(msg.get("Subject", "(no subject)"))
        sender = _decode_header_value(msg.get("From", "unknown"))
        print(f"\n[email] From: {sender}")
        print(f"        Subject: {subject}")

        saved: list[Path] = []
        for part in msg.walk():
            content_disposition = part.get("Content-Disposition", "")
            if "attachment" not in content_disposition:
                continue

            raw_filename = part.get_filename()
            if not raw_filename:
                continue
            filename = _safe_filename(_decode_header_value(raw_filename))
            if not filename:
                continue

            payload = part.get_payload(decode=True)
            if payload is None:
                continue

            if not self._should_download(filename, len(payload)):
                continue

            # Ensure unique path (avoid overwriting)
            self.download_dir.mkdir(parents=True, exist_ok=True)
            dest = self.download_dir / filename
            counter = 1
            while dest.exists():
                stem = Path(filename).stem
                suffix = Path(filename).suffix
                dest = self.download_dir / f"{stem}_{counter}{suffix}"
                counter += 1

            dest.write_bytes(payload)
            print(f"  [saved] {dest}  ({len(payload) // 1024} KB)")
            saved.append(dest)

        if not saved:
            print("  [info] No attachments found in this email.")
        return saved

    # ------------------------------------------------------------------
    # High-level run
    # ------------------------------------------------------------------

    def run(self) -> list[Path]:
        """Connect, fetch matching emails, download all attachments, disconnect."""
        self.connect()
        all_saved: list[Path] = []
        try:
            ids = self.fetch_email_ids()
            for msg_id in ids:
                saved = self.download_attachments_from_message(msg_id)
                all_saved.extend(saved)
        finally:
            self.disconnect()

        print(f"\n[gmail] Done. {len(all_saved)} attachment(s) downloaded to '{self.download_dir}'.")
        return all_saved
