"""
Gmail Reader — connects via IMAP (App Password auth), searches for emails
with certificate attachments and downloads them locally.

Setup:
  1. Enable 2-Step Verification: myaccount.google.com → Security
  2. Create App Password: myaccount.google.com/apppasswords
  3. Export: export GMAIL_APP_PASSWORD="xxxxxxxxxxxxxxxx"
  4. Enable IMAP in Gmail: Settings → See all settings → Forwarding and POP/IMAP
"""

import email
import imaplib
import os
import re
import socket
from email.header import decode_header
from pathlib import Path

_IMAP_TIMEOUT_SECS = 30


def _decode_header_value(value: str) -> str:
    parts = decode_header(value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return "".join(decoded)


def _safe_filename(name: str) -> str:
    keepchars = (" ", ".", "_", "-")
    return "".join(c for c in name if c.isalnum() or c in keepchars).rstrip()


def _extract_body_text(msg) -> str:
    """Return plain-text body parts joined together."""
    parts = []
    for part in msg.walk():
        if (part.get_content_type() == "text/plain"
                and "attachment" not in part.get("Content-Disposition", "")):
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                parts.append(payload.decode(charset, errors="replace"))
    return "\n".join(parts)


def _extract_as2_id(body: str):
    """
    Parse AS2 ID from email body.
    Matches patterns like:
      AS2 ID: OpenAS2A_OID
      AS2ID=PartnerA_OID
      as2_id : PartnerB_OID
    Returns the value or None if not found.
    """
    match = re.search(
        r'AS2[-_\s]?ID\s*[:=\-]\s*([A-Za-z0-9_\-\.]+)',
        body,
        re.IGNORECASE,
    )
    return match.group(1).strip() if match else None


class GmailReader:
    def __init__(self, config: dict):
        gmail_cfg = config["gmail"]
        self.email_address = gmail_cfg["email"]
        self.app_password = os.environ.get("GMAIL_APP_PASSWORD", "").replace(" ", "").strip()
        self.imap_host = gmail_cfg["imap_host"]
        self.imap_port = gmail_cfg["imap_port"]

        search_cfg = gmail_cfg.get("search", {})
        self.folder = search_cfg.get("folder", "INBOX")
        self.subject_filter = search_cfg.get("subject_filter", "")
        self.unread_only = search_cfg.get("unread_only", False)
        self.max_emails = search_cfg.get("max_emails", 10)

        attach_cfg = gmail_cfg.get("attachments", {})
        self.download_dir = Path(attach_cfg.get("download_dir", "downloads/certs"))
        raw_ext = attach_cfg.get("allowed_extensions", [])
        self.allowed_extensions = {e.lower().lstrip(".") for e in raw_ext} if raw_ext else set()
        self.max_size_bytes = int(attach_cfg.get("max_size_mb", 0)) * 1024 * 1024

        self._imap: imaplib.IMAP4_SSL | None = None

    def connect(self) -> None:
        if not self.app_password:
            raise EnvironmentError(
                "GMAIL_APP_PASSWORD environment variable is not set.\n"
                "Generate one at: myaccount.google.com/apppasswords"
            )
        print(f"[gmail] Connecting to {self.imap_host}:{self.imap_port} …")
        self._imap = imaplib.IMAP4_SSL(
            self.imap_host, self.imap_port,
            timeout=_IMAP_TIMEOUT_SECS,
        )
        try:
            self._imap.login(self.email_address, self.app_password)
        except imaplib.IMAP4.error as e:
            raise RuntimeError(
                f"Gmail login failed: {e}\n\n"
                "Checklist:\n"
                "  1. Enable IMAP: Gmail → Settings → Forwarding and POP/IMAP\n"
                "  2. Use App Password (not regular password)\n"
                "  3. Password must be 16 chars (no spaces)\n"
                f"  4. Password length received: {len(self.app_password)} chars"
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

    def _build_search_criteria(self) -> str:
        parts = []
        if self.unread_only:
            parts.append("UNSEEN")
        if self.subject_filter:
            parts.append(f'SUBJECT "{self.subject_filter}"')
        return " ".join(parts) if parts else "ALL"

    def fetch_email_ids(self) -> list:
        assert self._imap, "Not connected"
        self._imap.select(self.folder)
        criteria = self._build_search_criteria()
        print(f"[gmail] Searching '{self.folder}' with: {criteria!r}")
        status, data = self._imap.search(None, criteria)
        if status != "OK":
            raise RuntimeError(f"IMAP search failed: {data}")
        ids = data[0].split()
        ids = ids[::-1][: self.max_emails]
        print(f"[gmail] Found {len(ids)} email(s).")
        return ids

    def _should_download(self, filename: str, size: int) -> bool:
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if self.allowed_extensions and ext not in self.allowed_extensions:
            return False
        if self.max_size_bytes and size > self.max_size_bytes:
            print(f"  [skip] {filename} ({size // 1024} KB) exceeds size limit.")
            return False
        return True

    def download_attachments_from_message(self, msg_id: bytes) -> tuple:
        """
        Returns (saved_paths, as2_id, message_id) where:
          saved_paths — list of Path objects for downloaded attachments
          as2_id      — AS2 ID extracted from the email body, or None
          message_id  — RFC 2822 Message-ID header value (stable unique ID)
        """
        assert self._imap
        status, data = self._imap.fetch(msg_id, "(RFC822)")
        if status != "OK":
            return [], None, None

        raw = data[0][1]
        msg = email.message_from_bytes(raw)

        message_id = msg.get("Message-ID", "").strip()
        subject = _decode_header_value(msg.get("Subject", "(no subject)"))
        sender = _decode_header_value(msg.get("From", "unknown"))
        print(f"\n[email] From: {sender}")
        print(f"        Subject: {subject}")
        print(f"        Message-ID: {message_id or '(none)'}")

        body = _extract_body_text(msg)
        as2_id = _extract_as2_id(body)
        if as2_id:
            print(f"        AS2 ID (from body): {as2_id}")
        else:
            print("        AS2 ID (from body): not found")

        saved = []
        for part in msg.walk():
            if "attachment" not in part.get("Content-Disposition", ""):
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
            print("  [info] No certificate attachments in this email.")
        return saved, as2_id, message_id

    def run(self, seen_ids: set = None) -> tuple:
        """
        Fetch new emails not present in seen_ids.

        Returns (downloads, new_seen_ids) where:
          downloads     — list of dicts: [{"path": Path, "as2_id": str|None, "message_id": str}, ...]
          new_seen_ids  — set of Message-IDs that were processed this run (to be saved by caller)
        """
        if seen_ids is None:
            seen_ids = set()

        self.connect()
        all_saved = []
        new_seen_ids = set()
        try:
            ids = self.fetch_email_ids()
            for msg_id in ids:
                paths, as2_id, message_id = self.download_attachments_from_message(msg_id)
                if message_id and message_id in seen_ids:
                    print(f"  [skip] Already processed — Message-ID: {message_id}")
                    continue
                if message_id:
                    new_seen_ids.add(message_id)
                for p in paths:
                    all_saved.append({"path": p, "as2_id": as2_id, "message_id": message_id})
        finally:
            self.disconnect()
        print(f"\n[gmail] Done. {len(all_saved)} new cert attachment(s) in '{self.download_dir}'.")
        return all_saved, new_seen_ids
