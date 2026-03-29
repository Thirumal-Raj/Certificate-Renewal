"""
Certificate Checker — reads X.509 certificates (PEM, DER, PKCS#12)
and reports expiry dates and days remaining.
"""
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


class CertChecker:
    """Parse certificate files and return expiry information."""

    def check(self, cert_path: Path) -> Optional[dict]:
        """
        Returns dict:
          path, subject, issuer, expiry_date, days_remaining, expired
        Returns None if the file cannot be parsed as a certificate.
        """
        data = cert_path.read_bytes()
        ext = cert_path.suffix.lower().lstrip(".")

        cert = None
        if ext in ("p12", "pfx"):
            cert = self._load_pkcs12(data)
        elif ext == "der":
            cert = self._load_der(data)
        elif ext == "cer":
            cert = self._load_cer(data)
        else:
            cert = self._load_pem_or_der(data)

        if cert is None:
            log.warning(f"Cannot parse certificate: {cert_path.name}")
            return None

        try:
            # cryptography >= 42 exposes not_valid_after_utc; older uses not_valid_after
            if hasattr(cert, "not_valid_after_utc"):
                expiry = cert.not_valid_after_utc
            else:
                expiry = cert.not_valid_after.replace(tzinfo=timezone.utc)

            now = datetime.now(tz=timezone.utc)
            days = (expiry - now).days

            return {
                "path": cert_path,
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "expiry_date": expiry.strftime("%Y-%m-%d"),
                "days_remaining": max(days, 0),
                "expired": days < 0,
            }
        except Exception as e:
            log.warning(f"Failed to read cert fields from {cert_path.name}: {e}")
            return None

    def check_all(self, paths: list) -> list:
        """Check a list of certificate paths, skip unparseable files."""
        results = []
        for p in paths:
            info = self.check(Path(p))
            if info:
                results.append(info)
        return results

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    def _load_pem_or_der(self, data: bytes):
        try:
            from cryptography import x509
            if b"-----BEGIN" in data:
                return x509.load_pem_x509_certificate(data)
            return x509.load_der_x509_certificate(data)
        except Exception:
            return None

    def _load_cer(self, data: bytes):
        """Load a .cer file — tries DER first (most common), then PEM."""
        try:
            from cryptography import x509
            try:
                return x509.load_der_x509_certificate(data)
            except Exception:
                pass
            if b"-----BEGIN" in data:
                return x509.load_pem_x509_certificate(data)
        except Exception:
            pass
        return None

    def _load_der(self, data: bytes):
        try:
            from cryptography import x509
            return x509.load_der_x509_certificate(data)
        except Exception:
            return None

    def _load_pkcs12(self, data: bytes, password: bytes = None):
        try:
            from cryptography.hazmat.primitives.serialization.pkcs12 import (
                load_key_and_certificates,
            )
            _, cert, _ = load_key_and_certificates(data, password)
            return cert
        except Exception:
            return None
