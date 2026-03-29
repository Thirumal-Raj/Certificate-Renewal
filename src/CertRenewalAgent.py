"""
OpenAS2 Certificate Renewal Agent
Automates: check expiry → backup → renew → restart server → notify via Gmail
"""

import subprocess
import os
import shutil
import smtplib
import schedule
import time
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ─── CONFIG ───────────────────────────────────────────────────────────────────
OPENAS2_HOME     = os.path.expanduser("~/downloads/OpenAS2Server-4.8.0")
KEYSTORE_PATH    = f"{OPENAS2_HOME}/config/as2_certs.p12"
KEYSTORE_PASS    = "testas2"
KEYSTORE_TYPE    = "PKCS12"
OPENAS2_BIN      = f"{OPENAS2_HOME}/bin/start-openas2.sh"

# Days before expiry to trigger renewal
RENEWAL_THRESHOLD_DAYS = 30

# New certificate validity (days)
CERT_VALIDITY_DAYS = 730  # 2 years

# Certificate details — update these
CERT_DETAILS = {
    "mycompany": {
        "dname": "CN=MyCompany, OU=IT, O=MyCompany Inc, L=Houston, ST=Texas, C=US",
        "alias": "mycompany",
    },
    "partnera": {
        "dname": "CN=PartnerA, OU=IT, O=PartnerA Inc, L=Houston, ST=Texas, C=US",
        "alias": "partnera",
    },
    "partnerb": {
        "dname": "CN=PartnerB, OU=IT, O=PartnerB Inc, L=Houston, ST=Texas, C=US",
        "alias": "partnerb",
    },
}

# Gmail config — fill these in
GMAIL_SENDER   = "your_email@gmail.com"
GMAIL_PASSWORD = "your_app_password"       # Use Gmail App Password
GMAIL_RECEIVER = "your_email@gmail.com"

# ─── LOGGING ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(f"{OPENAS2_HOME}/logs/cert_renewal_agent.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)


# ─── STEP 1: CHECK EXPIRY ─────────────────────────────────────────────────────
def get_cert_expiry(alias: str) -> datetime | None:
    """Returns expiry date of a certificate alias from the keystore."""
    try:
        result = subprocess.run(
            [
                "keytool", "-list", "-v",
                "-alias", alias,
                "-keystore", KEYSTORE_PATH,
                "-storetype", KEYSTORE_TYPE,
                "-storepass", KEYSTORE_PASS,
            ],
            capture_output=True, text=True, check=True,
        )
        for line in result.stdout.splitlines():
            if "until:" in line.lower():
                # Example: "Valid from: Fri Mar 27 2026 until: Thu Oct 10 2028"
                date_str = line.split("until:")[-1].strip()
                return datetime.strptime(date_str, "%a %b %d %H:%M:%S %Z %Y")
    except subprocess.CalledProcessError as e:
        log.error(f"keytool error for alias '{alias}': {e.stderr}")
    return None


def check_all_certs() -> dict:
    """Check all aliases and return their expiry status."""
    report = {}
    for alias in CERT_DETAILS:
        expiry = get_cert_expiry(alias)
        if expiry:
            days_left = (expiry - datetime.now()).days
            report[alias] = {"expiry": expiry, "days_left": days_left}
            log.info(f"  [{alias}] Expires: {expiry.date()} | Days left: {days_left}")
        else:
            report[alias] = {"expiry": None, "days_left": -1}
            log.warning(f"  [{alias}] Could not read expiry date")
    return report


# ─── STEP 2: BACKUP KEYSTORE ──────────────────────────────────────────────────
def backup_keystore() -> str:
    """Backup the keystore before any changes."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{OPENAS2_HOME}/config/as2_certs_backup_{timestamp}.p12"
    shutil.copy2(KEYSTORE_PATH, backup_path)
    log.info(f"Keystore backed up to: {backup_path}")
    return backup_path


# ─── STEP 3: RENEW CERTIFICATE ────────────────────────────────────────────────
def renew_certificate(alias: str) -> bool:
    """Renew a certificate by replacing old alias with a new one."""
    details = CERT_DETAILS.get(alias)
    if not details:
        log.error(f"No cert details found for alias '{alias}'")
        return False

    temp_alias = f"{alias}_new"

    try:
        # Step A: Generate new cert with temp alias
        log.info(f"Generating new certificate for '{alias}'...")
        subprocess.run(
            [
                "keytool", "-genkeypair",
                "-alias", temp_alias,
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-sigalg", "SHA256withRSA",
                "-dname", details["dname"],
                "-validity", str(CERT_VALIDITY_DAYS),
                "-keystore", KEYSTORE_PATH,
                "-storetype", KEYSTORE_TYPE,
                "-storepass", KEYSTORE_PASS,
                "-keypass", KEYSTORE_PASS,
            ],
            capture_output=True, text=True, check=True,
        )

        # Step B: Delete old alias
        log.info(f"Deleting old certificate '{alias}'...")
        subprocess.run(
            [
                "keytool", "-delete",
                "-alias", alias,
                "-keystore", KEYSTORE_PATH,
                "-storetype", KEYSTORE_TYPE,
                "-storepass", KEYSTORE_PASS,
            ],
            capture_output=True, text=True, check=True,
        )

        # Step C: Rename temp alias to original
        log.info(f"Renaming '{temp_alias}' to '{alias}'...")
        subprocess.run(
            [
                "keytool", "-changealias",
                "-alias", temp_alias,
                "-destalias", alias,
                "-keystore", KEYSTORE_PATH,
                "-storetype", KEYSTORE_TYPE,
                "-storepass", KEYSTORE_PASS,
            ],
            capture_output=True, text=True, check=True,
        )

        log.info(f"Certificate '{alias}' renewed successfully!")
        return True

    except subprocess.CalledProcessError as e:
        log.error(f"Failed to renew '{alias}': {e.stderr}")
        return False


# ─── STEP 4: RESTART OPENAS2 ─────────────────────────────────────────────────
def restart_openas2():
    """Stop and restart the OpenAS2 server."""
    log.info("Restarting OpenAS2 server...")
    try:
        # Kill existing process
        subprocess.run(
            ["pkill", "-f", "OpenAS2Server"],
            capture_output=True,
        )
        time.sleep(3)

        # Start fresh
        subprocess.Popen(
            ["sh", OPENAS2_BIN],
            cwd=f"{OPENAS2_HOME}/bin",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log.info("OpenAS2 server restarted successfully.")
    except Exception as e:
        log.error(f"Failed to restart OpenAS2: {e}")


# ─── STEP 5: GMAIL NOTIFICATION ───────────────────────────────────────────────
def send_email(subject: str, body: str):
    """Send a notification email via Gmail."""
    try:
        msg = MIMEMultipart()
        msg["From"]    = GMAIL_SENDER
        msg["To"]      = GMAIL_RECEIVER
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_SENDER, GMAIL_PASSWORD)
            server.sendmail(GMAIL_SENDER, GMAIL_RECEIVER, msg.as_string())

        log.info(f"Email sent: {subject}")
    except Exception as e:
        log.error(f"Failed to send email: {e}")


def build_email_body(report: dict, renewed: list) -> str:
    rows = ""
    for alias, info in report.items():
        days = info["days_left"]
        expiry = info["expiry"].date() if info["expiry"] else "Unknown"
        status = "✅ OK" if days > RENEWAL_THRESHOLD_DAYS else "🔄 Renewed" if alias in renewed else "⚠️ Expiring"
        color = "#2d8a4e" if "OK" in status else "#1a6fa3" if "Renewed" in status else "#c0392b"
        rows += f"""
        <tr>
          <td style='padding:8px;border:1px solid #ddd'>{alias}</td>
          <td style='padding:8px;border:1px solid #ddd'>{expiry}</td>
          <td style='padding:8px;border:1px solid #ddd'>{days} days</td>
          <td style='padding:8px;border:1px solid #ddd;color:{color};font-weight:bold'>{status}</td>
        </tr>"""

    return f"""
    <html><body>
    <h2 style='color:#333'>OpenAS2 Certificate Renewal Report</h2>
    <p>Checked on: <strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong></p>
    <table style='border-collapse:collapse;width:100%'>
      <tr style='background:#f2f2f2'>
        <th style='padding:8px;border:1px solid #ddd'>Alias</th>
        <th style='padding:8px;border:1px solid #ddd'>Expiry Date</th>
        <th style='padding:8px;border:1px solid #ddd'>Days Left</th>
        <th style='padding:8px;border:1px solid #ddd'>Status</th>
      </tr>
      {rows}
    </table>
    <p style='color:#888;font-size:12px'>OpenAS2 Certificate Renewal Agent</p>
    </body></html>"""


# ─── MAIN AGENT ───────────────────────────────────────────────────────────────
def run_agent():
    log.info("=" * 60)
    log.info("OpenAS2 Certificate Renewal Agent started")
    log.info("=" * 60)

    # Step 1: Check all cert expiries
    log.info("Step 1: Checking certificate expiry dates...")
    report = check_all_certs()

    # Step 2: Find certs needing renewal
    to_renew = [
        alias for alias, info in report.items()
        if info["days_left"] != -1 and info["days_left"] <= RENEWAL_THRESHOLD_DAYS
    ]

    renewed = []
    if to_renew:
        log.info(f"Step 2: Certificates needing renewal: {to_renew}")

        # Step 3: Backup keystore
        backup_keystore()

        # Step 4: Renew each cert
        for alias in to_renew:
            success = renew_certificate(alias)
            if success:
                renewed.append(alias)

        # Step 5: Restart OpenAS2 if any cert renewed
        if renewed:
            restart_openas2()
    else:
        log.info("All certificates are valid. No renewal needed.")

    # Step 6: Send email report
    subject = f"OpenAS2 Cert Report - {len(renewed)} renewed - {datetime.now().date()}"
    body = build_email_body(report, renewed)
    send_email(subject, body)

    log.info("Agent run complete.")


# ─── SCHEDULER ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("Scheduling agent to run daily at 08:00 AM...")

    # Run immediately on start
    run_agent()

    # Then schedule daily
    schedule.every().day.at("08:00").do(run_agent)

    while True:
        schedule.run_pending()
        time.sleep(60)