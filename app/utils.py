from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from flask import request, session, flash, redirect, url_for
from .config import DISCORD_PUBLIC_KEY, logger

def verify_signature(signature, timestamp, body):
    """Verifies the signature of a Discord interaction request."""
    logger.info("Starting signature verification...")
    logger.debug(f"Signature: {signature}")
    logger.debug(f"Timestamp: {timestamp}")
    logger.debug(f"Body: {body}")
    try:
        key = VerifyKey(bytes.fromhex(DISCORD_PUBLIC_KEY))
        message = bytes(timestamp + body, encoding="utf8")
        signature_bytes = bytes.fromhex(signature)
        key.verify(message, signature_bytes)
        logger.info("Signature verification successful.")
        return True
    except BadSignatureError:
        logger.error("Invalid signature.")
        return False
    except Exception as e:
        logger.error(f"Error during signature verification: {e}")
        return False

def handle_admin_action(endpoint):
    """Handles admin actions, checking for test mode."""
    if not session.get("logged_in") or not session.get("is_admin"):
        flash("You do not have permission to perform this action.", "error")
        return redirect(url_for("index"))

    is_test = request.form.get("is_test") == "on"
    # import pdb; pdb.set_trace()
    if is_test:
        logger.info(f"Test mode is enabled for {endpoint}")
        flash(f"Test mode is enabled for {endpoint}", "warning")

    logger.info(f"Performing action: {endpoint} (Test mode: {is_test})")
    flash(f"Performing action: {endpoint} (Test mode: {is_test})", "info")

    return redirect(url_for("index"))
