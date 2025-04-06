from flask import render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf.csrf import validate_csrf, ValidationError
from . import app
from .forms import *
from .discord_oauth import get_discord_user, get_user_guilds, is_admin, exchange_code
from .config import DISCORD_GUILD_ID, DISCORD_ADMIN_ROLE_ID, logger
from .utils import verify_signature, handle_admin_action
from .discord_bot import send_message
from .config import logger, DISCORD_AUTHORIZATION_URL
from .raffle_types import StandardRaffle, LuckyNumberRaffle, RoyalRumbleRaffle
import redis
import os

@app.route("/")
def index():
    start_raffle_form = StartRaffleForm()
    end_raffle_form = EndRaffleForm()
    clear_raffle_form = ClearRaffleForm()
    archive_raffle_form = ArchiveRaffleForm()
    add_participant_form = AddParticipantForm()
    remove_participant_form = RemoveParticipantForm()
    set_participant_limit_form = SetParticipantLimitForm()
    set_entry_limit_form = SetEntryLimitForm()
    set_raffle_name_form = SetRaffleNameForm()
    set_webhook_url_form = SetWebhookURLForm()
    set_admin_role_form = SetAdminRoleForm()
    set_raffle_channel_form = SetRaffleChannelForm()
    set_lucky_number_form = SetLuckyNumberForm()
    set_all_entry_limit_form = SetAllEntryLimitForm()
    raffle_types = [StandardRaffle(), LuckyNumberRaffle(), RoyalRumbleRaffle()]
    return render_template("index.html", user=session.get("user"), is_admin=session.get("is_admin"),
                           guild_name=session.get("guild_name"), start_raffle_form=start_raffle_form,
                           end_raffle_form=end_raffle_form, clear_raffle_form=clear_raffle_form,
                           archive_raffle_form=archive_raffle_form,
                           add_participant_form=add_participant_form,
                           remove_participant_form=remove_participant_form,
                           set_participant_limit_form=set_participant_limit_form,
                           set_entry_limit_form=set_entry_limit_form,
                           set_raffle_name_form=set_raffle_name_form,
                           set_webhook_url_form=set_webhook_url_form,
                           set_admin_role_form=set_admin_role_form,
                           set_raffle_channel_form=set_raffle_channel_form,
                           set_lucky_number_form=set_lucky_number_form,
                           set_all_entry_limit_form=set_all_entry_limit_form,
                           raffle_types=raffle_types)

@app.route("/discord")
async def send_discord_message():
    """Sends a message to the Discord channel."""
    message = "Hello from the web app!"
    return await send_message(message)

@app.route("/login")
def login():
    """Redirects the user to Discord's OAuth2 authorization URL."""
    return redirect(DISCORD_AUTHORIZATION_URL)

@app.route("/callback")
def callback():
    """Handles the callback from Discord's OAuth2 flow."""
    code = request.args.get("code")
    if not code:
        logger.error("OAuth2 callback: Missing authorization code.")
        flash("Failed to get authorization code.", "error")
        return redirect(url_for("index"))

    try:
        # Check if the session is stored in redis
        redis_client = redis.Redis(host=os.getenv("REDIS_HOST", "localhost"),
                                  port=int(os.getenv("REDIS_PORT", "6379")))
        session_key = f"{app.config['SESSION_KEY_PREFIX']}{session.sid}"
        session_data = redis_client.get(session_key)
        if session_data:
            logger.info(f"Session data stored in Redis for key: {session_key}")
        else:
            logger.error(f"Session data not found in Redis for key: {session_key}")
            
        token_data = exchange_code(code)
        access_token = token_data.get("access_token")

        if not access_token:
            logger.error("OAuth2 callback: Failed to get access token.")
            flash("Failed to get access token.", "error")
            return redirect(url_for("index"))

        # Get the user's information
        try:
            user_data = get_discord_user(access_token)
            # Store user data in the session
            session["user"] = user_data
            session["logged_in"] = True  # Set a flag for login status

            # Check for admin
            user_guilds = get_user_guilds(access_token)
            guild_name = is_admin(user_guilds, DISCORD_GUILD_ID, DISCORD_ADMIN_ROLE_ID, access_token)
            session["is_admin"] = True if guild_name else False
            session["guild_name"] = guild_name if isinstance(guild_name, str) else None

            flash("Login successful!", "success")
            return redirect(url_for("index"))
        except requests.exceptions.RequestException as e:
            logger.error(f"OAuth2 callback: Failed to get user information: {e}")
            flash(f"Failed to get user information: {e}", "error")
            return redirect(url_for("index"))

        except requests.exceptions.RequestException as e:
            logger.error(f"OAuth2 callback: Failed to get user information: {e}")
            flash(f"Failed to get user information: {e}", "error")
            return redirect(url_for("index"))  # Redirect to the main page

    except requests.exceptions.RequestException as e:
        logger.error(f"OAuth2 callback: Failed to exchange code for access token: {e}")
        flash("Failed to exchange code for access token.", "error")
        return redirect(url_for("index"))
    except Exception as e:
        logger.exception("OAuth2 callback: An unexpected error occurred.")  # Log the full exception
        flash("An unexpected error occurred.", "error")
        return redirect(url_for("index"))


@app.route("/logout")
def logout():
    """Logs the user out by clearing the session."""
    session.clear()
    session["logged_in"] = False
    return redirect(url_for("index"))  # Redirect to the main page

@app.route("/interactions", methods=["POST"])
def interactions():
    """Handles Discord interactions (e.g., slash commands)."""
    logger.info("Received a request to /interactions")
    signature = request.headers.get("X-Signature-Ed2519")
    timestamp = request.headers.get("X-Signature-Timestamp")
    body = request.data.decode("utf-8")

    logger.debug(f"Signature: {signature}")
    logger.debug(f"Timestamp: {timestamp}")
    logger.debug(f"Body: {body}")

    if not signature or not timestamp:
        logger.error("Missing signature or timestamp.")
        return "Missing signature or timestamp.", 400

    if not verify_signature(signature, timestamp, body):
        logger.error("Signature verification failed.")
        return "Invalid signature.", 401

    data = request.get_json()
    interaction_type = data.get("type")

    logger.debug(f"Interaction type: {interaction_type}")

    if interaction_type == 1:  # Ping Interaction
        logger.info("Responding to Ping interaction.")
        return jsonify({"type": 1})
    elif interaction_type == 2:  # Command Interaction
        command_name = data["data"]["name"]
        logger.info(f"Received command: {command_name}")
        if command_name == "hello":
            logger.info("Responding to 'hello' command.")
            return jsonify({
                "type": 4,
                "data": {
                    "content": "Hello from the bot!"
                }
            })
        else:
            logger.warning(f"Unknown command: {command_name}")
            return "Unknown command.", 400
    elif interaction_type == 3:  # Component Interaction
        logger.info("Responding to Component interaction.")
        return jsonify({"type": 6})
    else:
        logger.warning(f"Invalid interaction type: {interaction_type}")
        return "Invalid interaction type.", 400

@app.route("/start_raffle", methods=["POST"])
def start_raffle():
    """Starts a raffle."""
    form = StartRaffleForm()
    if form.validate_on_submit():
        session["raffle_name"] = form.raffle_name.data
        session["raffle_type"] = form.raffle_type.data
        session["all_entry_limit"] = form.all_entry_limit.data
        request.form.get("is_test")
        return handle_admin_action("start_raffle")
    else:
        flash("CSRF token is missing or invalid", "error")
        return redirect(url_for("index"))

@app.route("/end_raffle", methods=["POST"])
def end_raffle():
    """Ends the raffle."""
    form = EndRaffleForm()
    if form.validate_on_submit():
        return handle_admin_action("end_raffle")
    else:
        flash("CSRF token is missing or invalid", "error")
        return redirect(url_for("index"))

@app.route("/clear_raffle", methods=["POST"])
def clear_raffle():
    """Clears the raffle."""
    form = ClearRaffleForm()
    if form.validate_on_submit():
        return handle_admin_action("clear_raffle")
    else:
        flash("CSRF token is missing or invalid", "error")
        return redirect(url_for("index"))

@app.route("/archive_raffle", methods=["POST"])
def archive_raffle():
    """Archives the raffle."""
    form = ArchiveRaffleForm()
    if form.validate_on_submit():
        return handle_admin_action("archive_raffle")
    else:
        flash("CSRF token is missing or invalid", "error")
        return redirect(url_for("index"))

@app.route("/add_participant", methods=["POST"])
def add_participant():
    """Adds a participant."""
    form = AddParticipantForm()
    if form.validate_on_submit():
        session["user_id"] = form.user_id.data
        session["entries"] = form.entries.data
        return handle_admin_action("add_participant")
    else:
        flash("CSRF token is missing or invalid", "error")
        return redirect(url_for("index"))

@app.route("/remove_participant", methods=["POST"])
def remove_participant():
    """Removes a participant."""
    form = RemoveParticipantForm()
    if form.validate_on_submit():
        session["user_id"] = form.user_id.data
        return handle_admin_action("remove_participant")
    else:
        flash("CSRF token is missing or invalid", "error")
        return redirect(url_for("index"))

@app.route("/set_participant_limit", methods=["POST"])
def set_participant_limit():
    """Sets the participant limit."""
    form = SetParticipantLimitForm()
    if form.validate_on_submit():
        session["participant_limit"] = form.participant_limit.data
        return handle_admin_action("set_participant_limit")
    else:
        flash("CSRF token is missing or invalid", "error")
        return redirect(url_for("index"))

@app.route("/set_entry_limit", methods=["POST"])
def set_entry_limit():
    """Sets the entry limit."""
    form = SetEntryLimitForm()
    if form.validate_on_submit():
        session["entry_limit"] = form.entry_limit.data
        return handle_admin_action("set_entry_limit")
    else:
        flash("CSRF token is missing or invalid", "error")
        return redirect(url_for("index"))

@app.route("/set_raffle_name", methods=["POST"])
def set_raffle_name():
    """Sets the raffle name."""
    form = SetRaffleNameForm()
    if form.validate_on_submit():
        session["raffle_name"] = form.raffle_name.data
        return handle_admin_action("set_raffle_name")
    else:
        flash("CSRF token is missing or invalid", "error")
        return redirect(url_for("index"))

@app.route("/set_webhook_url", methods=["POST"])
def set_webhook_url():
    """Sets the webhook URL."""
    form = SetWebhookURLForm()
    if form.validate_on_submit():
        session["webhook_url"] = form.webhook_url.data
        return handle_admin_action("set_webhook_url")
    else:
        flash("CSRF token is missing or invalid", "error")
        return redirect(url_for("index"))

@app.route("/set_admin_role", methods=["POST"])
def set_admin_role():
    """Sets the admin role."""
    form = SetAdminRoleForm()
    if form.validate_on_submit():
        session["admin_role_id"] = form.admin_role_id.data
        return handle_admin_action("set_admin_role")
    else:
        flash("CSRF token is missing or invalid", "error")
        return redirect(url_for("index"))

@app.route("/set_raffle_channel", methods=["POST"])
def set_raffle_channel():
    """Sets the raffle channel."""
    form = SetRaffleChannelForm()
    if form.validate_on_submit():
        session["raffle_channel_id"] = form.raffle_channel_id.data
        return handle_admin_action("set_raffle_channel")
    else:
        flash("CSRF token is missing or invalid", "error")
        return redirect(url_for("index"))

@app.route("/set_lucky_number", methods=["POST"])
def set_lucky_number():
    """Sets the lucky number."""
    form = SetLuckyNumberForm()
    if form.validate_on_submit():
        session["lucky_number"] = form.lucky_number.data
        return handle_admin_action("set_lucky_number")
    else:
        flash("CSRF token is missing or invalid", "error")
        return redirect(url_for("index"))

@app.route("/set_all_entry_limit", methods=["POST"])
def set_all_entry_limit():
    """Sets the entry limit for all participants."""
    form = SetAllEntryLimitForm()
    if form.validate_on_submit():
        session["all_entry_limit"] = form.all_entry_limit.data
        return handle_admin_action("set_all_entry_limit")
    else:
        flash("CSRF token is missing or invalid", "error")
        return redirect(url_for("index"))
