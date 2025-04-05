import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort, flash
import discord
from discord.ext import commands
from nacl.signing import VerifyKey
import requests # type: ignore
from urllib.parse import quote_plus
from nacl.exceptions import BadSignatureError
from flask_wtf import FlaskForm # type: ignore
from wtforms import StringField, SubmitField # type: ignore
from wtforms.validators import DataRequired # type: ignore
from flask_wtf.csrf import CSRFProtect, validate_csrf, generate_csrf # type: ignore
from wtforms import ValidationError # type: ignore
import logging
from flask_limiter import Limiter # type: ignore
from flask_limiter.util import get_remote_address # type: ignore
from flask_session import Session # type: ignore
import redis # type: ignore
import multiprocessing
from multiprocessing import Queue
import traceback
import asyncio
from datetime import timedelta


load_dotenv()

# Inspect environment variables
print("Environment variables (Flask App):")
for key, value in os.environ.items():
    print(f"{key}={value}")
print("-----------------------")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Configure CSRF protection
csrf = CSRFProtect(app)

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True
    session['csrf_token'] = generate_csrf()

# Configure logging
log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=log_level,
                    format='%(asctime)s [%(levelname)s] %(name)s - %(message)s')
logger = logging.getLogger(__name__)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri=f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}",
    strategy="fixed-window"
)

# Configure Redis session
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_PERMANENT"] = True  # Make sessions persistent
app.config["SESSION_USE_SIGNER"] = True  # Securely sign the session cookie
app.config["SESSION_REDIS"] = redis.Redis(host=os.getenv("REDIS_HOST", "localhost"), port=int(os.getenv("REDIS_PORT", "6379")))  # Redis connection details
app.config["SESSION_KEY_PREFIX"] = "session:"  # Add a prefix to session keys
Session(app)  # Initialize Flask-Session

# Discord Bot Setup
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
CHANNEL_ID = os.getenv("CHANNEL_ID")

if not BOT_TOKEN:
    print("Error: BOT_TOKEN is not set in the .env file.")

intents = discord.Intents.default()
intents.messages = True
intents.guilds = True
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents)

discord_channel_id = None
discord_guild_id = None
discord_admin_role_id = None

# Discord OAuth2 Configuration
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
if DISCORD_REDIRECT_URI:
    DISCORD_REDIRECT_URI = quote_plus(DISCORD_REDIRECT_URI.encode('utf-8'))  # Encode to bytes
else:
    print("Error: DISCORD_REDIRECT_URI is not set in the .env file.")
    # Handle the case where the variable is not set, e.g., set a default or exit
    exit()  # Or set a default value: DISCORD_REDIRECT_URI = "http://localhost:5000/callback"
print(f"DISCORD_REDIRECT_URI is {DISCORD_REDIRECT_URI}")
SCOPES = "identify email guilds guilds.members.read"

DISCORD_AUTHORIZATION_URL = f"https://discord.com/api/oauth2/authorize?client_id={DISCORD_CLIENT_ID}&redirect_uri={DISCORD_REDIRECT_URI}&response_type=code&scope={SCOPES}"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"
DISCORD_API_BASE_URL = "https://discord.com/api/v10"
DISCORD_GUILD_ID = os.getenv("DISCORD_GUILD_ID")
DISCORD_ADMIN_ROLE_ID = os.getenv("DISCORD_ADMIN_ROLE_ID")
DISCORD_PUBLIC_KEY = os.getenv("DISCORD_PUBLIC_KEY")


def get_discord_user(access_token):
    """Fetches the user's Discord data."""
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{DISCORD_API_BASE_URL}/users/@me", headers=headers)
    response.raise_for_status()
    return response.json()


def get_user_guilds(access_token):
    """Fetches the guilds the user is in."""
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{DISCORD_API_BASE_URL}/users/@me/guilds", headers=headers)
    response.raise_for_status()
    return response.json()

def get_user_guild_member(access_token, guild_id):
    """Fetches the user's member data in a specific guild."""
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{DISCORD_API_BASE_URL}/users/@me/guilds/{guild_id}/member", headers=headers)
    if response.status_code == 404:
        return None  # User is not a member of the guild
    response.raise_for_status()
    return response.json()

def is_admin(user_guilds, guild_id, admin_role_id, access_token):
    """Checks if the user is an admin in the specified guild."""
    for guild in user_guilds:
        if guild["id"] == guild_id:
            # User is in the guild, now check for the admin role
            member_data = get_user_guild_member(access_token, guild_id)
            if member_data is None:
                return False
            
            if "roles" in member_data:
                if str(admin_role_id) in member_data["roles"]:
                    return guild["name"]
            return False
    return False


@bot.event
async def on_ready():
    print(f"Bot connected as {bot.user}")
    global discord_channel_id, discord_guild_id, discord_admin_role_id
    if CHANNEL_ID:
        discord_channel_id = int(CHANNEL_ID)
    if DISCORD_GUILD_ID:
        discord_guild_id = int(DISCORD_GUILD_ID)
    if DISCORD_ADMIN_ROLE_ID:
        discord_admin_role_id = int(DISCORD_ADMIN_ROLE_ID)
    try:
        # Set the desired permissions
        permissions = discord.Permissions()
        permissions.read_messages = True
        permissions.send_messages = True
        permissions.use_application_commands = True
        permissions.embed_links = True

        # Generate the invite link with the specified permissions
        invite_link = discord.utils.oauth_url(client_id=bot.user.id, permissions=permissions)
        print(f"Invite the bot using this URL: {invite_link}")
    except Exception as e:
        print(f"Error generating invite link: {e}")


# Flask Routes
@app.route("/")
def index():
    return render_template("index.html", user=session.get("user"), is_admin=session.get("is_admin"), guild_name=session.get("guild_name"), csrf_token=session.get('csrf_token'))


@app.route("/discord")
def send_discord_message():
    """Sends a message to the Discord channel."""
    message = "Hello from the web app!"
    if discord_channel_id:
        # Get the channel
        channel = bot.get_channel(int(discord_channel_id))
        if channel:
            # Send the message
            asyncio.run(channel.send(message))
            return "Message sent to Discord!"
        else:
            return "Channel not found."
    else:
        return "Channel ID not set."


@app.route("/login")
def login():
    """Redirects the user to Discord's OAuth2 authorization URL."""
    return redirect(DISCORD_AUTHORIZATION_URL)


@app.route("/callback")
@limiter.limit("10/minute")  # Apply rate limiting to the /callback route
def callback():
    """Handles the callback from Discord's OAuth2 flow."""
    code = request.args.get("code")
    if not code:
        logger.error("OAuth2 callback: Missing authorization code.")
        flash("Failed to get authorization code.", "error")
        return redirect(url_for("index"))

    try:
        # Check if the session is stored in redis
        redis_client = redis.Redis(host=os.getenv("REDIS_HOST", "localhost"), port=int(os.getenv("REDIS_PORT", "6379")))
        session_key = f"{app.config['SESSION_KEY_PREFIX']}{session.sid}"
        session_data = redis_client.get(session_key)
        if session_data:
            logger.info(f"Session data stored in Redis for key: {session_key}")
        else:
            logger.error(f"Session data not found in Redis for key: {session_key}")
            
        # Exchange the code for an access token
        data = {
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": os.getenv("DISCORD_REDIRECT_URI"),
            "scope": "identify email guilds guilds.members.read"
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(DISCORD_TOKEN_URL, data=data, headers=headers)
        response.raise_for_status()
        token_data = response.json()
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


@app.route("/interactions", methods=["POST"])
def interactions():
    """Handles Discord interactions (e.g., slash commands)."""
    logger.info("Received a request to /interactions")
    signature = request.headers.get("X-Signature-Ed25519")
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


def execute_bot_command(command):
    """Puts a bot command into the command queue."""
    app.queue.put(command)
    print(f"Command '{command}' added to the queue.")


def handle_admin_action(endpoint):
    """Handles admin actions, checking for test mode."""
    if not session.get("logged_in") or not session.get("is_admin"):
        flash("You do not have permission to perform this action.", "error")
        return redirect(url_for("index"))

    is_test = request.form.get("is_test") == "on"
    #import pdb; pdb.set_trace()
    if is_test:
        logger.info(f"Test mode is enabled for {endpoint}")
        flash(f"Test mode is enabled for {endpoint}", "warning")

    logger.info(f"Performing action: {endpoint} (Test mode: {is_test})")
    flash(f"Performing action: {endpoint} (Test mode: {is_test})", "info")

    return redirect(url_for("index"))


@app.route("/start_raffle", methods=["POST"])
def start_raffle():
    """Starts a raffle."""
    return handle_admin_action("start_raffle")


@app.route("/end_raffle", methods=["POST"])
def end_raffle():
    """Ends the raffle."""
    return handle_admin_action("end_raffle")


@app.route("/clear_raffle", methods=["POST"])
def clear_raffle():
    """Clears the raffle."""
    return handle_admin_action("clear_raffle")


@app.route("/archive_raffle", methods=["POST"])
def archive_raffle():
    """Archives the raffle."""
    return handle_admin_action("archive_raffle")


@app.route("/add_participant", methods=["POST"])
def add_participant():
    """Adds a participant."""
    return handle_admin_action("add_participant")


@app.route("/remove_participant", methods=["POST"])
def remove_participant():
    """Removes a participant."""
    return handle_admin_action("remove_participant")


@app.route("/set_participant_limit", methods=["POST"])
def set_participant_limit():
    """Sets the participant limit."""
    return handle_admin_action("set_participant_limit")


@app.route("/set_entry_limit", methods=["POST"])
def set_entry_limit():
    """Sets the entry limit."""
    return handle_admin_action("set_entry_limit")


@app.route("/set_raffle_name", methods=["POST"])
def set_raffle_name():
    """Sets the raffle name."""
    return handle_admin_action("set_raffle_name")


@app.route("/set_webhook_url", methods=["POST"])
def set_webhook_url():
    """Sets the webhook URL."""
    return handle_admin_action("set_webhook_url")


@app.route("/set_admin_role", methods=["POST"])
def set_admin_role():
    """Sets the admin role."""
    return handle_admin_action("set_admin_role")


@app.route("/set_raffle_channel", methods=["POST"])
def set_raffle_channel():
    """Sets the raffle channel."""
    return handle_admin_action("set_raffle_channel")


@app.route("/set_lucky_number", methods=["POST"])
def set_lucky_number():
    """Sets the lucky number."""
    return handle_admin_action("set_lucky_number")


@app.route("/set_all_entry_limit", methods=["POST"])
def set_all_entry_limit():
    """Sets the entry limit for all participants."""
    if not session.get("logged_in") or not session.get("is_admin"):
        flash("You do not have permission to perform this action.", "error")
        return redirect(url_for("index"))

    try:
        validate_csrf(request.form.get('csrf_token'))
    except ValidationError:
        flash('CSRF token is missing or invalid', 'error')
        return redirect(url_for('index'))

    is_test = request.form.get("is_test") == "on"
    all_entry_limit = request.form.get("all_entry_limit")

    if is_test:
        logger.info(f"Test mode is enabled for set_all_entry_limit")
        flash(f"Test mode is enabled for set_all_entry_limit", "warning")

    logger.info(f"Performing action: set_all_entry_limit (Test mode: {is_test})")
    flash(f"Performing action: set_all_entry_limit (Test mode: {is_test})", "info")

    return redirect(url_for("index"))

# ... (your existing app.py code) ...

Session(app)  # Initialize Flask-Session

# Test Redis connection
try:
    redis_client = redis.Redis(host=os.getenv("REDIS_HOST", "localhost"), port=int(os.getenv("REDIS_PORT", "6379")))
    response = redis_client.ping()
    if response:
        logger.info("Redis connection successful!")
    else:
        logger.error("Redis ping failed!")
except redis.exceptions.ConnectionError as e:
    logger.error(f"Redis connection failed: {e}")
except Exception as e:
    logger.error(f"An unexpected error occurred while testing Redis: {e}")

# ... (rest of your app.py code) ...
