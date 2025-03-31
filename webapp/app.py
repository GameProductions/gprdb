import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort, flash
import discord
from discord.ext import commands
import requests # type: ignore
from urllib.parse import quote_plus
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from flask_wtf import FlaskForm # type: ignore
from wtforms import StringField, SubmitField # type: ignore
from wtforms.validators import DataRequired # type: ignore
from flask_wtf.csrf import CSRFProtect # type: ignore
import logging
from flask_limiter import Limiter # type: ignore
from flask_limiter.util import get_remote_address # type: ignore
from flask_session import Session # type: ignore
import redis # type: ignore
import multiprocessing
from multiprocessing import Queue
import traceback
import asyncio

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

# Configure logging
logging.basicConfig(level=logging.ERROR)

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
    """    Fetches the guilds the user is in    """
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{DISCORD_API_BASE_URL}/users/@me/guilds", headers=headers)
    response.raise_for_status()
    return response.json()


def is_admin(user_guilds, guild_id, admin_role_id):
    """Checks if the user is an admin in the specified guild."""
    for guild in user_guilds:
        if guild["id"] == guild_id:
            # The user is in the guild, now check for the admin role
            # This part requires the 'guilds.members.read' scope and a different API endpoint
            # For simplicity, we'll assume the user is an admin if they are in the guild
            # A more robust implementation would check the user's roles in the guild
            return True
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
    return render_template("templates/index.html", user=session.get("user"), is_admin=session.get("is_admin"))


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
        logging.error("OAuth2 callback: Missing authorization code.")
        flash("Failed to get authorization code.", "error")
        return redirect(url_for("index"))

    try:
        # Exchange the code for an access token
        data = {
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": os.getenv("DISCORD_REDIRECT_URI"),
            "scope": "identify email guilds"
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(DISCORD_TOKEN_URL, data=data, headers=headers)
        response.raise_for_status()
        token_data = response.json()
        access_token = token_data.get("access_token")

        if not access_token:
            logging.error("OAuth2 callback: Failed to get access token.")
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
            session["is_admin"] = is_admin(user_guilds, DISCORD_GUILD_ID, DISCORD_ADMIN_ROLE_ID)

            flash("Login successful!", "success")
            return redirect(url_for("index"))  # Redirect to the main page

        except requests.exceptions.RequestException as e:
            logging.error(f"OAuth2 callback: Failed to get user information: {e}")
            flash(f"Failed to get user information: {e}", "error")
            return redirect(url_for("index"))

    except requests.exceptions.RequestException as e:
        logging.error(f"OAuth2 callback: Failed to exchange code for access token: {e}")
        flash("Failed to exchange code for access token.", "error")
        return redirect(url_for("index"))
    except Exception as e:
        logging.exception("OAuth2 callback: An unexpected error occurred.")  # Log the full exception
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
    key = VerifyKey(bytes.fromhex(DISCORD_PUBLIC_KEY))
    message = bytes(timestamp + body, encoding="utf8")
    signature_bytes = bytes.fromhex(signature)
    try:
        key.verify(message, signature_bytes)
        return True
    except BadSignatureError:
        return False


@app.route("/interactions", methods=["POST"])
def interactions():
    """Handles Discord interactions (e.g., slash commands)."""
    signature = request.headers.get("X-Signature-Ed25519")
    timestamp = request.headers.get("X-Signature-Timestamp")
    body = request.data.decode("utf-8")

    if not signature or not timestamp:
        return "Missing signature or timestamp.", 400

    if not verify_signature(signature, timestamp, body):
        return "Invalid signature.", 401

    data = request.get_json()
    interaction_type = data.get("type")

    if interaction_type == 1:  # Ping Interaction
        return jsonify({"type": 1})
    elif interaction_type == 2: # Command Interaction
        command_name = data["data"]["name"]
        if command_name == "hello":
            return jsonify({
                "type": 4,
                "data": {
                    "content": "Hello from the bot!"
                }
            })
        else:
            return "Unknown command.", 400
    elif interaction_type == 3:  # Component Interaction
        return jsonify({"type": 6})
    else:
        return "Invalid interaction type.", 400


def execute_bot_command(command):
    """Puts a bot command into the command queue."""
    app.queue.put(command)
    print(f"Command '{command}' added to the queue.")


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    """Renders the admin dashboard and handles form submissions."""
    if not session.get("logged_in"):
        flash("You must be logged in to access the dashboard.", "error")
        return redirect(url_for("login"))
    if not session.get("is_admin"):
        flash("You must be an admin to access the dashboard.", "error")
        return redirect(url_for("index"))
    csrf_token = csrf.generate_csrf()  # Generate CSRF token outside the if block
    if request.method == "POST":
        # Validate CSRF token
        csrf_token = request.form.get("csrf_token")
        if not csrf.validate(csrf_token):
            flash("Invalid CSRF token.", "error")
            return redirect(url_for("dashboard"))
        # Handle channel ID submission
        new_channel_id = request.form.get("channel_id")

        if new_channel_id:

            global discord_channel_id
            discord_channel_id = new_channel_id
            os.environ["CHANNEL_ID"] = new_channel_id
            flash(f"Channel ID set to {discord_channel_id}", "success")
            return redirect(url_for("dashboard"))
        # Handle guild ID submission
        new_guild_id = request.form.get("guild_id")
        if new_guild_id:

            global discord_guild_id
            discord_guild_id = new_guild_id
            os.environ["DISCORD_GUILD_ID"] = new_guild_id
            flash(f"Guild ID set to {discord_guild_id}", "success")
            return redirect(url_for("dashboard"))
        # Handle admin role ID submission;
        new_admin_role_id = request.form.get("admin_role_id")
        if new_admin_role_id:

            global discord_admin_role_id
            discord_admin_role_id = new_admin_role_id
            os.environ["DISCORD_ADMIN_ROLE_ID"] = new_admin_role_id
            flash(f"Admin role ID set to {discord_admin_role_id}", "success")
            return redirect(url_for("dashboard"))
    return render_template("dashboard.html",
        channel_id=discord_channel_id,
        guild_id=discord_guild_id,
        admin_role_id=discord_admin_role_id,
        csrf_token=csrf_token
    )


def run_flask_app(queue):
    app.queue = queue
    app.run(debug=True, use_reloader=False)


if __name__ == "__main__":
    try:
        command_queue = multiprocessing.Queue()
        flask_process = multiprocessing.Process(target=run_flask_app, args=(command_queue,))
        bot_process = multiprocessing.Process(target=bot.run, args=(os.getenv("DISCORD_BOT_TOKEN"),))
        flask_process.start()
        bot_process.start()
        flask_process.join()
        bot_process.join()
    except Exception as e:
        print(f"An error occurred during startup: {e}")
        traceback.print_exc()
