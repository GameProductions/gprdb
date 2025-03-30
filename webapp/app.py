import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort, flash
import discord
from discord.ext import commands
import requests
from urllib.parse import quote_plus
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
import redis
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


@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    print(f"Message from {message.author}: {message.content}")

    if message.content.startswith("!hello"):
        await message.channel.send("Hello!")

    await bot.process_commands(message)


# Flask Routes
@app.route("/")
def index():
    return render_template("index.html", user=session.get("user"), is_admin=session.get("is_admin"))


@app.route("/control_panel")
def control_panel():
    if not session.get("logged_in"):
        flash("You must be logged in to access the control panel.", "error")
        return redirect(url_for("login"))
    if not session.get("is_admin"):
        flash("You must be an admin to access the control panel.", "error")
        return redirect(url_for("index"))
    return render_template(
        "control_panel.html",
        user=session.get("user"),
        is_admin=session.get("is_admin"),
        channel_id=discord_channel_id,
        guild_id=discord_guild_id,
        admin_role_id=discord_admin_role_id
    )


class ChannelIDForm(FlaskForm):
    channel_id = StringField("Channel ID", validators=[DataRequired()])
    submit = SubmitField("Set Channel ID")


@app.route("/set_channel_id", methods=["POST"])
def set_channel_id():
    """Sets the channel ID for the bot."""
    if not session.get("logged_in"):
        return jsonify({"status": "error", "message": "You must be logged in to access this page."}), 403

    try:
        data = request.get_json()
        new_channel_id = data.get("channel_id")
        csrf_token = data.get("csrf_token")

        if not new_channel_id:
            return jsonify({"status": "error", "message": "Channel ID is required."}), 400

        # Validate CSRF token
        if not csrf.validate(csrf_token):
            return jsonify({"status": "error", "message": "Invalid CSRF token."}), 400

        global discord_channel_id
        discord_channel_id = new_channel_id
        print(f"Channel ID set to {discord_channel_id}")
        return jsonify({"status": "success", "message": f"Channel ID set to {discord_channel_id}"}), 200

    except Exception as e:
        print(f"Error setting channel ID: {e}")
        return jsonify({"status": "error", "message": "An error occurred while setting the channel ID."}), 500


@app.route("/set_guild_id", methods=["POST"])
def set_guild_id():
    """Sets the guild ID for the bot."""
    new_guild_id = request.form["guild_id"]
    global discord_guild_id
    discord_guild_id = new_guild_id
    print(f"Guild ID set to {discord_guild_id}")
    return redirect(url_for("control_panel"))


@app.route("/set_admin_role_id", methods=["POST"])
def set_admin_role_id():
    """Sets the admin role ID for the bot."""
    new_admin_role_id = request.form["admin_role_id"]
    global discord_admin_role_id
    discord_admin_role_id = new_admin_role_id
    print(f"Admin role ID set to {discord_admin_role_id}")
    return redirect(url_for("control_panel"))


@app.route("/get_channel_id", methods=["GET"])
def get_channel_id():
    """Returns the current channel ID."""
    return jsonify({"channel_id": discord_channel_id})


@app.route("/get_guild_id", methods=["GET"])
def get_guild_id():
    """Returns the current guild ID."""
    return jsonify({"guild_id": discord_guild_id})


@app.route("/get_admin_role_id", methods=["GET"])
def get_admin_role_id():
    """Returns the current admin role ID."""
    return jsonify({"admin_role_id": discord_admin_role_id})


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


@app.route("/dashboard")
def dashboard():
    """Renders the admin dashboard."""
    if not session.get("logged_in"):
        flash("You must be logged in to access the dashboard.", "error")
        return redirect(url_for("login"))
    if not session.get("is_admin"):
        flash("You must be an admin to access the dashboard.", "error")
        return redirect(url_for("index"))
    return render_template("dashboard.html")


# Route to start the raffle
@app.route("/start_raffle", methods=["POST"])
def start_raffle():
    """Starts the raffle."""
    if not session.get("logged_in") or not session.get("is_admin"):
        flash("Unauthorized access.", "error")
        return redirect(url_for("index"))

    raffle_name = request.form.get("raffle_name")
    raffle_type = request.form.get("raffle_type")

    # Basic validation
    if not raffle_name or not raffle_type:
        flash("Raffle name and type are required.", "error")
        return redirect(url_for("dashboard"))

    # Construct the command
    command = f"!start {raffle_name} {raffle_type}"

    # Execute the command
    execute_bot_command(command)

    flash(f"Raffle '{raffle_name}' started successfully!", "success")
    return redirect(url_for("dashboard"))


# New route to create a test raffle
@app.route("/create_test_raffle", methods=["POST"])
def create_test_raffle():
    """Creates a test raffle with sample participants."""
    if not session.get("logged_in") or not session.get("is_admin"):
        flash("Unauthorized access.", "error")
        return redirect(url_for("index"))

    test_raffle_name = request.form.get("test_raffle_name")
    test_raffle_type = request.form.get("test_raffle_type")
    num_test_entries = int(request.form.get("num_test_entries", 5))

    # Basic validation
    if not test_raffle_name or not test_raffle_type:
        flash("Raffle name and type are required.", "error")
        return redirect(url_for("dashboard"))

    # Construct the start command
    start_command = f"!start {test_raffle_name} {test_raffle_type}"
    execute_bot_command(start_command)

    # Add test participants
    for i in range(1, num_test_entries + 1):
        add_command = f"!add TestUser{i} {i}"
        execute_bot_command(add_command)

    flash(f"Test raffle '{test_raffle_name}' created with {num_test_entries} participants!", "success")
    return redirect(url_for("dashboard"))


# Route to end the raffle
@app.route("/end_raffle", methods=["POST"])
def end_raffle():
    """Ends the raffle."""
    if not session.get("logged_in") or not session.get("is_admin"):
        flash("Unauthorized access.", "error")
        return redirect(url_for("index"))

    # Construct the command
    command = "!end"

    # Execute the command
    execute_bot_command(command)

    flash("Raffle ended successfully!", "success")
    return redirect(url_for("dashboard"))


# Route to set the participant limit
@app.route("/set_participant_limit", methods=["POST"])
def set_participant_limit():
    """Sets the participant limit for the raffle."""
    if not session.get("logged_in") or not session.get("is_admin"):
        flash("Unauthorized access.", "error")
        return redirect(url_for("index"))

    participant_limit = request.form.get("participant_limit")

    # Basic validation
    if not participant_limit or not participant_limit.isdigit():
        flash("Invalid participant limit.", "error")
        return redirect(url_for("dashboard"))

    # Construct the command
    command = f"!setlimit {participant_limit}"

    # Execute the command
    execute_bot_command(command)

    flash(f"Participant limit set to {participant_limit} successfully!", "success")
    return redirect(url_for("dashboard"))


# Route to set the entry limit
@app.route("/set_entry_limit", methods=["POST"])
def set_entry_limit():
    """Sets the entry limit for the raffle."""
    if not session.get("logged_in") or not session.get("is_admin"):
        flash("Unauthorized access.", "error")
        return redirect(url_for("index"))

    entry_limit = request.form.get("entry_limit")

    # Basic validation
    if not entry_limit or not entry_limit.isdigit():
        flash("Invalid entry limit.", "error")
        return redirect(url_for("dashboard"))

    # Construct the command
    command = f"!setentrylimit {entry_limit}"

    # Execute the command
    execute_bot_command(command)

    flash(f"Entry limit set to {entry_limit} successfully!", "success")
    return redirect(url_for("dashboard"))


# Route to set the webhook URL
@app.route("/set_webhook_url", methods=["POST"])
def set_webhook_url():
    """Sets the webhook URL for the raffle."""
    if not session.get("logged_in") or not session.get("is_admin"):
        flash("Unauthorized access.", "error")
        return redirect(url_for("index"))

    webhook_url = request.form.get("webhook_url")

    # Basic validation
    if not webhook_url:
        flash("Webhook URL is required.", "error")
        return redirect(url_for("dashboard"))

    # Construct the command
    command = f"!setwebhook {webhook_url}"

    # Execute the command
    execute_bot_command(command)

    flash(f"Webhook URL set to {webhook_url} successfully!", "success")
    return redirect(url_for("dashboard"))


# Route to set the admin role
@app.route("/set_admin_role", methods=["POST"])
def set_admin_role():
    """Sets the admin role for the raffle."""
    if not session.get("logged_in") or not session.get("is_admin"):
        flash("Unauthorized access.", "error")
        return redirect(url_for("index"))

    admin_role_id = request.form.get("admin_role_id")

    # Basic validation
    if not admin_role_id or not admin_role_id.isdigit():
        flash("Invalid admin role ID.", "error")
        return redirect(url_for("dashboard"))

    # Construct the command
    command = f"!setadminrole {admin_role_id}"

    # Execute the command
    execute_bot_command(command)

    flash(f"Admin role set to {admin_role_id} successfully!", "success")
    return redirect(url_for("dashboard"))


# Route to set the raffle channel
@app.route("/set_raffle_channel", methods=["POST"])
def set_raffle_channel():
    """Sets the raffle channel for the raffle."""
    if not session.get("logged_in") or not session.get("is_admin"):
        flash("Unauthorized access.", "error")
        return redirect(url_for("index"))

    raffle_channel_id = request.form.get("raffle_channel_id")

    # Basic validation
    if not raffle_channel_id or not raffle_channel_id.isdigit():
        flash("Invalid raffle channel ID.", "error")
        return redirect(url_for("dashboard"))

    # Construct the command
    command = f"!setchannel {raffle_channel_id}"

    # Execute the command
    execute_bot_command(command)

    flash(f"Raffle channel set to {raffle_channel_id} successfully!", "success")
    return redirect(url_for("dashboard"))


# Route to set the lucky number
@app.route("/set_lucky_number", methods=["POST"])
def set_lucky_number():
    """Sets the lucky number for the raffle."""
    if not session.get("logged_in") or not session.get("is_admin"):
        flash("Unauthorized access.", "error")
        return redirect(url_for("index"))

    lucky_number = request.form.get("lucky_number")

    # Basic validation
    if not lucky_number or not lucky_number.isdigit():
        flash("Invalid lucky number.", "error")
        return redirect(url_for("dashboard"))

    # Construct the command
    command = f"!setluckynumber {lucky_number}"

    # Execute the command
    execute_bot_command(command)

    flash(f"Lucky number set to {lucky_number} successfully!", "success")
    return redirect(url_for("dashboard"))


# Route to clear the raffle
@app.route("/clear_raffle", methods=["POST"])
def clear_raffle():
    """Clears the raffle."""
    if not session.get("logged_in") or not session.get("is_admin"):
        flash("Unauthorized access.", "error")
        return redirect(url_for("index"))

    # Construct the command
    command = "!clear"

    # Execute the command
    execute_bot_command(command)

    flash("Raffle cleared successfully!", "success")
    return redirect(url_for("dashboard"))


# Route to archive the raffle
@app.route("/archive_raffle", methods=["POST"])
def archive_raffle():
    """Archives the raffle."""
    if not session.get("logged_in") or not session.get("is_admin"):
        flash("Unauthorized access.", "error")
        return redirect(url_for("index"))

    # Construct the command
    command = "!archive"

    # Execute the command
    execute_bot_command(command)

    flash("Raffle archived successfully!", "success")
    return redirect(url_for("dashboard"))


def run_flask_app(queue):
    """Runs the Flask app."""
    app.queue = queue  # Store the queue in the app
    app.run(debug=True, use_reloader=False)


if __name__ == "__main__":
    # Create a command queue
    command_queue = multiprocessing.Queue()

    # Create separate processes for the bot and the web app
    flask_process = multiprocessing.Process(target=run_flask_app, args=(command_queue,))
    bot_process = multiprocessing.Process(target=bot.run, args=(os.getenv("DISCORD_BOT_TOKEN"),))
    # Start the processes
    flask_process.start()
    bot_process.start()

    # Wait for the processes to finish (optional)
    flask_process.join()
    bot_process.join()