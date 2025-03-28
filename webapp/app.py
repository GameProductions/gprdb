import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort
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
import logging  # Import the logging module
from flask_limiter import Limiter # type: ignore
from flask_limiter.util import get_remote_address # type: ignore
from flask_session import Session  # type: ignore # Import Flask-Session
import redis  # type: ignore # Import the Redis module
import multiprocessing

load_dotenv()

# Inspect environment variables
print("Environment variables (Flask App):")
for key, value in os.environ.items():
    print(f"{key}={value}")
print("-----------------------")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")  # Use a strong, random secret key

# Configure CSRF protection
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.ERROR)  # Set the logging level

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri=f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}", # Use Redis for storage
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
    exit() # Or set a default value: DISCORD_REDIRECT_URI = "http://localhost:5000/callback"
print(f"DISCORD_REDIRECT_URI is {DISCORD_REDIRECT_URI}")
SCOPES = "identify email guilds"  # Add 'email' if you need it and guilds
# Add a slash
DISCORD_AUTHORIZATION_URL = f"https://discord.com/api/oauth2/authorize?client_id={DISCORD_CLIENT_ID}&redirect_uri={DISCORD_REDIRECT_URI}&response_type=code&scope={SCOPES}"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"
DISCORD_API_BASE_URL = "https://discord.com/api/v10"  # Use a specific API version
DISCORD_GUILD_ID = os.getenv("DISCORD_GUILD_ID")  # Add guild ID to env
DISCORD_ADMIN_ROLE_ID = os.getenv("DISCORD_ADMIN_ROLE_ID")  # Add role ID
DISCORD_PUBLIC_KEY = os.getenv("DISCORD_PUBLIC_KEY")  # Add public key


def get_discord_user(access_token):
    """Fetches the user's Discord data."""
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{DISCORD_API_BASE_URL}/users/@me", headers=headers)
    response.raise_for_status()
    return response.json()


def get_user_guilds(access_token):
    """
    Fetches the guilds the user is in
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{DISCORD_API_BASE_URL}/users/@me/guilds", headers=headers)
    response.raise_for_status()
    return response.json()


def is_admin(user_guilds, guild_id, admin_role_id):
    """
    Checks if the user has admin role in the specific guild.
    """
    for guild in user_guilds:
        if guild["id"] == guild_id:
            # Get the roles for the user in the guild
            roles_response = requests.get(
                f"{DISCORD_API_BASE_URL}/guilds/{guild_id}/members/{session['user']['id']}",
                headers={"Authorization": f"Bot {BOT_TOKEN}"},
            )
            roles_response.raise_for_status()
            member_data = roles_response.json()
            role_ids = member_data.get("roles", [])
            return admin_role_id in role_ids
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
        permissions = discord.Permissions(manage_guild=True, manage_channels=True, send_messages=True)
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
        abort(403)  # Only logged-in users can access
    if not session.get("is_admin"):
        abort(403)  # Only admins can access
    return render_template(
        "control_panel.html",
        user=session.get("user"),
        is_admin=session.get("is_admin"),
        channel_id=discord_channel_id, # Added these
        guild_id=discord_guild_id,
        admin_role_id=discord_admin_role_id
    )

class ChannelIDForm(FlaskForm):
    channel_id = StringField('Channel ID', validators=[DataRequired()])
    submit = SubmitField('Set Channel ID')

@app.route("/set_channel_id", methods=["GET", "POST"])
def set_channel_id():
    global discord_channel_id
    if not session.get("logged_in"):
        abort(401)  # Unauthorized
    if not session.get("is_admin"):
        abort(403)  # Forbidden

    form = ChannelIDForm()
    if form.validate_on_submit():
        try:
            discord_channel_id = int(form.channel_id.data)
            return redirect(url_for('control_panel'))
        except ValueError:
            form.channel_id.errors.append("Invalid Channel ID")

    return render_template("set_channel_id.html", form=form, user=session.get("user"), is_admin=session.get("is_admin"))


@app.route("/set_guild_id", methods=["POST"]) #Added
def set_guild_id():
    global discord_guild_id
    if not session.get("logged_in"):
        return jsonify({"status": "error", "message": "Login required"}), 401
    if not session.get("is_admin"):
        return jsonify({"status": "error", "message": "Admin permissions required"}), 403

    data = request.get_json()
    guild_id = data.get("guild_id")

    if not guild_id:
        return jsonify({"status": "error", "message": "Guild ID is required"}), 400

    try:
        discord_guild_id = int(guild_id)
        return jsonify({"status": "success", "message": f"Guild ID set to {discord_guild_id}"})
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid Guild ID"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"An error occurred: {e}"}), 500

@app.route("/set_admin_role_id", methods=["POST"]) # Added
def set_admin_role_id():
    global discord_admin_role_id
    if not session.get("logged_in"):
        return jsonify({"status": "error", "message": "Login required"}), 401
    if not session.get("is_admin"):
        return jsonify({"status": "error", "message": "Admin permissions required"}), 403

    data = request.get_json()
    admin_role_id = data.get("admin_role_id")

    if not admin_role_id:
        return jsonify({"status": "error", "message": "Admin Role ID is required"}), 400

    try:
        discord_admin_role_id = int(admin_role_id)
        return jsonify({"status": "success", "message": f"Admin Role ID set to {discord_admin_role_id}"})
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid Admin Role ID"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"An error occurred: {e}"}), 500



@app.route("/get_channel_id", methods=["GET"])
def get_channel_id():
    global discord_channel_id
    if discord_channel_id:
        return jsonify({"status": "success", "channel_id": discord_channel_id}), 200
    else:
        return jsonify({"status": "success", "channel_id": None}), 200
@app.route("/get_guild_id", methods=["GET"]) # Added
def get_guild_id():
    global discord_guild_id
    if discord_guild_id:
        return jsonify({"status": "success", "guild_id": discord_guild_id}), 200
    else:
        return jsonify({"status": "success", "guild_id": None}), 200

@app.route("/get_admin_role_id", methods=["GET"]) # Added
def get_admin_role_id():
    global discord_admin_role_id
    if discord_admin_role_id:
        return jsonify({"status": "success", "admin_role_id": discord_admin_role_id}), 200
    else:
        return jsonify({"status": "success", "admin_role_id": None}), 200


@app.route("/discord")
def send_discord_message():
    global discord_channel_id
    if not session.get("logged_in"):
        return "Login required", 401
    if not session.get("is_admin"):
        return "Admin permissions required", 403

    if not discord_channel_id:
        return "Channel ID not set. Please set the channel ID first.", 400

    message_text = "Hello from the Flask app!"

    async def send_message():
        try:
            channel = bot.get_channel(discord_channel_id)
            if channel:
                await channel.send(message_text)
                print(f"Message sent to channel {discord_channel_id}: {message_text}")
                return "Message sent to Discord!", 200
            else:
                print(f"Channel with ID {discord_channel_id} not found.")
                return "Channel not found.", 404
        except discord.Forbidden:
            print(
                f"Error: Bot does not have permission to send messages to channel {discord_channel_id}"
            )
            return "Bot does not have permission to send messages to this channel.", 403
        except discord.NotFound:
            print(f"Error: Channel with ID {discord_channel_id} not found.")
            return "Channel not found.", 404
        except Exception as e:
            print(f"Error sending message: {e}")
            return f"Error sending message: {e}", 500

    bot.loop.create_task(send_message())
    return "Sending message...", 200


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
        return "Failed to get authorization code.", 400

    try:
        # Exchange the code for an access token
        data = {
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": os.getenv("DISCORD_REDIRECT_URI"),
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(DISCORD_TOKEN_URL, data=data, headers=headers)
        response.raise_for_status()
        token_data = response.json()
        access_token = token_data.get("access_token")

        if not access_token:
            logging.error("OAuth2 callback: Failed to get access token.")
            return "Failed to get access token.", 400

        # Get the user's information
        try:
            user_data = get_discord_user(access_token)
            # Store user data in the session
            session["user"] = user_data
            session["logged_in"] = True  # Set a flag for login status

            # Check for admin
            user_guilds = get_user_guilds(access_token)
            session["is_admin"] = is_admin(user_guilds, DISCORD_GUILD_ID, DISCORD_ADMIN_ROLE_ID)

            return redirect(url_for("index"))  # Redirect to a protected page

        except requests.exceptions.RequestException as e:
            logging.error(f"OAuth2 callback: Failed to get user information: {e}")
            return f"Failed to get user information: {e}", 500

    except requests.exceptions.RequestException as e:
        logging.error(f"OAuth2 callback: Failed to exchange code for access token: {e}")
        return "Failed to exchange code for access token.", 500
    except Exception as e:
        logging.exception("OAuth2 callback: An unexpected error occurred.")  # Log the full exception
        return "An unexpected error occurred.", 500


@app.route("/logout")
def logout():
    """Logs the user out by clearing the session."""
    session.clear()
    session["logged_in"] = False
    return redirect(url_for("index"))  # Redirect to the main page


def verify_signature(signature, timestamp, body):
    """Verifies the signature of a Discord interaction request."""
    key = VerifyKey(bytes.fromhex(DISCORD_PUBLIC_KEY))  # Use the public key
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

    if not signature or not timestamp or not body:
        return jsonify({"error": "Missing signature, timestamp, or body"}), 400

    if not verify_signature(signature, timestamp, body):
        return jsonify({"error": "Invalid signature"}), 401

    data = request.get_json()
    interaction_type = data.get("type")

    if interaction_type == 1:  # Ping
        return jsonify({"type": 1})  # Respond with a Pong

    elif interaction_type == 2:  # Application Command (Slash Command)
        command_name = data["data"]["name"]
        user = data["member"]["user"]
        if command_name == "hello":
            return jsonify({
                "type": 4,  # Respond to the command
                "data": {
                    "content": f"Hello, {user['username']}!",
                },
            })
        elif command_name == "raffles":
            return jsonify({
                "type": 4,
                "data": {
                    "content": "raffles command",
                    "components": [
                        {
                            "type": 1,
                            "components": [
                                {
                                    "type": 2,
                                    "style": 2,
                                    "custom_id": "create_raffle",
                                    "label": "Create Raffle"
                                },
                                {
                                    "type": 2,
                                    "style": 2,
                                    "custom_id": "enter_raffle",
                                    "label": "Enter Raffle"
                                },
                            ],
                        },
                    ],
                },
            })
        else:
            return jsonify({
                "type": 4,
                "data": {
                    "content": f"Unknown command: {command_name}",
                },
            })

    elif interaction_type == 3:  # Component Interaction
        custom_id = data["data"]["custom_id"]
        if custom_id == "create_raffle":
            return jsonify({
                "type": 4,
                "data": {
                    "content": "You clicked the create raffle button",
                },
            })
        elif custom_id == "enter_raffle":
            return jsonify({
                "type": 4,
                "data": {
                    "content": "You clicked the enter raffle button",
                },
            })
        else:
            return jsonify({
                "type": 4,
                "data": {
                    "content": f"Unknown component clicked: {custom_id}",
                },
            })

    else:
        return jsonify({"error": "Unknown interaction type"}), 400

def run_flask_app():
    app.run(debug=True, use_reloader=False)

if __name__ == "__main__":
    # Create separate processes for the bot and the web app
    flask_process = multiprocessing.Process(target=run_flask_app)
    bot_process = multiprocessing.Process(target=bot.run, args=(os.getenv("DISCORD_BOT_TOKEN"),))
    # Start the processes
    flask_process.start()
    bot_process.start()

    # Wait for the processes to finish (optional)
    flask_process.join()
    bot_process.join()