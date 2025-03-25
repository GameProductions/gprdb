from flask import Flask, request, jsonify, session, redirect, url_for
import discord
from discord.ext import commands
import os
import requests
from urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_default_secret_key')

# --- Discord Configuration ---
DISCORD_CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID')
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET')
DISCORD_REDIRECT_URI = os.environ.get('DISCORD_REDIRECT_URI', 'http://localhost:5000/callback')  # Important:  Match your Discord Developer Portal
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN")

if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
    print("Warning: DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET environment variables must be set for OAuth2.")
    #  Don't proceed with OAuth2 if the credentials are not set.
    DISCORD_CLIENT_ID = "YOUR_DISCORD_CLIENT_ID"
    DISCORD_CLIENT_SECRET = "YOUR_DISCORD_CLIENT_SECRET"

if not DISCORD_BOT_TOKEN:
    print("Warning: DISCORD_BOT_TOKEN environment variable not set. Discord features will not work.")
    DISCORD_BOT_TOKEN = "YOUR_DISCORD_BOT_TOKEN"  # Placeholder, replace!

# --- Discord Bot Setup (Minimal - for demonstration) ---
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

@bot.event
async def on_ready():
    print(f'Discord bot logged in as {bot.user.name}')
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} global command(s)")
    except Exception as e:
        print(e)

@bot.command()
async def hello(ctx):
    await ctx.send("Hello from the Flask app (and Discord bot)!")

# --- OAuth2 Endpoints ---
@app.route('/login')
def login():
    """
    Redirects the user to Discord's OAuth2 authorization URL.
    """
    params = {
        'client_id': DISCORD_CLIENT_ID,
        'redirect_uri': DISCORD_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'identify guilds',  #  identify for user data, guilds for guild access
    }
    discord_url = f'https://discord.com/api/oauth2/authorize?{urlencode(params)}'
    return redirect(discord_url)

@app.route('/callback')
def callback():
    """
    Handles the callback from Discord after the user authorizes the app.
    Exchanges the code for an access token.
    """
    code = request.args.get('code')
    if not code:
        return jsonify({'status': 'error', 'message': 'No code provided.'}), 400

    token_data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DISCORD_REDIRECT_URI,
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    token_response = requests.post('https://discord.com/api/oauth2/token', data=token_data, headers=headers)

    if token_response.status_code != 200:
        return jsonify({'status': 'error', 'message': f'Failed to get token: {token_response.text}'}), 400

    token_json = token_response.json()
    session['access_token'] = token_json['access_token']
    #  You can also store refresh_token, expires_in, etc. if needed

    # Get user information
    user_data_response = requests.get('https://discord.com/api/users/@me',
                                     headers={'Authorization': f"Bearer {token_json['access_token']}"})
    user_data = user_data_response.json()
    session['user'] = user_data  # Store user data in session

    return redirect(url_for('dashboard'))  #  Redirect to a dashboard route

@app.route('/dashboard')
def dashboard():
    """
    Example route to show user data after successful authentication.
    """
    access_token = session.get('access_token')
    user_data = session.get('user')
    if not access_token or not user_data:
        return redirect(url_for('login'))  #  Redirect to login if not authenticated

    #  Display user information
    return f"""
        <h1>Welcome, {user_data['username']}#{user_data['discriminator']}!</h1>
        <p>Your ID: {user_data['id']}</p>
        <p>Access Token: {access_token}</p>
        <a href="/logout">Logout</a>
        <p><a href="/discord">Go to discord route</a></p>
        <p><a href="/webhook">Go to webhook route</a></p>
    """

@app.route('/logout')
def logout():
    """
    Clears the session data (access token, user info).
    """
    session.clear()
    return redirect(url_for('hello_world'))  #  Redirect to the home page

# --- Flask Routes ---
@app.route('/')
def hello_world():
    return 'Hello, World! The Flask app is running.'

@app.route('/discord')
def discord_integration():
    """
    Example of a Flask route that interacts with the Discord bot.
    This route sends a message to a specific Discord channel.
    """
    channel_id = 1234567890  # Replace with a valid channel ID.  This could also come from a database, or user input.
    channel = bot.get_channel(channel_id)

    if channel:
        bot.loop.create_task(channel.send("Hello from the Flask app!"))
        return "Message sent to Discord channel (if bot is running)."
    else:
        return "Channel not found.  Make sure the bot is in the channel and the ID is correct."


@app.route('/webhook', methods=['POST'])
def webhook_example():
    """
    Example of a Flask route that handles a webhook.
    """
    data = request.json
    print(f"Received webhook data: {data}")
    channel_id = 1234567890  # Replace with your channel ID
    channel = bot.get_channel(channel_id)
    if channel:
        bot.loop.create_task(channel.send(f"Webhook received: {data}"))
        return jsonify({'status': 'success', 'message': 'Webhook data received and sent to Discord.'}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Channel not found.'}), 500

# --- Run the Flask App ---
def run_flask_app():
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    # --- Start the Discord Bot (in a separate thread) ---
    import threading
    discord_thread = threading.Thread(target=bot.run, args=(DISCORD_BOT_TOKEN,))
    discord_thread.start()

    # --- Run the Flask app ---
    run_flask_app()
