import discord
from discord.ext import commands
from .config import BOT_TOKEN, CHANNEL_ID, DISCORD_GUILD_ID, DISCORD_ADMIN_ROLE_ID, logger

intents = discord.Intents.default()
intents.messages = True
intents.guilds = True
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents)

discord_channel_id = None
discord_guild_id = None
discord_admin_role_id = None

@bot.event
async def on_ready():
    logger.info(f"Bot connected as {bot.user}")
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
        logger.info(f"Invite the bot using this URL: {invite_link}")
    except Exception as e:
        logger.error(f"Error generating invite link: {e}")

async def send_message(message):
    """Sends a message to the Discord channel."""
    if discord_channel_id:
        # Get the channel
        channel = bot.get_channel(int(discord_channel_id))
        if channel:
            # Send the message
            await channel.send(message)
            return "Message sent to Discord!"
        else:
            return "Channel not found."
    else:
        return "Channel ID not set."
