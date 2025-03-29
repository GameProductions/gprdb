import os
import logging
import multiprocessing
import discord
from discord.ext import commands
from discord import app_commands
import random
import asyncio
from typing import List, Optional, Dict, Any
import psycopg2
from psycopg2 import sql
from datetime import datetime, timezone
from dotenv import load_dotenv  # Import load_dotenv

load_dotenv()  # Load environment variables from .env

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("bot.log"),
        logging.StreamHandler()
    ]
)

# --- Constants ---
DEFAULT_PARTICIPANT_LIMIT = 30
MAX_PARTICIPANT_LIMIT = 1000
TOKEN = os.environ.get("DISCORD_BOT_TOKEN")
WEBAPP_PORT = os.environ.get("WEBAPP_PORT")

# --- Database Connection ---
def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(
            host=os.environ.get("POSTGRES_HOST", "localhost"),
            database=os.environ.get("POSTGRES_DB", "rafflebot"),
            user=os.environ.get("POSTGRES_USER", "postgres"),
            password=os.environ.get("POSTGRES_PASSWORD"),
            port=os.environ.get("POSTGRES_PORT", "5432")
        )
        return conn
    except psycopg2.Error as e:
        logging.error(f"Error connecting to the database: {e}")
        raise

# --- Helper Functions ---
def create_tables_if_not_exists():
    """Creates the necessary database tables if they don't exist."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            sql.SQL("""
                CREATE TABLE IF NOT EXISTS guilds (
                    guild_id BIGINT PRIMARY KEY,
                    participant_limit INTEGER NOT NULL,  -- Renamed 'limit' to 'participant_limit'
                    running BOOLEAN NOT NULL,
                    name VARCHAR(255),
                    webhook_url TEXT,
                    entry_limit INTEGER NOT NULL DEFAULT 1,
                    raffle_type VARCHAR(255) NOT NULL DEFAULT 'standard',
                    admin_role_id BIGINT,
                    raffle_channel_id BIGINT,
                    lucky_number INTEGER
                )
            """)
        )
        cursor.execute(
            sql.SQL("""
                CREATE TABLE IF NOT EXISTS participants (
                    guild_id BIGINT REFERENCES guilds(guild_id) ON DELETE CASCADE,
                    user_id BIGINT,  -- Remove PRIMARY KEY here
                    entry_number INTEGER NOT NULL,
                    entries INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (guild_id, user_id)  -- Keep the composite primary key
                )
            """)
        )
        cursor.execute(
            sql.SQL("""
                CREATE TABLE IF NOT EXISTS raffles_archive (
                    id SERIAL PRIMARY KEY,
                    guild_id BIGINT NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    winner_id BIGINT,
                    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
                    raffle_type VARCHAR(255) NOT NULL
                )
            """)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except psycopg2.Error as e:
        logging.error(f"Error creating tables: {e}")
        raise

def load_raffle_data(guild_id: int) -> dict:
    """Loads raffle data from the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch guild data
        cursor.execute(
            sql.SQL("SELECT participant_limit, running, name, webhook_url, entry_limit, raffle_type, admin_role_id, raffle_channel_id, lucky_number FROM guilds WHERE guild_id = %s"), (guild_id,) #renamed limit
        )
        guild_data = cursor.fetchone()

        if guild_data is None:
            # Guild not found, create a new entry with default values
            cursor.execute(
                sql.SQL("INSERT INTO guilds (guild_id, participant_limit, running, name, webhook_url, entry_limit, raffle_type, admin_role_id, raffle_channel_id, lucky_number) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"), #renamed limit
                (guild_id, DEFAULT_PARTICIPANT_LIMIT, False, None, None, 1, 'standard', None, None, None),
            )
            conn.commit()
            limit = DEFAULT_PARTICIPANT_LIMIT
            running = False
            name = None
            webhook_url = None
            entry_limit = 1
            raffle_type = 'standard'
            admin_role_id = None
            raffle_channel_id = None
            lucky_number = None
            participants = {}
        else:
            limit, running, name, webhook_url, entry_limit, raffle_type, admin_role_id, raffle_channel_id, lucky_number = guild_data #renamed limit
            # Fetch participants for the guild
            cursor.execute(
                sql.SQL("SELECT user_id, entry_number, entries FROM participants WHERE guild_id = %s"), (guild_id,)
            )
            participants = {row[0]: {'entry_number': row[1], 'entries': row[2]} for row in cursor.fetchall()}

        cursor.close()
        conn.close()
        return {"participants": participants, "limit": limit, "running": running, "name": name, "webhook_url": webhook_url, "entry_limit": entry_limit, "raffle_type": raffle_type, "admin_role_id": admin_role_id, "raffle_channel_id": raffle_channel_id, "lucky_number": lucky_number}
    except psycopg2.Error as e:
        print(f"Error loading raffle data: {e}")
        raise

def save_raffle_data(guild_id: int, data: dict):
    """Saves raffle data to the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Update guild data
        cursor.execute(
            sql.SQL("UPDATE guilds SET participant_limit = %s, running = %s, name = %s, webhook_url = %s, entry_limit = %s, raffle_type = %s, admin_role_id = %s, raffle_channel_id = %s, lucky_number = %s WHERE guild_id = %s"), #renamed limit
            (data['limit'], data['running'], data['name'], data['webhook_url'], data['entry_limit'], data['raffle_type'], data['admin_role_id'], data['raffle_channel_id'], data['lucky_number'], guild_id),
        )
        if cursor.rowcount == 0:
            # Guild not found, insert a new entry
            cursor.execute(
                sql.SQL("INSERT INTO guilds (guild_id, participant_limit, running, name, webhook_url, entry_limit, raffle_type, admin_role_id, raffle_channel_id, lucky_number) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"), #renamed limit
                (guild_id, data['limit'], data['running'], data['name'], data['webhook_url'], data['entry_limit'], data['raffle_type'], data['admin_role_id'], data['raffle_channel_id'], data['lucky_number']),
            )
        conn.commit()

        # Clear existing participants for the guild
        cursor.execute(
            sql.SQL("DELETE FROM participants WHERE guild_id = %s"), (guild_id,)
        )

        # Insert the current participants
        for user_id, participant_data in data['participants'].items():
            cursor.execute(
                sql.SQL("INSERT INTO participants (guild_id, user_id, entry_number, entries) VALUES (%s, %s, %s, %s)"),
                (guild_id, user_id, participant_data['entry_number'], participant_data['entries']),
            )
        conn.commit()

        cursor.close()
        conn.close()
    except psycopg2.Error as e:
        print(f"Error saving raffle data: {e}")
        raise

def get_raffle_status(guild_id: int) -> str:
    """Gets the current status of the raffle."""
    data = load_raffle_data(guild_id)
    if not data['running']:
        return "Not running"
    else:
        name_str = f"Name: {data['name']}, " if data['name'] else ""
        webhook_str = f"Webhook: {data['webhook_url']}, " if data['webhook_url'] else ""
        entry_limit_str = f"Entry Limit: {data['entry_limit']}, " if data['entry_limit'] > 1 else ""
        raffle_type_str = f"Raffle Type: {data['raffle_type']}, "
        admin_role_str = f"Admin Role: {data['admin_role_id']}, " if data['admin_role_id'] else ""
        channel_str = f"Channel: {data['raffle_channel_id']}, " if data['raffle_channel_id'] else ""
        lucky_number_str = f"Lucky Number: {data['lucky_number']}" if data['lucky_number'] else ""
        return f"Running. {name_str}{webhook_str}{entry_limit_str}{raffle_type_str}{admin_role_str}{channel_str}{lucky_number_str} Participants: {len(data['participants'])}/{data['limit']}"

def choose_winner(guild_id: int) -> Optional[int]:
    """Chooses a winner from the participant list. Returns the winner's ID or None if no participants.
       Now considers raffle type.
    """
    data = load_raffle_data(guild_id)
    participants = data['participants']
    raffle_type = data['raffle_type']
    lucky_number = data['lucky_number']

    if not participants:
        return None

    if raffle_type == 'standard':
        # Create a list of user IDs, repeating each user ID by their number of entries
        weighted_participants = []
        for user_id, participant_data in participants.items():
            weighted_participants.extend([user_id] * participant_data['entries'])
        winner_id = random.choice(weighted_participants)
        return winner_id
    elif raffle_type == 'weighted':
        # More entries = higher chance, but not strictly proportional
        weighted_list = []
        for user_id, participant_data in participants.items():
            #  Add user_id to the list, repeated by a factor of their entries.
            weighted_list.extend([user_id] * participant_data['entries'])
        winner_id = random.choice(weighted_list)
        return winner_id
    elif raffle_type == 'lucky_number':
        # Select a winner based on a "lucky number"
        if lucky_number is None:
            print("Lucky number raffle requires a lucky number to be set.")
            return None  # Or raise an exception

        closest_user_id = None
        closest_difference = float('inf')

        for user_id, participant_data in participants.items():
            # For simplicity, let's say entry_number is participant's chosen number
            difference = abs(participant_data['entry_number'] - lucky_number)
            if difference < closest_difference:
                closest_difference = difference
                closest_user_id = user_id
        return closest_user_id
    else:
        # Default to standard if raffle type is not recognized
        weighted_participants = []
        for user_id, participant_data in participants.items():
            weighted_participants.extend([user_id] * participant_data['entries'])
        winner_id = random.choice(weighted_participants)
        return winner_id

def clear_raffle(guild_id: int):
    """Clears all raffle data for a guild (participants, running state, limit)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Reset participants and running state
        cursor.execute(
            sql.SQL("UPDATE guilds SET running = %s, participant_limit = %s, name = %s, webhook_url = %s, entry_limit = %s, raffle_type = %s, admin_role_id = %s, raffle_channel_id = %s, lucky_number = %s WHERE guild_id = %s"), #renamed limit
            (False, DEFAULT_PARTICIPANT_LIMIT, None, None, 1, 'standard', None, None, None, guild_id),
        )
        cursor.execute(
            sql.SQL("DELETE FROM participants WHERE guild_id = %s"), (guild_id,)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except psycopg2.Error as e:
        print(f"Error clearing raffle: {e}")
        raise

def archive_raffle(guild_id: int, winner_id: Optional[int], name: Optional[str]):
    """Archives the raffle data."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        end_time = datetime.now(timezone.utc)
        raffle_type = load_raffle_data(guild_id)['raffle_type'] #get raffle type

        # Insert into archive table
        cursor.execute(
            sql.SQL("""
                INSERT INTO raffles_archive (guild_id, name, winner_id, end_time, raffle_type)
                VALUES (%s, %s, %s, %s, %s)
            """),
            (guild_id, name, winner_id, end_time, raffle_type),
        )
        conn.commit()

        # Clear the raffle data
        clear_raffle(guild_id)

        cursor.close()
        conn.close()
    except psycopg2.Error as e:
        print(f"Error archiving raffle: {e}")
        raise

def get_available_entries(guild_id: int, limit: int, participants: dict) -> List[int]:
    """Gets a list of available entry numbers."""
    taken_entries = set()
    for participant_data in participants.values():
        taken_entries.add(participant_data['entry_number'])
    return [entry for entry in range(1, limit + 1) if entry not in taken_entries]

# --- Discord Bot Class ---
class RaffleBot(commands.Bot):
    def __init__(self, *, command_prefix, intents):
        super().__init__(command_prefix=command_prefix, intents=intents)
        self.command_queue = None  # Initialize command_queue

    async def setup_hook(self) -> None:
        # Create tables if they don't exist
        create_tables_if_not_exists()
        # Sync global commands
        await self.tree.sync()
        # Sync commands to individual guilds (for testing)
        for guild in self.guilds:
            await self.tree.sync(guild=guild)
        # Start processing commands from the queue
        self.loop.create_task(self.process_commands_from_queue())

    async def on_ready(self):
        print(f'Logged in as {self.user.name} ({self.user.id})')
        print('------')
        for guild in self.guilds:  # Corrected: Use self.guilds
            print(f"Connected to guild: {guild.name} (ID: {guild.id})")

    async def process_commands_from_queue(self):
        """Processes commands from the command queue."""
        await self.wait_until_ready()
        while not self.is_closed():
            try:
                command = self.command_queue.get(timeout=1)  # Check every 1 second
                print(f"Executing command from queue: {command}")
                # Get the channel
                discord_channel_id = os.environ.get("DISCORD_CHANNEL_ID")  # Define or fetch the channel ID
                if discord_channel_id:
                    channel = self.get_channel(int(discord_channel_id))
                else:
                    print("DISCORD_CHANNEL_ID is not set in the environment variables.")
                    continue
                if channel:
                    # Send the command to the channel
                    await channel.send(command)
                else:
                    print("Channel not found.")
            except multiprocessing.queues.Empty:
                pass  # No command in the queue
            except Exception as e:
                print(f"Error processing command from queue: {e}")
            await asyncio.sleep(1)  # Prevent busy-waiting

# --- Bot Setup ---
intents = discord.Intents.default()
intents.members = True
intents.message_content = True
bot = RaffleBot(command_prefix="!", intents=intents)

# --- Helper function to check admin role ---
def is_admin(ctx: discord.ext.commands.Context | discord.Interaction) -> bool:
    """Checks if the user has the admin role or is the guild owner."""
    guild_id = ctx.guild.id
    data = load_raffle_data(guild_id)
    admin_role_id = data['admin_role_id']

    if isinstance(ctx, discord.Interaction):
        member = ctx.user
    else:
        member = ctx.author

    if member.guild_permissions.administrator:
        return True  # Guild owner or administrator

    if admin_role_id:
        admin_role = discord.utils.get(ctx.guild.roles, id=admin_role_id)
        if admin_role and member in admin_role.members:
            return True  # User has the admin role
    return False

# --- Decorator to check admin role ---
def check_admin():
    def predicate(ctx: discord.ext.commands.Context | discord.Interaction) -> bool:
        if not is_admin(ctx):
            if isinstance(ctx, discord.Interaction):
                raise app_commands.MissingPermissions(["Administrator", "Manage Guild"])
            else:
                raise commands.MissingRole("Admin")  # Or a custom role name
        return True
    return commands.check(predicate)

# --- Slash Commands ---
@bot.tree.command(name="join", description="Join the raffle!")
async def join_raffle(interaction: discord.Interaction):
    guild_id = interaction.guild_id
    data = load_raffle_data(guild_id)
    raffle_channel_id = data['raffle_channel_id']

    if raffle_channel_id and interaction.channel.id != raffle_channel_id:
        await interaction.response.send_message(f"This raffle is being held in <#{raffle_channel_id}>.", ephemeral=True)
        return

    if not data['running']:
        await interaction.response.send_message("The raffle is not running yet!", ephemeral=True)
        return

    if len(data['participants']) >= data['limit']:
        await interaction.response.send_message("The raffle is full!", ephemeral=True)
        return

    user_id = interaction.user.id
    if user_id in data['participants']:
        await interaction.response.send_message("You are already in the raffle!", ephemeral=True)
        return

    available_entries = get_available_entries(guild_id, data['limit'], data['participants'])
    if not available_entries:
        await interaction.response.send_message("There are no available entries!", ephemeral=True)
        return

    entry_number = random.choice(available_entries)
    data['participants'][user_id] = {'entry_number': entry_number, 'entries': 1}  # Initialize with 1 entry
    save_raffle_data(guild_id, data)
    await interaction.response.send_message(f"You have joined the raffle! Your entry number is {entry_number}", ephemeral=True)

@bot.tree.command(name="leave", description="Leave the raffle!")
async def leave_raffle(interaction: discord.Interaction):
    guild_id = interaction.guild_id
    data = load_raffle_data(guild_id)
    raffle_channel_id = data['raffle_channel_id']

    if raffle_channel_id and interaction.channel.id != raffle_channel_id:
        await interaction.response.send_message(f"This raffle is being held in <#{raffle_channel_id}>.", ephemeral=True)
        return

    if not data['running']:
        await interaction.response.send_message("The raffle is not running!", ephemeral=True)
        return

    user_id = interaction.user.id
    if user_id not in data['participants']:
        await interaction.response.send_message("You are not in the raffle!", ephemeral=True)
        return

    del data['participants'][user_id]
    save_raffle_data(guild_id, data)
    await interaction.response.send_message("You have left the raffle!", ephemeral=True)

@bot.tree.command(name="reassign", description="Reassign your entry number.")
async def reassign_entry(interaction: discord.Interaction):
    guild_id = interaction.guild_id
    data = load_raffle_data(guild_id)
    raffle_channel_id = data['raffle_channel_id']

    if raffle_channel_id and interaction.channel.id != raffle_channel_id:
        await interaction.response.send_message(f"This raffle is being held in <#{raffle_channel_id}>.", ephemeral=True)
        return

    if not data['running']:
        await interaction.response.send_message("The raffle is not running!", ephemeral=True)
        return

    user_id = interaction.user.id
    if user_id not in data['participants']:
        await interaction.response.send_message("You are not in the raffle!", ephemeral=True)
        return

    available_entries = get_available_entries(guild_id, data['limit'], data['participants'])
    if not available_entries:
        await interaction.response.send_message("There are no available entries to reassign to!", ephemeral=True)
        return

    old_entry_number = data['participants'][user_id]['entry_number']
    new_entry_number = random.choice(available_entries)
    data['participants'][user_id]['entry_number'] = new_entry_number
    save_raffle_data(guild_id, data)
    await interaction.response.send_message(f"Your entry number has been changed from {old_entry_number} to {new_entry_number}", ephemeral=True)

@bot.tree.command(name="status", description="View the raffle status.")
async def raffle_status(interaction: discord.Interaction):
    guild_id = interaction.guild_id
    data = load_raffle_data(guild_id)
    raffle_channel_id = data['raffle_channel_id']

    if raffle_channel_id and interaction.channel.id != raffle_channel_id:
        await interaction.response.send_message(f"This raffle is being held in <#{raffle_channel_id}>.", ephemeral=True)
        return

    status = get_raffle_status(guild_id)
    await interaction.response.send_message(status, ephemeral=True)

# --- Context Menu Commands (for admins) ---
@bot.tree.context_menu(name="Start Raffle")
@check_admin()
async def start_raffle_context(interaction: discord.Interaction, message: discord.Message):
    await start_raffle(interaction)

@bot.tree.context_menu(name="End Raffle")
@check_admin()
async def end_raffle_context(interaction: discord.Interaction, message: discord.Message):
    await end_raffle(interaction)

# --- Text Commands (for admins) ---
@bot.command(name="start", description="Start the raffle (admin only).")
@commands.check(is_admin)
async def start_raffle_command(ctx, name: str = None, raffle_type: str = 'standard'):
    await start_raffle(ctx, name, raffle_type)

@bot.command(name="end", description="End the raffle and pick a winner (admin only).")
@commands.check(is_admin)
async def end_raffle_command(ctx):
    await end_raffle(ctx)

@bot.command(name="setlimit", description="Set the participant limit (admin only).")
@commands.check(is_admin)
async def set_limit_command(ctx, limit: int):
    await set_limit(ctx, limit)

@bot.command(name="add", description="Add a user to the raffle (admin only).")
@commands.check(is_admin)
async def add_participant_command(ctx, user: discord.Member, entry_number: int, entries: int = 1):
    await add_participant(ctx, user, entry_number, entries)

@bot.command(name="remove", description="Remove a user from the raffle (admin only).")
@commands.check(is_admin)
async def remove_participant_command(ctx, user: discord.Member):
    await remove_participant(ctx, user)

@bot.command(name="list", description="List all participants in the raffle (admin only).")
@commands.check(is_admin)
async def list_participants_command(ctx):
    await list_participants(ctx)

@bot.command(name="clear", description="Clear the raffle (admin only).")
@commands.check(is_admin)
async def clear_raffle_command(ctx):
    await clear_raffle_command_func(ctx)

@bot.command(name="archive", description="Archive the raffle (admin only).")
@commands.check(is_admin)
async def archive_raffle_command(ctx):
    await archive_raffle_func(ctx)

@bot.command(name="setname", description="Sets the name of the raffle (admin only)")
@commands.check(is_admin)
async def set_name_command(ctx, name: str):
    await set_name(ctx, name)

@bot.command(name="setwebhook", description="Sets the webhook URL for the raffle (admin only)")
@commands.check(is_admin)
async def set_webhook_command(ctx, url: str):
    await set_webhook(ctx, url)

@bot.command(name="setentrylimit", description="Sets the entry limit for each participant (admin only)")
@commands.check(is_admin)
async def set_entry_limit_command(ctx, limit: int):
    await set_entry_limit(ctx, limit)

@bot.command(name="settype", description="Sets the raffle type (admin only).")
@commands.check(is_admin)
async def set_raffle_type_command(ctx, raffle_type: str):
    await set_raffle_type(ctx, raffle_type)

@bot.command(name="setadminrole", description="Sets the admin role for the raffle (admin only).")
@commands.check(is_admin)
async def set_admin_role_command(ctx, role: discord.Role):
    await set_admin_role(ctx, role)

@bot.command(name="setchannel", description="Sets the channel for the raffle (admin only).")
@commands.check(is_admin)
async def set_channel_command(ctx, channel: discord.TextChannel):
    await set_channel(ctx, channel)

@bot.command(name="setluckynumber", description="Sets the lucky number for lucky number raffles (admin only).")
@commands.check(is_admin)
async def set_lucky_number_command(ctx, number: int):
    await set_lucky_number(ctx, number)

# --- Command Functions ---
async def start_raffle(ctx: discord.ext.commands.Context | discord.Interaction, name: str = None, raffle_type: str = 'standard'):
    """Starts the raffle."""
    if isinstance(ctx, discord.Interaction):
        guild_id = ctx.guild_id
        await ctx.response.defer(ephemeral=True)  # Defer for interactions
    else:
        guild_id = ctx.guild.id

    data = load_raffle_data(guild_id)

    if data['running']:
        if isinstance(ctx, discord.Interaction):
            await ctx.followup.send("The raffle is already running!", ephemeral=True)
        else:
            await ctx.send("The raffle is already running!")
        return

    if raffle_type not in ['standard', 'weighted', 'lucky_number']:
        if isinstance(ctx, discord.Interaction):
            await ctx.followup.send(f"Invalid raffle type: {raffle_type}.  Must be 'standard', 'weighted', or 'lucky_number'.", ephemeral=True)
        else:
            await ctx.send(f"Invalid raffle type: {raffle_type}. Must be 'standard', 'weighted', or 'lucky_number'.")
        return

    if raffle_type == 'lucky_number' and data['lucky_number'] is None:
        if isinstance(ctx, discord.Interaction):
            await ctx.followup.send("Please set a lucky number before starting a lucky number raffle.", ephemeral=True)
        else:
            await ctx.send("Please set a lucky number before starting a lucky number raffle.")
        return

    data['running'] = True
    data['name'] = name
    data['raffle_type'] = raffle_type  # Store the raffle type
    save_raffle_data(guild_id, data)

    if isinstance(ctx, discord.Interaction):
        await ctx.followup.send(f"The raffle has started! Raffle type: {raffle_type}", ephemeral=True)
    else:
        await ctx.send(f"The raffle has started! Raffle type: {raffle_type}")

async def end_raffle(ctx: discord.ext.commands.Context | discord.Interaction):
    """Ends the raffle and picks a winner."""
    if isinstance(ctx, discord.Interaction):
        guild_id = ctx.guild_id
        await ctx.response.defer(ephemeral=True)  # Defer for interactions
    else:
        guild_id = ctx.guild.id

    data = load_raffle_data(guild_id)
    if not data['running']:
        if isinstance(ctx, discord.Interaction):
            await ctx.followup.send("The raffle is not running!", ephemeral=True)
        else:
            await ctx.send("The raffle is not running!")
        return

    winner_id = choose_winner(guild_id)
    name = data['name']  # Get the raffle name before clearing

    if winner_id:
        winner = ctx.guild.get_member(winner_id)
        if winner:
            message = f"The winner is {winner.mention}!"
            if data['webhook_url']:
                webhook = discord.Webhook.from_url(data['webhook_url'], client=bot)
                await webhook.send(message)
            else:
                if isinstance(ctx, discord.Interaction):
                    await ctx.followup.send(message)
                else:
                    await ctx.send(message)
        else:
            message = "The winner could not be found."
            if isinstance(ctx, discord.Interaction):
                await ctx.followup.send(message)
            else:
                await ctx.send(message)
    else:
        message = "There were no participants in the raffle."
        if isinstance(ctx, discord.Interaction):
            await ctx.followup.send(message)
        else:
            await ctx.send(message)

    archive_raffle(guild_id, winner_id, name)  # Archive the raffle data
    if isinstance(ctx, discord.Interaction):
        await ctx.followup.send("The raffle has ended.", ephemeral=True)
    else:
        await ctx.send("The raffle has ended.")

async def set_limit(ctx: discord.ext.commands.Context | discord.Interaction, limit: int):
    """Sets the participant limit for the raffle."""
    if isinstance(ctx, discord.Interaction):
        guild_id = ctx.guild_id
        await ctx.response.defer(ephemeral=True)  # Defer for interactions
    else:
        guild_id = ctx.guild.id

    if limit > MAX_PARTICIPANT_LIMIT:
        limit = MAX_PARTICIPANT_LIMIT
        if isinstance(ctx, discord.Interaction):
            await ctx.followup.send(f"Limit exceeds maximum of {MAX_PARTICIPANT_LIMIT}. Limit set to {MAX_PARTICIPANT_LIMIT}.", ephemeral=True)
        else:
            await ctx.send(f"Limit exceeds maximum of {MAX_PARTICIPANT_LIMIT}. Limit set to {MAX_PARTICIPANT_LIMIT}.")

    data = load_raffle_data(guild_id)
    data['limit'] = limit
    save_raffle_data(guild_id, data)
    if isinstance(ctx, discord.Interaction):
        await ctx.followup.send(f"Participant limit set to {limit}", ephemeral=True)
    else:
        await ctx.send(f"Participant limit set to {limit}")

async def add_participant(ctx: discord.ext.commands.Context | discord.Interaction, user: discord.Member, entry_number: int, entries: int = 1):
    """Adds a participant to the raffle."""
    if isinstance(ctx, discord.Interaction):
        guild_id = ctx.guild_id
        await ctx.response.defer(ephemeral=True)  # Defer for interactions
    else:
        guild_id = ctx.guild.id

    data = load_raffle_data(guild_id)

    if not data['running']:
        if isinstance(ctx, discord.Interaction):
            await ctx.followup.send("The raffle is not running!", ephemeral=True)
        else:
            await ctx.send("The raffle is not running!")
        return

    if len(data['participants']) >= data['limit']:
        if isinstance(ctx, discord.Interaction):
            await ctx.followup.send("The raffle is full!", ephemeral=True)
        else:
            await ctx.send("The raffle is full!")
        return

    if user.id in data['participants']:
        if isinstance(ctx, discord.Interaction):
             await ctx.followup.send("User is already in the raffle!", ephemeral=True)
        else:
            await ctx.send("User is already in the raffle!")
        return

    if entry_number in [p['entry_number'] for p in data['participants'].values()]:
        if isinstance(ctx, discord.Interaction):
            await ctx.followup.send("Entry number is already taken!", ephemeral=True)
        else:
            await ctx.send("Entry number is already taken!")
        return

    if not 1 <= entry_number <= data['limit']:
        if isinstance(ctx, discord.Interaction):
            await ctx.followup.send(f"Entry number must be between 1 and {data['limit']}", ephemeral=True)
        else:
            await ctx.send(f"Entry number must be between 1 and {data['limit']}")
        return

    if entries > data['entry_limit']:
        entries = data['entry_limit']
        if isinstance(ctx, discord.Interaction):
            await ctx.followup.send(f"Entries exceed the maximum entry limit of {data['entry_limit']}.  Entries set to {data['entry_limit']}", ephemeral=True)
        else:
            await ctx.send(f"Entries exceed the maximum entry limit of {data['entry_limit']}. Entries set to {data['entry_limit']}")

    data['participants'][user.id] = {'entry_number': entry_number, 'entries': entries}
    save_raffle_data(guild_id, data)
    if isinstance(ctx, discord.Interaction):
        await ctx.followup.send(f"{user.mention} has been added to the raffle with entry number {entry_number} and {entries} entries.", ephemeral=True)
    else:
        await ctx.send(f"{user.mention} has been added to the raffle with entry number {entry_number} and {entries} entries.")

async def remove_participant(ctx: discord.ext.commands.Context | discord.Interaction, user: discord.Member):
    """Removes a participant from the raffle."""
    if isinstance(ctx, discord.Interaction):
        guild_id = ctx.guild_id
        await ctx.response.defer(ephemeral=True)  # Defer for interactions
    else:
        guild_id = ctx.guild.id

    data = load_raffle_data(guild_id)
    if user.id not in data['participants']:
        if isinstance(ctx, discord.Interaction):
            await ctx.followup.send("User is not in the raffle!", ephemeral=True)
        else:
            await ctx.send("User is not in the raffle!")
        return
    del data['participants'][user.id]
    save_raffle_data(guild_id, data)
    if isinstance(ctx, discord.Interaction):
        await ctx.followup.send(f"{user.mention} has been removed from the raffle.", ephemeral=True)
    else:
        await ctx.send(f"{user.mention} has been removed from the raffle.")

async def list_participants(ctx: discord.ext.commands.Context | discord.Interaction):
    """Lists all participants in the raffle."""
    if isinstance(ctx, discord.Interaction):
        guild_id = ctx.guild_id
        await ctx.response.defer(ephemeral=True)  # Defer for interactions
    else:
        guild_id = ctx.guild.id

    data = load_raffle_data(guild_id)
    if not data['participants']:
        if isinstance(ctx, discord.Interaction):
            await ctx.followup.send("There are no participants in the raffle.", ephemeral=True)
        else:
            await ctx.send("There are no participants in the raffle.")
        return

    participant_list = "\n".join(
        f"User: {ctx.guild.get_member(user_id).mention}, Entry Number: {participant_data['entry_number']}, Entries: {participant_data['entries']}"
        for user_id, participant_data in data['participants'].items()
    )
    if isinstance(ctx, discord.Interaction):
        await ctx.followup.send(f"Participants:\n{participant_list}", ephemeral=True)
    else:
        await ctx.send(f"Participants:\n{participant_list}")

async def clear_raffle_command_func(ctx: discord.ext.commands.Context | discord.Interaction):
    """Clears the raffle."""
    if isinstance(ctx, discord.Interaction):
        guild_id = ctx.guild_id
        await ctx.response.defer(ephemeral=True)  # Defer for interactions
    else:
        guild_id = ctx.guild.id
    clear_raffle(guild_id)
    if isinstance(ctx, discord.Interaction):
        await ctx.followup.send("The raffle has been cleared.", ephemeral=True)
    else:
        await ctx.send("The raffle has been cleared.")

async def archive_raffle_func(ctx: discord.ext.commands.Context | discord.Interaction):
    """Archives the raffle."""
    if isinstance(ctx, discord.Interaction):
        guild_id = ctx.guild_id
        await ctx.response.defer(ephemeral=True)  # Defer for interactions
    else:
        guild_id = ctx.guild.id
    data = load_raffle_data(guild_id)
    if data['running']:
        if isinstance(ctx, discord.Interaction):
            await ctx.followup.send("Please end the raffle before archiving.", ephemeral=True)
        else:
            await ctx.send("Please end the raffle before archiving.")
        return

    clear_raffle(guild_id) # changed to clear raffle.
    if isinstance(ctx, discord.Interaction):
        await ctx.followup.send("The raffle has been archived (data cleared).", ephemeral=True)
    else:
        await ctx.send("The raffle has been archived (data cleared).")

async def set_name(ctx: discord.ext.commands.Context | discord.Interaction, name: str):
    """Sets the name of the raffle."""
    if isinstance(ctx, discord.Interaction):
        guild_id = ctx.guild_id
        await ctx.response.defer(ephemeral=True)  # Defer for interactions
    else:
        guild_id = ctx.guild.id
    data = load_raffle_data(guild_id)
    data['name'] = name
    save_raffle_data(guild_id, data)
    if isinstance(ctx, discord.Interaction):
        await ctx.followup.send(f"The raffle name has been set to {name}.", ephemeral=True)
    else:
        await ctx.send(f"The raffle name has been set to {name}.")

async def set_webhook(ctx: discord.ext.commands.Context | discord.Interaction, url: str):
    """Sets the webhook URL for the raffle."""
    if isinstance(ctx, discord.Interaction):
        guild_id = ctx.guild_id
        await ctx.response.defer(ephemeral=True)  # Defer for interactions
    else:
        guild_id = ctx.guild.id
    data = load_raffle_data(guild_id)
    data['webhook_url'] = url
    save_raffle_data(guild_id, data)
    if isinstance(ctx, discord.Interaction):
        await ctx.followup.send(f"The webhook URL has been set to {url}.", ephemeral=True)
    else:
        await ctx.send(f"The webhook URL has been set to {url}.")

async def set_entry_limit(ctx: discord.ext.commands.Context | discord.Interaction, limit: int):
    """Sets the entry limit for each participant."""
    if isinstance(ctx, discord.Interaction):
        guild_id = ctx.guild_id
        await ctx.response.defer(ephemeral=True)  # Defer for interactions
    else:
        guild_id = ctx.guild.id
    data = load_raffle_data(guild_id)
    data['entry_limit'] = limit
    save_raffle_data(guild_id, data)
    if isinstance(ctx, discord.Interaction):
        await ctx.followup.send(f"The entry limit has been set to {limit}.", ephemeral=True)
    else:
        await ctx.send(f"The entry limit has been set to {limit}.")

async def set_raffle_type(ctx: discord.ext.commands.Context | discord.Interaction, raffle_type: str):
    """Sets the raffle type."""
    if isinstance(ctx, discord.Interaction):
        guild_id = ctx.guild_id
        await ctx.response.defer(ephemeral=True)  # Defer for interactions
    else:
        guild_id = ctx.guild.id

    if raffle_type not in ['standard', 'weighted', 'lucky_number']:
        if isinstance(ctx, discord.Interaction):
            await ctx.followup.send(f"Invalid raffle type: {raffle_type}.  Must be 'standard', 'weighted', or 'lucky_number'.", ephemeral=True)
        else:
            await ctx.send(f"Invalid raffle type: {raffle_type}. Must be 'standard', 'weighted', or 'lucky_number'.")
        return

    data = load_raffle_data(guild_id)
    data['raffle_type'] = raffle_type
    save_raffle_data(guild_id, data)
    if isinstance(ctx, discord.Interaction):
        await ctx.followup.send(f"The raffle type has been set to {raffle_type}.", ephemeral=True)
    else:
        await ctx.send(f"The raffle type has been set to {raffle_type}.")

async def set_admin_role(ctx: discord.ext.commands.Context | discord.Interaction, role: discord.Role):
    """Sets the admin role for the raffle."""
    if isinstance(ctx, discord.Interaction):
        guild_id = ctx.guild_id
        await ctx.response.defer(ephemeral=True)  # Defer for interactions
    else:
        guild_id = ctx.guild.id
    data = load_raffle_data(guild_id)
    data['admin_role_id'] = role.id
    save_raffle_data(guild_id, data)
    if isinstance(ctx, discord.Interaction):
        await ctx.followup.send(f"The admin role has been set to {role.name}.", ephemeral=True)
    else:
        await ctx.send(f"The admin role has been set to {role.name}.")

async def set_channel(ctx: discord.ext.commands.Context | discord.Interaction, channel: discord.TextChannel):
    """Sets the channel for the raffle."""
    if isinstance(ctx, discord.Interaction):
        guild_id = ctx.guild_id
        await ctx.response.defer(ephemeral=True)  # Defer for interactions
    else:
        guild_id = ctx.guild.id
    data = load_raffle_data(guild_id)
    data['raffle_channel_id'] = channel.id
    save_raffle_data(guild_id, data)
    if isinstance(ctx, discord.Interaction):
        await ctx.followup.send(f"The raffle channel has been set to {channel.name}.", ephemeral=True)
    else:
        await ctx.send(f"The raffle channel has been set to {channel.name}.")

async def set_lucky_number(ctx: discord.ext.commands.Context | discord.Interaction, number: int):
    """Sets the lucky number for lucky number raffles."""
    if isinstance(ctx, discord.Interaction):
        guild_id = ctx.guild_id
        await ctx.response.defer(ephemeral=True)  # Defer for interactions
    else:
        guild_id = ctx.guild.id

    data = load_raffle_data(guild_id)
    data['lucky_number'] = number
    save_raffle_data(guild_id, data)
    if isinstance(ctx, discord.Interaction):
        await ctx.followup.send(f"The lucky number has been set to {number}.", ephemeral=True)
    else:
        await ctx.send(f"The lucky number has been set to {number}.")

# --- Error Handling ---
@bot.event
async def on_command_error(ctx, error):
    """Handles errors for commands."""
    if isinstance(error, commands.MissingRole):
        await ctx.send(f"You do not have the required role to use this command.  You need the {error.missing_role} role.")
    elif isinstance(error, commands.MissingPermissions):
        await ctx.send("You do not have the required permissions to use this command.")
    elif isinstance(error, commands.CommandNotFound):
        await ctx.send("Command not found.  Use !help for a list of commands.")
    else:
        print(f"An error occurred: {error}")
        await ctx.send(f"An unexpected error occurred: {error}")

@bot.event
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    """Handles errors for application commands (slash commands, context menus)."""
    if isinstance(error, app_commands.MissingPermissions):
        await interaction.response.send_message("You do not have the required permissions to use this command.", ephemeral=True)
    elif isinstance(error, app_commands.CommandNotFound):
        await interaction.response.send_message("Command not found.", ephemeral=True)
    else:
        print(f"An error occurred: {error}")
        await interaction.response.send_message(f"An unexpected error occurred: {error}", ephemeral=True)

# --- Run the Bot ---
def run_bot(token, queue):
    """Runs the bot, retrieving commands from the queue."""
    bot.command_queue = queue  # Store the queue in the bot
    bot.run(token)

if __name__ == "__main__":
    if not TOKEN:
        print("DISCORD_BOT_TOKEN environment variable not set!")
    else:
        # Create a command queue
        command_queue = multiprocessing.Queue()
        # Run the bot, passing the token and the queue
        run_bot(TOKEN, command_queue)
