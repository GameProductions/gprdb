import requests
from urllib.parse import quote_plus
from .config import DISCORD_TOKEN_URL, DISCORD_API_BASE_URL, DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI, SCOPES
from .config import logger

DISCORD_AUTHORIZATION_URL = f"https://discord.com/api/oauth2/authorize?client_id={DISCORD_CLIENT_ID}&redirect_uri={quote_plus(DISCORD_REDIRECT_URI)}&response_type=code&scope={SCOPES}"

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

def exchange_code(code):
    """Exchanges the authorization code for an access token."""
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "scope": SCOPES
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(DISCORD_TOKEN_URL, data=data, headers=headers)
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
