# Settings

This document outlines the various settings that can be configured for the gprdb application.

## Environment Variables

The following environment variables can be set in the `.env` file to configure the application:

*   `DISCORD_BOT_TOKEN`: The token for the Discord bot. This is required for the bot to connect to Discord.
*   `DISCORD_CLIENT_ID`: The client ID for the Discord application. This is required for OAuth2 authentication.
*   `DISCORD_CLIENT_SECRET`: The client secret for the Discord application. This is required for OAuth2 authentication.
*   `DISCORD_GUILD_ID`: The ID of the Discord guild (server) where the bot will be used.
*   `DISCORD_PUBLIC_KEY`: The public key for the Discord application. This is required for verifying interactions.
*   `DISCORD_REDIRECT_URI`: The redirect URI for OAuth2 authentication. This must match the URL for your `/callback` route (e.g., `http://localhost:5000/callback`).
*   `FLASK_SECRET_KEY`: A secret key used to secure the Flask application. This should be a random, complex string.
*   `POSTGRES_DB`: The name of the PostgreSQL database.
*   `POSTGRES_HOST`: The host of the PostgreSQL database. This is typically `localhost` or the name of the PostgreSQL service in Docker Compose.
*   `POSTGRES_PASSWORD`: The password for the PostgreSQL database.
*   `POSTGRES_PORT`: The port for the PostgreSQL database. This is usually `5432`.
*   `POSTGRES_USER`: The username for the PostgreSQL database.
*   `REDIS_HOST`: The host of the Redis server. This is typically `localhost` or the name of the Redis service in Docker Compose.
*   `REDIS_PORT`: The port for the Redis server. This is usually `6379`.
*   `CHANNEL_ID`: The ID of the Discord channel where the bot will send messages.
*   `DATA_FOLDER_PATH`: The folder path to the GPRDB data files.
*   `DISCORD_ADMIN_ROLE_ID`: The ID of the Discord role that has admin privileges.
*   `UID`: The user ID of the user that runs the Docker container.
*   `PGID`: The group ID of the group that runs the Docker container.
*   `WEBAPP_PORT`: The port the Flask webapp will run on.

## Discord Bot Settings

The following settings can be configured for the Discord bot:

*   **Admin Role:** The Discord role that has admin privileges. This can be set using the `!setadminrole` command.
*   **Raffle Channel:** The Discord channel where the bot will send raffle messages. This can be set using the `!setchannel` command.

## Raffle Settings

The following settings can be configured for raffles:

*   **Name:** The name of the raffle. This can be set using the `!setname` command.
*   **Type:** The type of raffle (e.g., `standard`, `lucky_number`). This can be set using the `!settype` command.
*   **Participant Limit:** The maximum number of participants allowed in the raffle. This can be set using the `!setlimit` command.
*   **Entry Limit:** The maximum number of entries each participant can have. This can be set using the `!setentrylimit` command.
*   **Webhook URL:** The URL where raffle results will be sent. This can be set using the `!setwebhook` command.
*   **Lucky Number:** The lucky number for lucky number raffles. This can be set using the `!setluckynumber` command.