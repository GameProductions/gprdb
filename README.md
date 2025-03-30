# gprdb
GameProductions Raffle Discord Bot

## Description

gprdb is a Discord bot designed to manage raffles within Discord servers. It provides a suite of commands for starting, managing, and ending raffles, as well as tools for setting participant limits, entry limits, and more. The bot is integrated with a Flask web application, providing a user-friendly interface for administrators to control the bot and view raffle data.

## Features

*   **Raffle Management:** Start, end, clear, and archive raffles with ease.
*   **Participant Management:** Add and remove participants, set entry limits, and manage participant limits.
*   **Web Dashboard:** A Flask-based web dashboard for administrators to control the bot and view raffle data.
*   **Discord Integration:** Seamless integration with Discord servers, allowing administrators to manage raffles directly from Discord.
*   **Customizable Settings:** Set raffle names, types, webhook URLs, admin roles, and raffle channels.
*   **Slash Commands:** Utilizes Discord's slash commands for a more intuitive user experience.
*   **Context Menu Commands:** Provides context menu commands for quick access to raffle management functions.

## Prerequisites

Before you begin, ensure you have met the following requirements:

*   Python 3.6 or higher
*   pip package manager
*   Discord bot token
*   Discord client ID and secret
*   PostgreSQL database
*   Redis server

## Installation

1.  Clone the repository:

    ```bash
    git clone https://github.com/GameProductions/gprdb.git
    cd gprdb
    ```

2.  Install the required Python packages:

    ```bash
    pip install -r requirements.txt
    cd bot
    pip install -r requirements.txt
    cd ..
    ```

3.  Set up the environment variables:

    *   Create a `.env` file in the root directory of the project.
    *   Add the following environment variables to the `.env` file:

        ```plaintext
        DISCORD_BOT_TOKEN=<your_discord_bot_token>
        DISCORD_CLIENT_ID=<your_discord_client_id>
        DISCORD_CLIENT_SECRET=<your_discord_client_secret>
        DISCORD_GUILD_ID=<your_discord_guild_id>
        DISCORD_PUBLIC_KEY=<your_discord_public_key>
        DISCORD_REDIRECT_URI=<your_discord_redirect_uri>
        FLASK_SECRET_KEY=<your_flask_secret_key>
        POSTGRES_DB=<your_postgres_db_name>
        POSTGRES_HOST=<your_postgres_host>
        POSTGRES_PASSWORD=<your_postgres_password>
        POSTGRES_PORT=<your_postgres_port>
        POSTGRES_USER=<your_postgres_user>
        REDIS_HOST=<your_redis_host>
        REDIS_PORT=<your_redis_port>
        CHANNEL_ID=<your_discord_channel_id>
        DATA_FOLDER_PATH=<your_data_folder_path>
        DISCORD_ADMIN_ROLE_ID=<your_discord_admin_role_id>
        UID=<your_uid>
        PGID=<your_pgid>
        WEBAPP_PORT=<your_webapp_port>
        ```

    *   Replace the placeholder values with your actual values.

## Docker Compose Installation

1.  Ensure you have Docker and Docker Compose installed.

2.  Create a `docker-compose.yml` file in the root directory of the project:

    ```yaml
    version: "3.8"
    services:
      webapp:
        build: ./webapp
        ports:
          - "5000:5000"
        environment:
          - DISCORD_BOT_TOKEN=${DISCORD_BOT_TOKEN}
          - DISCORD_CLIENT_ID=${DISCORD_CLIENT_ID}
          - DISCORD_CLIENT_SECRET=${DISCORD_CLIENT_SECRET}
          - DISCORD_GUILD_ID=${DISCORD_GUILD_ID}
          - DISCORD_PUBLIC_KEY=${DISCORD_PUBLIC_KEY}
          - DISCORD_REDIRECT_URI=${DISCORD_REDIRECT_URI}
          - FLASK_SECRET_KEY=${FLASK_SECRET_KEY}
          - POSTGRES_DB=${POSTGRES_DB}
          - POSTGRES_HOST=${POSTGRES_HOST}
          - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
          - POSTGRES_PORT=${POSTGRES_PORT}
          - POSTGRES_USER=${POSTGRES_USER}
          - REDIS_HOST=${REDIS_HOST}
          - REDIS_PORT=${REDIS_PORT}
          - CHANNEL_ID=${CHANNEL_ID}
          - DATA_FOLDER_PATH=${DATA_FOLDER_PATH}
          - DISCORD_ADMIN_ROLE_ID=${DISCORD_ADMIN_ROLE_ID}
          - UID=${UID}
          - PGID=${PGID}
          - WEBAPP_PORT=${WEBAPP_PORT}
        depends_on:
          - postgres
          - redis
        volumes:
          - ./webapp:/app
      bot:
        build: ./bot
        environment:
          - DISCORD_BOT_TOKEN=${DISCORD_BOT_TOKEN}
          - DISCORD_CLIENT_ID=${DISCORD_CLIENT_ID}
          - DISCORD_CLIENT_SECRET=${DISCORD_CLIENT_SECRET}
          - DISCORD_GUILD_ID=${DISCORD_GUILD_ID}
          - DISCORD_PUBLIC_KEY=${DISCORD_PUBLIC_KEY}
          - DISCORD_REDIRECT_URI=${DISCORD_REDIRECT_URI}
          - FLASK_SECRET_KEY=${FLASK_SECRET_KEY}
          - POSTGRES_DB=${POSTGRES_DB}
          - POSTGRES_HOST=${POSTGRES_HOST}
          - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
          - POSTGRES_PORT=${POSTGRES_PORT}
          - POSTGRES_USER=${POSTGRES_USER}
          - REDIS_HOST=${REDIS_HOST}
          - REDIS_PORT=${REDIS_PORT}
          - CHANNEL_ID=${CHANNEL_ID}
          - DATA_FOLDER_PATH=${DATA_FOLDER_PATH}
          - DISCORD_ADMIN_ROLE_ID=${DISCORD_ADMIN_ROLE_ID}
          - UID=${UID}
          - PGID=${PGID}
          - WEBAPP_PORT=${WEBAPP_PORT}
        depends_on:
          - postgres
          - redis
        volumes:
          - ./bot:/app
      postgres:
        image: postgres:13
        ports:
          - "5432:5432"
        environment:
          - POSTGRES_USER=${POSTGRES_USER}
          - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
          - POSTGRES_DB=${POSTGRES_DB}
        volumes:
          - postgres_data:/var/lib/postgresql/data
      redis:
        image: redis:latest
        ports:
          - "6379:6379"
        volumes:
          - redis_data:/data

    volumes:
      postgres_data:
      redis_data:
    ```

3.  Run Docker Compose:

    ```bash
    docker-compose up -d
    ```

## Usage

1.  Start the Discord bot:

    This will be handled by docker-compose

2.  Start the Flask web application:

    This will be handled by docker-compose

3.  Access the web dashboard in your browser at `http://localhost:5000`.

## Contributing

Contributions are welcome! If you'd like to contribute to gprdb, please follow these steps:

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Make your changes and commit them with descriptive commit messages.
4.  Push your changes to your fork.
5.  Submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

If you have any questions or suggestions, feel free to contact us at gprdb\_privacy@gameproductions.net.
