# Use an official Python runtime as a parent image
FROM python:3.11-slim-buster

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any dependencies specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make sure the bot.py script is executable.
RUN chmod +x bot.py

# Specify the command to run when the container starts
CMD ["python", "bot.py"]
```yaml
version: '3.8'
services:
  rafflebot:
    build: .
    # Use environment variables for sensitive data
    environment:
      DISCORD_BOT_TOKEN: ${DISCORD_BOT_TOKEN}
      POSTGRES_HOST: ${POSTGRES_HOST}
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_PORT: ${POSTGRES_PORT:-5432} # default to 5432 if not provided
    # Mount a volume for persistent storage of the database data.  Remove this if you
    # are using a managed database service like AWS RDS.
    volumes:
      - postgres_data:/var/lib/postgresql/data
    depends_on:
      - postgres

  postgres:
    image: postgres:14
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    ports:
      - "${POSTGRES_PORT:-5432}:${POSTGRES_PORT:-5432}" # Map the port, default to 5432
    volumes:
      - postgres_data:/var/lib/postgresql/data

# Declare the volume
volumes:
  postgres_data:
