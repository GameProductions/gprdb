# Use a minimal Python 3.12 image based on Debian for Linux/amd64
# FROM --platform=linux/amd64 python:3.12-slim
FROM python:3.12-slim

# Set the working directory inside the container to /app
WORKDIR /app

# Copy the requirements.txt file to /app
COPY requirements.txt /app

# Install Python dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the bot.py file (your Discord bot's code) to /app
COPY bot.py /app

# Specify the command to run when the container starts: run the bot.py script with Python
CMD ["python", "bot.py"]