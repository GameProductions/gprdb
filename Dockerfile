# Use an official Python runtime as a parent image
FROM python:3.11-slim-bookworm

# Set the working directory to /app
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt /app/requirements.txt

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . /app

# Set environment variables
ENV FLASK_APP=app
ENV FLASK_ENV=production
# Add any other environment variables here (e.g., DISCORD_BOT_TOKEN, etc.)

# Expose port 5000 for the Flask app
EXPOSE 5000

# Define the command to run your application
CMD ["python", "run.py"]
