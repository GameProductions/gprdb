# Use a minimal Python 3.12 image based on Debian for Linux/amd64
# FROM --platform=linux/amd64 python:3.12-slim
FROM python:3.12-slim

# Set the working directory inside the container to /app
WORKDIR /app

# Copy the requirements.txt file to /app
COPY requirements.txt /app

# Install Python dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Create a directory for the Flask templates
RUN mkdir /app/templates

# Create test folder
RUN mkdir /app/test

# Copy the entire Flask application code to /app
COPY . /app

# Expose port 5000 to allow access to the Flask app from outside the container
EXPOSE 5000

# Set the Flask application file (usually app.py or main.py)
ENV FLASK_APP=app.py

# Make the Flask app accessible on the network (0.0.0.0) as opposed to only localhost
ENV FLASK_RUN_HOST=0.0.0.0

# Specify the command to run when the container starts: run the Flask development server
CMD ["flask", "run"]