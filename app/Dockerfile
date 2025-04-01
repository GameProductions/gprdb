# Use a minimal Python 3.12 image based on Debian for Linux/amd64
# FROM --platform=linux/amd64 python:3.12-slim
FROM python:3.12-slim

# Set the working directory inside the container to /app
WORKDIR /app

# Copy the requirements.txt file to /app
COPY requirements.txt /app

# Install Python dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code to /app
# This includes the wsgi.py file and any other necessary files
# Ensure that the wsgi.py file is in the same directory as this Dockerfile
# If your wsgi.py file is in a different directory, adjust the COPY command accordingly
# For example, if wsgi.py is in a subdirectory called 'src', use:
# COPY src/wsgi.py /app/wsgi.py
# If your application has a different structure, adjust the COPY command accordingly
# For example, if your application code is in a directory called 'src', use:
# COPY src/ /app/src
COPY . .

# Web server configuration
# Expose port 5000 for the web server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "wsgi:app"]