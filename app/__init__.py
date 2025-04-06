from flask import Flask
from .config import FLASK_SECRET_KEY, SESSION_TYPE, SESSION_PERMANENT, SESSION_USE_SIGNER, SESSION_REDIS, SESSION_KEY_PREFIX
from flask_session import Session
from .config import logger
from .discord_bot import bot
from .config import REDIS_HOST, REDIS_PORT
import redis
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# Configure CSRF protection
csrf = CSRFProtect(app)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri=f"redis://{REDIS_HOST}:{REDIS_PORT}",
    strategy="fixed-window"
)

# Configure Redis session
app.config["SESSION_TYPE"] = SESSION_TYPE
app.config["SESSION_PERMANENT"] = SESSION_PERMANENT  # Make sessions persistent
app.config["SESSION_USE_SIGNER"] = SESSION_USE_SIGNER  # Securely sign the session cookie
app.config["SESSION_REDIS"] = SESSION_REDIS  # Redis connection details
app.config["SESSION_KEY_PREFIX"] = SESSION_KEY_PREFIX  # Add a prefix to session keys
Session(app)  # Initialize Flask-Session

# Test Redis connection
try:
    redis_client = redis.Redis(host=REDIS_HOST, port=int(REDIS_PORT))
    response = redis_client.ping()
    if response:
        logger.info("Redis connection successful!")
    else:
        logger.error("Redis ping failed!")
except redis.exceptions.ConnectionError as e:
    logger.error(f"Redis connection failed: {e}")
except Exception as e:
    logger.error(f"An unexpected error occurred while testing Redis: {e}")

from . import routes
