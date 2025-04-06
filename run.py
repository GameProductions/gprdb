from app import app, bot
from app.config import BOT_TOKEN
import asyncio

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.create_task(bot.start(BOT_TOKEN))
    app.run(debug=True)
