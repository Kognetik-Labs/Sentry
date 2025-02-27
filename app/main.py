import logging
from typing import Optional
from discord import Message, Intents, Client
from settings import settings
from urls import extract_urls, check_cloudflare, check_virustotal

# Define the intents for the bot.
intents = Intents.default()
intents.message_content = True
client = Client(intents=intents)

# Create a new logger instance.
logger = logging.getLogger()
logging.basicConfig(level=logging.INFO)


@client.event
async def on_ready():
    logger.info(f"Successfully logged in as {client.user}.")


@client.event
async def on_message(message: Message):
    # Check if the message author is the bot.
    if message.author == client.user.id:
        return

    # Check if links exist in the message content.
    urls: list[str] = extract_urls(message.content)
    if len(urls) < 1:
        return

    # Determine if the link is malicious using various vendors.
    virustotal: list[Optional[bool]] = [await check_virustotal(url) for url in urls]
    cloudflare: list[Optional[bool]] = [await check_cloudflare(url) for url in urls]

    # Add the dangerous emoji to the message if any url is suspicious or malicious in the message content.
    if any(virustotal) or any(cloudflare):
        logger.warning("Found malicious links!")
        await message.delete()
        return

    # Check if any urls failed to be scanned.
    if None in virustotal or None in cloudflare:
        logger.info("Failed to determine if links are malicious!")
        await message.add_reaction(emoji="🟠")
        return

    # Marked the message as safe.
    await message.add_reaction(emoji="🟢")
    logger.info(f"Marked message {message.id} in channel {message.channel.id} as safe.")


# Start the bot using the defined token.
client.run(settings().DISCORD_SECRET)
