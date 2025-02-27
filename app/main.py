import logging
from typing import Optional
from discord import Message, Intents, Client, Embed, Color
from settings import settings
from urls import extract_urls, check_url

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

    # Determine if the link is malicious using VirusTotal.
    results: list[Optional[bool]] = [await check_url(url) for url in urls]

    # Add the dangerous emoji to the message if any url is suspicious or malicious in the message content.
    if any(results):
        # Remove the message.
        await message.delete()
        logger.warning(f"Removed a malicious link. | {urls}")

        # Ensure the logging channel exists.
        channel = client.get_channel(settings().DISCORD_LOGGING_CHANNEL_ID)
        if channel is None:
            logger.warning("The Discord channel provided could not be found.")
            return

        # Send an embed if a logging channel exists.
        r, g, b = tuple(int(settings().DISCORD_LOGGING_EMBED_COLOR[i:i+2], 16) for i in (0, 2, 4))
        embed = Embed(
            title="Removed Malicious URL",
            description=f"Removed a malicious message from {message.author.mention} in {message.channel.mention}.",
            color=Color.from_rgb(r, g, b)
        )
        await channel.send(embed=embed)
        return

    # Check if any urls failed to be scanned.
    if None in results:
        logger.info("Failed to determine if links are malicious!")
        await message.add_reaction(emoji="🟠")
        return

    # Marked the message as safe.
    await message.add_reaction(emoji="🟢")
    logger.info(f"Marked message {message.id} in channel {message.channel.id} as safe.")


# Start the bot using the defined token.
client.run(settings().DISCORD_SECRET)
