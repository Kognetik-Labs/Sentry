import logging
from functools import cache
from pydantic.v1 import BaseSettings, ValidationError

logger = logging.getLogger()


class Settings(BaseSettings):
    """ Defines the accepted environment variables using Pydantic. """
    class Config:
        env_file = [".env"]  # Ensure to only load the default env file.
        env_file_encoding = "utf-8"  # Ensure UTF-8 to allow for parsing of lists in env file.
        env_ignore_empty = True  # Use

    # Define required environment variables and default values if applicable.
    DISCORD_SECRET: str = None
    DISCORD_REACTION_SAFE: str = "�"  # Unicode Green Circle
    DISCORD_REACTION_ERROR: str = "�"  # Unicode Orange Circle
    DISCORD_LOGGING_CHANNEL_ID: int = None
    DISCORD_LOGGING_EMBED_COLOR: str = "ED4337"
    VIRUSTOTAL_SECRET: str = None


@cache
def settings() -> Settings:
    """ Returns the cached settings object. """
    try:
        return Settings()
    except ValidationError as error:
        logger.error(f"Error creating settings object, likely due to missing environment variable. | {error}")
        quit()
