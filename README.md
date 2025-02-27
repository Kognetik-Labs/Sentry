## Disclaimer
This project is in active development and is not yet ready for deployment onto servers. This project is provided as is and will recieve various updates over the coming weeks. You have been warned! 

## Overview
Sentry is a Discord bot designed to enhance the security of Discord servers by 
automatically extracting and analyzing URLs sent in channels. This bot aims to 
prevent users from clicking on known malicious links by actively identifying 
unsafe URLs using VirusTotal and Cloudflare Radar.


## Installation
1. Register a new Discord bot on the Discord Developer Portal.
2. Enable the `Message Content Intent` in the `Bot` section of the Discord Developer Portal.
3. Invite the Discord bot to a Discord server with the scopes `bot` and bot permissions `Send Messages`, `Manage Messages`, `Slash Commands`, and `Add Reactions`. 
4. Clone the repository to the host.
5. Rename the `.env.example` file to `.env` and set the provided secrets.
6. Run `docker compose up -d --build` to start the service. 