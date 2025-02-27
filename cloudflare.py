async def check_cloudflare(url: str, attempts: int = 10) -> Optional[bool]:
    """ Check the provided url for malicious activity using the CloudFlare Radar API. """
    headers = {
        "Authorization": f"Bearer {settings().CLOUDFLARE_SECRET}",
        "Content-Type": "application/json",
    }

    # Create a new session.
    async with aiohttp.ClientSession() as session:
        # Attempt to submit the url.
        async with session.post(f"https://api.cloudflare.com/client/v4/accounts/{settings().CLOUDFLARE_ACCOUNT}/urlscanner/v2/scan", headers=headers, json={"url": url}) as response:
            # Return if not successful.
            if response.status != 200:
                logger.error(f"Error submitting url to Cloudflare Radar API. | Status: {response.status}")
                return None

            # Extract the returned identifier for the url if successful.
            data = await response.json()
            id = data["uuid"]
            logger.info(f"Retrieved Cloudflare Radar API url submission identifier. | UUID: {id}")

        # Request the analysis of the url.
        count: int = 0
        while count < attempts:
            async with session.get(f"https://api.cloudflare.com/client/v4/accounts/{settings().CLOUDFLARE_ACCOUNT}/urlscanner/v2/result/{id}", headers=headers) as response:
                # Return results if successful.
                if response.status == 200:
                    # Extract the malicious verdict from the analysis.
                    data = await response.json()
                    malicious = data["verdicts"]["overall"]["malicious"]
                    logger.info(f"Cloudflare Radar API returned a verdict for the submitted url. | Malicious: {malicious}")
                    return True if malicious else False

                # Retry request if the request is still processing.
                count += 1
                logger.info(f"Retrying (#{count}) since Cloudflare Radar API is still processing. | Status: {response.status}")
                await asyncio.sleep(5)

        # Return if the request fails.
        logger.error(f"Failed to process the url with the Cloudflare Radar API.")
        return None