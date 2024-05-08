#!/usr/bin/env python3

import argparse
import json
import logging
import math
import re
from typing import Optional

import requests
from bs4 import BeautifulSoup
from requests.models import HTTPError

VERIFY_PASSWORD_URL = (
    "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword"
)
API_ROOT_URL = "https://g2g-zwp.ztarmobile.io"
USER_SITE_ROOT_URL = "https://www.good2gomobile.com"

GOOGLE_API_KEY_REGEX = re.compile('apiKey:"([a-zA-Z0-9-]+)"')
FIREBASE_LOGIN_URL = f"{API_ROOT_URL}/api/user/firebaseLogin"
BYTE_SIZE = {"kb": 1024, "mb": 1048576, "gb": 1073741824}
BYTE_SUFFIXES = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]


def byte_size_to_human_readable(byte_size: int) -> str:
    """
    Given an amount of bytes, return the number as a string
    formatted with the right size prefix

    taken from https://stackoverflow.com/questions/14996453/python-libraries-to-calculate-human-readable-filesize-from-bytes/14998888#14998888

    :param byte_size: An amount of bytes
    :type byte_size: int
    :return: A number of bytes as a string formatted with the right size prefix
    :rtype: str
    """

    byte_size_for_rank = byte_size
    rank = 0

    if byte_size != 0:
        rank = int((math.log10(byte_size)) / 3)
        rank = min(rank, len(BYTE_SUFFIXES) - 1)
        byte_size_for_rank = byte_size / (1024.0**rank)

    byte_size_for_rank = ("%.2f" % byte_size_for_rank).rstrip("0").rstrip(".")
    return f"{byte_size_for_rank} {BYTE_SUFFIXES[rank]}"


def get_google_api_key(
    good2go_session: Optional[requests.Session] = None,
) -> Optional[str]:
    """
    Attempt to locate and return Good2Go's Google API key from its main site

    :param good2go_session: If provided, a requests session to use
        for all HTTP requests
    :type good2go_session: Optional[requests.Session]
    :return: If located, Good2Go's Google API key
    :rtype: Optional[str]
    """

    if good2go_session is None:
        good2go_session = requests.Session()

    # download all JS scripts from good2go and look for their google API key
    site_res = good2go_session.get(USER_SITE_ROOT_URL)
    soup = BeautifulSoup(site_res.text, "html.parser")
    js_script_tags = soup.findAll("script")

    for js_script_tag in js_script_tags:
        url = js_script_tag.attrs.get("src", "https://")
        if url.startswith("https://") or url.startswith("http://"):
            continue

        else:
            # we've found locally hosted scripts
            script_url = f"{USER_SITE_ROOT_URL}/{url}"
            script_res = good2go_session.get(script_url).text

            api_key_match = GOOGLE_API_KEY_REGEX.search(script_res)
            if api_key_match is not None:
                return api_key_match.groups()[0]

    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        type=str,
        default="config.json",
        help="The path to a configuration file. If absent, ./config.json is used",
    )
    parser.add_argument(
        "--ignore-408",
        action="store_true",
        help="If set, do not alert when an HTTPError w/ response status 408 is raised"
        "(G2G is noisy with these)",
    )
    args = parser.parse_args()

    with open(args.config, "r") as f:
        config = json.load(f)

    # logging setup
    logger = logging.getLogger("Good2Go Plan Monitor")
    logging.basicConfig()

    logging_conf = config.get("logging", dict())
    logger.setLevel(logging_conf.get("log_level", logging.INFO))
    if "gotify" in logging_conf:
        from gotify_handler import GotifyHandler

        logger.addHandler(GotifyHandler(**logging_conf["gotify"]))

    try:
        good_session = requests.Session()
        good_session.hooks[
            "response"
        ] = lambda res, *args, **kwargs: res.raise_for_status()

        google_api_key = get_google_api_key(good_session)
        if google_api_key is None:
            raise BaseException("Could not locate Google API key")

        # get "secure token" from google API
        google_token = good_session.post(
            VERIFY_PASSWORD_URL,
            params={"key": google_api_key},
            json={
                "email": config["auth"]["username"],
                "password": config["auth"]["password"],
                "returnSecureToken": True,
            },
        ).json()["idToken"]

        # firebase login
        #
        # response is a shorter token to use below w/ an email
        firebase_token = good_session.post(
            FIREBASE_LOGIN_URL, json={"token": google_token}
        ).json()["token"]

        # TODO list user accounts / plans
        #
        # for now we just hardcode it
        account_info_json = good_session.get(
            f"{API_ROOT_URL}/api/plan/{config['account_id']}/account/{config['phone_number']}/sync",
            headers={"Authentication": firebase_token},
        ).json()

        # parse JSON, fire warnings if we need to
        if account_info_json.get("pastDue", False):
            logging.warning(f"{config['phone_number']} - plan past due")

        remaining_data = account_info_json["dataRemaining"]
        remaining_data_bytes = (
            remaining_data["balance"] * BYTE_SIZE[remaining_data["units"].lower()]
        )

        if remaining_data_bytes < config["low_data_warning_bytes"]:
            logger.warning(
                f"low data - {byte_size_to_human_readable(remaining_data_bytes)}"
            )

    except BaseException as be:
        # don't alert on 408s if the user doesn't care about them
        if not (
            type(be) == HTTPError and be.response.status_code == 408 and args.ignore_408
        ):
            logger.error(f"{type(be).__name__} - {' '.join(be.args)}")


if __name__ == "__main__":
    main()
