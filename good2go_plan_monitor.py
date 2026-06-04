#!/usr/bin/env python3

import argparse
import json
import logging
import logging.config
import math

import requests
from requests.models import HTTPError

# Public Firebase Web API key for Good2Go's Firebase project ("prod-good2go").
FIREBASE_API_KEY = "AIzaSyAUwn5YLtuu0b-xL2OgvhYVFE7Sp0p-hlY"

# Firebase Identity Toolkit endpoint for email/password sign-in.
FIREBASE_SIGN_IN_URL = (
    "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
)

# Good2Go's auth BFF - exchanges a Firebase ID token
# for a short-lived "server token" (a JWT issued by zwp_bff).
ZWP_BFF_URL = "https://zwp-bff-5zxbrbyvaq-uc.a.run.app"

# Good2Go's data BFF - exposes the account / plan / buckets endpoints.
ZMP_BFF_URL = "https://zmp-bff-5zxbrbyvaq-uc.a.run.app"

BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
)

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


def firebase_sign_in(session: requests.Session, email: str, password: str) -> str:
    """
    Sign in to Good2Go's Firebase project with email + password
    and return the resulting Firebase ID token.
    """

    res = session.post(
        FIREBASE_SIGN_IN_URL,
        params={"key": FIREBASE_API_KEY},
        json={
            "email": email,
            "password": password,
            "returnSecureToken": True,
            "clientType": "CLIENT_TYPE_WEB",
        },
    )
    return res.json()["idToken"]


def exchange_for_server_token(session: requests.Session, firebase_id_token: str) -> str:
    """
    Exchange a Firebase ID token for a Good2Go BFF "server token" -
    the JWT that the data BFF expects in the `authentication` header.
    """

    res = session.post(
        f"{ZWP_BFF_URL}/api/user/firebaseLogin",
        json={"token": firebase_id_token})
    return res.json()["token"]


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
    logger = logging.getLogger("good2go_plan_monitor")
    logging_conf = config.get("logging", dict())
    logging.config.dictConfig(logging_conf)

    try:
        good_session = requests.Session()
        good_session.headers["User-Agent"] = BROWSER_USER_AGENT
        good_session.hooks["response"] = (
            lambda res, *args, **kwargs: res.raise_for_status()
        )

        firebase_id_token = firebase_sign_in(
            good_session, config["auth"]["username"], config["auth"]["password"]
        )
        server_token = exchange_for_server_token(good_session, firebase_id_token)

        phone_number = config["phone_number"]
        buckets = good_session.get(f"{ZMP_BFF_URL}/v1/account/{phone_number}/buckets", headers={"authentication": server_token}).json()

        # account-status alert
        account_status = buckets.get("accountStatus")
        if account_status is not None and account_status != "INSTALLED":
            logger.warning(
                f"{phone_number} - unexpected account status: {account_status}"
            )

        # low data alert
        remaining_data = buckets["dataRemaining"]
        units = remaining_data["units"].lower()
        if units not in BYTE_SIZE:
            raise ValueError(
                f"Unsupported data unit from API: {remaining_data['units']!r} "
                f"(known units: {sorted(BYTE_SIZE)})"
            )
        remaining_data_bytes = int(remaining_data["balance"]) * BYTE_SIZE[units]

        if remaining_data_bytes < config["low_data_warning_bytes"]:
            logger.warning(
                f"low data - {byte_size_to_human_readable(remaining_data_bytes)}"
            )

    except BaseException as be:
        # don't alert on 408s if the user doesn't care about them
        if not (
            type(be) == HTTPError and be.response.status_code == 408 and args.ignore_408
        ):
            logger.error(f"{type(be).__name__} - {' '.join(str(a) for a in be.args)}")


if __name__ == "__main__":
    main()
