__version__ = "0.0.2"

import logging
from six.moves.urllib.parse import urlparse, urljoin
from six.moves.http_cookiejar import MozillaCookieJar
import xml.etree.ElementTree as ET
import requests
import time
import argparse

CERN_SSO_COOKIE_LIFETIME_S = 24 * 60 * 60
DEFAULT_TIMEOUT_SECONDS = 20
CERT_AUTH_URL_FRAGMENT = u"auth/sslclient/"


def setup_logger():
    fmt = logging.Formatter(
        fmt="\033[33m[cernsso|%(levelname)8s|%(asctime)s|%(module)s]:\033[0m %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler = logging.StreamHandler()
    handler.setFormatter(fmt)
    logger = logging.getLogger("cernsso")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger


logger = setup_logger()


def debug(flag=True):
    logger.setLevel(logging.DEBUG if flag else logging.INO)


def disable_warnings():
    # Try to disable warnings, but no big deal if this fails
    try:
        from requests.packages.urllib3.exceptions import InsecureRequestWarning

        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        logger.warning("All requests made will run with verify=False!")
    except Exception:
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("All requests made will run with verify=False!")
        except Exception:
            pass


disable_warnings()


def session_from_cookies_file(
    cert_file,
    key_file,
    cookie_filename="cookies.txt",
):
    logger.debug(
        "Setting up session using cert=%s key=%s based on cookies in %s",
        cert_file,
        key_file,
        cookie_filename,
    )
    s = requests.Session()
    s.cert = (cert_file, key_file)
    s.cookies = MozillaCookieJar(cookie_filename)
    s.cookies.load(ignore_discard=True, ignore_expires=True)
    return s


def refresh_cookies_file(
    url,
    cert_file,
    key_file,
    cookie_filename="cookies.txt",
):
    s = fresh_session(url, cert_file, key_file, cookie_filename)

    logger.info("Rewriting cookie expiration dates")
    for cookie in s.cookies:
        old_expires = cookie.expires
        cookie.expires = int(time.time() + CERN_SSO_COOKIE_LIFETIME_S)
        logger.debug(
            "Updating expiry date for cookie %s %s -> %s",
            cookie.name,
            old_expires,
            cookie.expires,
        )
        # This session cookie is not a session cookie. Definitely not.
        cookie.discard = False
    s.cookies.save()


def fresh_session(
    url,
    cert_file,
    key_file,
    cookie_filename="cookies.txt",
):
    logger.debug("Setting up fresh session using cert=%s key=%s", cert_file, key_file)

    s = requests.Session()
    s.cert = (cert_file, key_file)
    cookiejar = MozillaCookieJar(cookie_filename)
    s.cookies = cookiejar

    logger.info("Request #1, to get main redirect to authentication: %s", url)
    r1 = s.get(url, timeout=DEFAULT_TIMEOUT_SECONDS, verify=False)

    # Parse out the session keys from the GET arguments:
    redirect_url = urlparse(r1.url)
    logger.debug("Was redirected to SSO URL: %s", str(redirect_url))

    # ...and inject them into the Kerberos authentication URL
    final_auth_url = "{0}?{1}".format(
        urljoin(r1.url, CERT_AUTH_URL_FRAGMENT), redirect_url.query
    )
    logger.info(
        "Request #2, performing SSL Cert authentication against %s", final_auth_url
    )
    r2 = s.get(
        final_auth_url, cookies=cookiejar, verify=False, timeout=DEFAULT_TIMEOUT_SECONDS
    )

    # Did it work? Raise Exception otherwise.
    r2.raise_for_status()

    # Get the contents
    try:
        tree = ET.fromstring(r2.content)
    except ET.ParseError as e:
        logger.error(
            "Could not parse response from server! "
            "The contents returned was:\n{}".format(r2.content)
        )
        raise e

    action = tree.findall("body/form")[0].get("action")

    # Unpack the hidden form data fields
    form_data = {
        elm.get("name"): elm.get("value") for elm in tree.findall("body/form/input")
    }

    # ...and submit the form (WHY IS THIS STEP EVEN HERE!?)
    logger.info("Performing final authentication POST to %s", action)
    r3 = s.post(url=action, data=form_data, timeout=DEFAULT_TIMEOUT_SECONDS)
    # Did _that_ work?
    r3.raise_for_status()

    # The session cookie jar should now contain the necessary cookies.
    logger.debug("Cookie jar now contains: %s", str(s.cookies))
    return s


def cli_get_cookies():
    parser = argparse.ArgumentParser()
    parser.add_argument("url", type=str, help="URL to get cookies for")
    parser.add_argument("-c", "--cert", type=str, help="Path to a .pem file")
    parser.add_argument("-k", "--key", type=str, help="Path to a .key file")
    parser.add_argument(
        "-o",
        "--out",
        type=str,
        default="cookies.txt",
        help="Path to the output cookies file (default=%(default))",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        debug()

    refresh_cookies_file(args.url, args.cert, args.key)
