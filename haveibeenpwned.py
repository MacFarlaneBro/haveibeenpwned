#!/usr/bin/env python3.6
# Author = Laurens Houben
# Contact = https://www.linkedin.com/in/laurenshouben
# TODO:
# - Retrieve breached domain from response in case of a breach:
#   Example response for blup@blup.com:
#   [{"Title":"Adobe","Name":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","AddedDate":"2013-12-04T00:00:00Z","PwnCount":152445165,"Description":"In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, <em>encrypted</em> password and a password hint in plain text. The password cryptography was poorly done and <a href=\"http://stricture-group.com/files/adobe-top100.txt\" target=\"_blank\" rel=\"noopener\">many were quickly resolved back to plain text</a>. The unencrypted hints also <a href=\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\" target=\"_blank\" rel=\"noopener\">disclosed much about the passwords</a> adding further to the risk that hundreds of millions of Adobe customers already faced.","DataClasses":["Email addresses","Password hints","Passwords","Usernames"],"IsVerified":true,"IsSensitive":false,"IsActive":true,"IsRetired":false,"IsSpamList":false,"LogoType":"svg"},{"Title":"Xbox-Scene","Name":"Xbox-Scene","Domain":"xboxscene.com","BreachDate":"2015-02-01","AddedDate":"2016-02-07T20:26:56Z","PwnCount":432552,"Description":"In approximately February 2015, the Xbox forum known as <a href=\"http://xboxscene.com/\" target=\"_blank\" rel=\"noopener\">Xbox-Scene</a> was hacked and more than 432k accounts were exposed. The IP.Board forum included IP addresses and passwords stored as salted hashes using a weak implementation enabling many to be rapidly cracked.","DataClasses":["Email addresses","IP addresses","Passwords","Usernames"],"IsVerified":true,"IsSensitive":false,"IsActive":true,"IsRetired":false,"IsSpamList":false,"LogoType":"png"}]
# -

import requests
import time
import argparse

parser = argparse.ArgumentParser(description="Verify if email address has been pwned")
parser.add_argument("-a", dest="address", help="Single email address to be checked")
parser.add_argument(
    "-f", dest="filename", help="File to be checked with one email addresses per line"
)
parser.add_argument(
    "-w", action="store_true", help="Write the output of the command to a file"
)

args = parser.parse_args()

rate = (
    1.3
)  # 1.3 seconds is a safe value that in most cases does not trigger rate limiting
server = "haveibeenpwned.com"  # Website to contact
sslVerify = (
    True
)  # Verify server certificate (set to False when you use a debugging proxy like BurpSuite)
proxies = {  # Proxy to use (debugging)
    #  'http': 'http://127.0.0.1:8080',    # Uncomment when needed
    #  'https': 'http://127.0.0.1:8080',   # Uncomment when needed
}

# Set terminal ANSI code colors
OKGREEN = "\033[92m"
WARNING = "\033[93m"
FAILRED = "\033[91m"
ENDC = "\033[0m"

address = str(args.address)
filename = str(args.filename)
write = args.w


def main():
    if address != "None":
        checkAddress(address)
    elif filename != "None":
        email = [line.rstrip("\n") for line in open(filename)]
        if write:
            with open("pwned_or_not.csv", "a") as output_file:
                for email in email:
                    checkAddress(email, output_file)
        else:
            for email in email:
                checkAddress(email)
    else:
        print(
            "Please either specify an email address or a list of email addresses to be checked."
        )


def checkAddress(email, output_file=None):
    sleep = rate  # Reset default acceptable rate
    print(email)
    check = requests.get(
        "https://"
        + server
        + "/api/v2/breachedaccount/"
        + email
        + "?includeUnverified=true",
        proxies=proxies,
        verify=sslVerify,
    )
    print(check)

    if check.status_code == 404:  # The address has not been breached.
        print(OKGREEN + "[i] " + email + " has not been breached." + ENDC)
        time.sleep(sleep)  # sleep so that we don't trigger the rate limit
        status = False
    elif check.status_code == 200:  # The address has been breached!
        print(FAILRED + "[!] " + email + " has been breached!" + ENDC)
        time.sleep(sleep)  # sleep so that we don't trigger the rate limit
        status = True
    elif check.status_code == 429:  # Rate limit triggered
        print(
            WARNING
            + "[!] Rate limit exceeded, server instructed us to retry after "
            + check.headers["Retry-After"]
            + " seconds"
            + ENDC
        )
        print(
            WARNING
            + "    Refer to acceptable use of API: https://haveibeenpwned.com/API/v2#AcceptableUse"
            + ENDC
        )
        sleep = float(
            check.headers["Retry-After"]
        )  # Read rate limit from HTTP response headers and set local sleep rate
        time.sleep(sleep)  # sleeping a little longer as the server instructed us to do
        checkAddress(email)  # try again
    else:
        print(WARNING + "[!] Something went wrong while checking " + email + ENDC)
        time.sleep(sleep)  # sleep so that we don't trigger the rate limit
        status = True

    if output_file:
        output_file.write(f"{email}, {status}\n")

    return status


if __name__ == "__main__":
    main()
