import requests
import hashlib
import sys


def request_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    req = requests.get(url)
    # print(req)
    if req.status_code != 200:
        raise RuntimeError(f"Fetching Error : {req.status_code} check your code.")
    return req


def get_pwd_hack_count(hash, hash_to_check):
    hashes = (line.split(":") for line in hash.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
        return 0


def read_res(response):
    print(response.text)


def api_check(password):
    request_data(password)
    sha1pwd = hashlib.sha1(password.encode('utf-8'))
    print(sha1pwd)
    # sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest()
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    print(sha1pwd)
    first_5_char, tail = sha1pwd[:5], sha1pwd[5:]
    response = request_data(first_5_char)
    read_res(response)
    print(first_5_char)
    return get_pwd_hack_count(response, tail)


def main(args):
    for passwords in args:
        count = api_check(passwords)
        if count:
            print(f"{passwords} was found {count} times... should change your password")
        else:
            print(f"{passwords} was NOT found... Carry on!")
    return "Done"


main(sys.argv[1:])