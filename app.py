import hashlib
import sys

import requests


def request_api_data(query_chars):
    url = 'https://api.pwnedpasswords.com/range/' + query_chars
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError(f'Error Fetching: {res.status_code}, check the API and try again.')

    return res


def check_pwned_api(password):
    # Check password if it exists in API response
    hashed_password = hash_password(password)
    first_5_chars, tail = hashed_password[:5], hashed_password[5:]
    res = request_api_data(first_5_chars)

    return get_pass_leaks_count(res, tail)


def get_pass_leaks_count(hashes, hash_to_check):
    response_lines = hashes.text.splitlines()
    response_hashes = (line.split(':') for line in response_lines)

    for cracked_hash, count in response_hashes:
        if cracked_hash == hash_to_check:
            return count

    return 0


def hash_password(password):
    utf8_password = password.encode('utf8')
    sha1_password = hashlib.sha1(utf8_password)
    sha1_digest = sha1_password.hexdigest().upper()

    return sha1_digest


def main(args):
    for password in args:

        count = check_pwned_api(password)

        if count:
            print(f'{password} was found {count} times in vulnerability library...')
        else:
            print(f'{password} was NOT found in vulnerability library.')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

