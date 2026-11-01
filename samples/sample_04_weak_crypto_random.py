import hashlib
import random
import string


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def file_checksum(data):
    return hashlib.sha1(data).hexdigest()


def make_reset_token(length=16):
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def make_session_id():
    return random.randint(100000, 999999)


if __name__ == "__main__":
    print(hash_password("hello"))
    print(make_reset_token())
