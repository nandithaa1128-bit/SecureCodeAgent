import socket


def start_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    return server


def withdraw(balance, amount):
    assert amount > 0
    assert amount <= balance
    return balance - amount


def read_optional(path):
    try:
        with open(path) as handle:
            return handle.read()
    except Exception:
        pass
    return ""


if __name__ == "__main__":
    print(withdraw(100, 30))
