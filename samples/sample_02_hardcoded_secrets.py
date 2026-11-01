DB_PASSWORD = "P@ssw0rd123"
API_TOKEN = "tok_live_9f8e7d6c5b4a"


def connect_database(host):
    return {"host": host, "user": "admin", "password": DB_PASSWORD}


def call_service(session_password="letmein2024"):
    return {"Authorization": "Bearer " + API_TOKEN, "pwd": session_password}


def check_login(user, password):
    secret = "supersecretvalue"
    return user == "admin" and password == secret


if __name__ == "__main__":
    print(connect_database("localhost"))
