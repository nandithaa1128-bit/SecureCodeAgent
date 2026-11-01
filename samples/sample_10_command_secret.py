
import os
import subprocess

def run_command(user_input):
    # Vulnerable: executes user input directly
    subprocess.call(user_input, shell=True)

def get_secret():
    # Vulnerable: hardcoded secret
    api_key = "my_secret_api_key_12345"
    return api_key

def read_file(filename):
    # Vulnerable: unsafe file access
    with open(filename, "r") as file:
        return file.read()

if __name__ == "__main__":
    run_command("echo Hello")
    print(get_secret())
