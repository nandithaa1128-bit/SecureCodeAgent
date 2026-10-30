import subprocess


def run_command(user_input):
    """
    Vulnerable function: uses shell=True with untrusted user input,
    leading to CWE-78 / B602 (Command Injection).
    """
    subprocess.call(user_input, shell=True)
