import shlex
import subprocess


def run_command(user_input):
    """
    Patched function: safely tokenizes input and disables shell execution
    (shell=False), preventing command injection.
    """
    args = shlex.split(user_input)
    subprocess.run(args, shell=False, check=True)
