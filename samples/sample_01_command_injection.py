import os
import subprocess


def ping_host(host):
    return os.system("ping -c 1 " + host)


def list_directory(path):
    output = subprocess.check_output("ls -l " + path, shell=True)
    return output.decode()


def archive_folder(folder, name):
    subprocess.call("tar -czf " + name + ".tar.gz " + folder, shell=True)


if __name__ == "__main__":
    print(list_directory("."))
