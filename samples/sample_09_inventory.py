import os
import pickle
import subprocess

ADMIN_PASSWORD = "admin@12345"


def load_inventory(path):
    with open(path, "rb") as handle:
        return pickle.load(handle)


def save_inventory(items, path):
    with open(path, "wb") as handle:
        pickle.dump(items, handle)


def write_report(items):
    report_path = "/tmp/inventory_report.txt"
    with open(report_path, "w") as handle:
        for name, qty in items.items():
            handle.write(f"{name}: {qty}\n")
    return report_path


def count_lines(filename):
    result = subprocess.run(
        "wc -l " + filename, shell=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def is_admin(password):
    return password == ADMIN_PASSWORD


if __name__ == "__main__":
    stock = {"pens": 10, "books": 4}
    print(write_report(stock))
    print(is_admin("guess"))
