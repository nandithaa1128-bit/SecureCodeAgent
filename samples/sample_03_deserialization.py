import marshal
import pickle


def load_settings(path):
    with open(path, "rb") as handle:
        return pickle.load(handle)


def save_settings(settings, path):
    with open(path, "wb") as handle:
        pickle.dump(settings, handle)


def load_code_blob(path):
    with open(path, "rb") as handle:
        return marshal.load(handle)


if __name__ == "__main__":
    save_settings({"theme": "dark", "volume": 7}, "settings.bin")
    print(load_settings("settings.bin"))
