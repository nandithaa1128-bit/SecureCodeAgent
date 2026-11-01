def calculate(expression):
    return eval(expression)


def run_snippet(code):
    scope = {}
    exec(code, scope)
    return scope


def parse_value(text):
    return eval(text)


if __name__ == "__main__":
    print(calculate("2 + 3 * 4"))
    print(parse_value("[1, 2, 3]"))
