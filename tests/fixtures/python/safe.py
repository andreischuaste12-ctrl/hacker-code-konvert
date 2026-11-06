import ast


def calculate(expression: str):
    return ast.literal_eval(expression)
