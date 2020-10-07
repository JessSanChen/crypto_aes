# Quest SRI
# Jessica Chen
# 7/19/2020


import sys
import ast


def find_gcf(a: int, b: int):
    lower = min(a, b)
    upper = max(a, b)
    while lower > 0:
        remainder = upper % lower
        upper = lower
        lower = remainder
    return upper


def find_inverse(num: int, mod: int):
    i, x, y = 0, num, mod
    quotient = []
    while x > 0:
        quotient.append(int(y/x))
        old_x = x
        x = y % x
        y = old_x
        i += 1
    t = 1
    s = 0
    i -= 1
    while i > 0:
        i -= 1
        old_t = t
        t = s - t * quotient[i]
        s = old_t
    t = t % mod
    return t


def affine(message: str, key: tuple, keyspace: int, action: bool):
    answer = []
    a = int(key[0])
    b = int(key[1])
    if find_gcf(a, keyspace) == 1:
        for num in range(len(message)):
            char = ord(message[num]) - 97
            if action:
                answer.append(chr((a*char + b) % keyspace + 97))
            else:
                mult_inv = find_inverse(a, keyspace)
                answer.append(chr(mult_inv*(char-b) % keyspace + 97))
    else:
        print("Please enter a value a for which gcd(a, keyspace) = 1.")
        sys.exit(0)
    return "".join(answer)


if __name__ == '__main__':
    message_input = (input("Please enter a message: ")).lower()
    message = ''.join(e for e in message_input if e.isalnum())
    try:
        key = ast.literal_eval(input("Please enter the affine key in (a,b) format: "))
    except ValueError:
        print("Please enter a tuple in the specified (a,b) format.")
        sys.exit(0)
    try:
        keyspace = int(input("Please enter the size of the keyspace: "))
    except ValueError:
        print("Please enter an integer for the size of the keyspace.")
        sys.exit(0)
    action_input = input("Please enter E to encrypt, D to decrypt, or X to exit: ")
    while action_input != "E" and action_input != "D" and action_input != "X":
        action_input = input("Please try again by denoting E to encrypt, D to decrypt, or X to exit: ")
    action = True
    if action_input == "E":
        action = True
    elif action_input == "D":
        action = False
    elif action_input == "X":
        sys.exit(0)
    print("The answer is: " + affine(message, key, keyspace, action))