# Quest SRI
# Jessica Chen
# 7/12/2020

import sys


def vigenere(msg, key, crypt):
    msg_arr = []
    key_arr = []
    for char in key.lower():
        num = ord(char) - 97
        key_arr.append(num)
    for char in msg.lower():
        num = ord(char) - 97
        msg_arr.append(num)
    count = 0
    while count < len(msg):
        if crypt:
            msg_arr[count] += key_arr[count % len(key)]
        else:
            msg_arr[count] -= key_arr[count % len(key)]
        count += 1
    for num in range(len(msg_arr)):
        msg_arr[num] = chr((msg_arr[num] % 26) + 97)
    return "".join(msg_arr)


if __name__ == '__main__':
    message = input("Please enter a message: ")
    v_key = input("Please enter the Vigenere key: ")
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
    non_letters = ".,!?/ :;$*&@#'-"
    answer = vigenere(message, v_key, action)
    print("The answer is: " + answer)
