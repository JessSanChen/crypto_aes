# Quest SRI
# Jessica Chen
# 7/9/2020

import sys


def return_rail_fence(msg: str, key: int):
    graph = [[] for _ in range(key)]
    count = 0
    row_num = 0
    dire = 1
    while count < len(msg):
        graph[row_num].append(msg[count])
        count += 1
        if dire > 0:
            row_num += 1
        else:
            row_num -= 1
        if row_num == key - 1 or row_num == 0:
            dire *= -1
    return graph


def rail_fence_encrypt(msg, key):
    cipher = ""
    graph = return_rail_fence(msg, key)
    for num in range(key):
        temp = "".join(graph[num])
        cipher = cipher + temp
    return cipher


def rail_fence_decrypt(msg, key):
    formation = return_rail_fence(msg, key)
    graph = []
    count = 0
    for row_num in range(len(formation)):
        length = len(formation[row_num])
        row = []
        for num in range(length):
            row.append(msg[count])
            count += 1
        graph.append(row)
    result = []
    count = 0
    row_num = 0
    dir = 1
    while count < len(msg):
        row = graph[row_num]
        result.append(row.pop(0))
        count += 1
        if dir > 0:
            row_num += 1
        else:
            row_num -= 1
        if row_num == key - 1 or row_num == 0:
            dir *= -1
    return "".join(result)


def shift_crypt(msg, key, crypt):
    plain = msg.lower()
    arr = []
    for char in plain:
        if char in non_letters:
            arr.append(char)
        else:
            num = ord(char) - 97
            if crypt:
                num += key
            else:
                num -= key
            new_num = (num % 26) + 97
            arr.append(chr(new_num))
    return "".join(arr)


if __name__ == '__main__':
    message = input("Please enter a message: ")
    rf_key = int(input("Please enter the rail-fence cipher key: "))
    shift_key = int(input("Please enter the shift cipher key: "))
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
    answer = ""
    if action:
        answer = shift_crypt(rail_fence_encrypt(message, rf_key), shift_key, action)
    else:
        answer = rail_fence_decrypt(shift_crypt(message, shift_key, action), rf_key)
    print("The answer is: " + answer)
