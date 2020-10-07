# Quest SRI
# Jessica Chen
# 7/2/2020

# print("Jessica")
# print("Chen")


def draw_diamond(num):
    if num%2==0: print("Please enter an odd number.")
    else:
        mid = int(num/2)
        for line in range(1,num+1):
            a = abs(mid-line+1)
            for pos in range(a):
                print(" ",end=" ")
            for pos in range(a,num-a):
                print("*", end=" ")
            print("\n")


draw_diamond(5)


