# -*- coding: utf-8 -*-

import angr
import os
import subprocess
import claripy
import random
import multiprocessing
import time
import sys
import string

# record name
name_list = []
with open("names.txt") as file_in:
    for line in file_in:
        name_list.append(line.rstrip('\n'))

# print(name_list)

# record if-stms

if_stmts = ""
with open("if-stmts.txt") as file_in:
    for line in file_in:
        if_stmts += line.rstrip('\n')
# print(if_stmts)


# get encoding of variable
results = subprocess.run(['tail', '-1', 'test.c'], stdout=subprocess.PIPE).stdout.decode("utf-8")
org_res = results[2:-1]
# print(org_res)

# append new lines of variable to test.c
if os.stat("if-stmts.txt").st_size != 0:  # if this is not empty
    new_res = ""
    to_remove = []
    for i in range(len(name_list)):
        if if_stmts.find(name_list[i]) != -1:
            # print("found ", i)
            new_res += org_res[2*i] + org_res[2*i + 1]
        else:
            to_remove.append(name_list[i])

    # print("new_res : ", new_res)
    new_res = "//" + new_res + "\n"

    file = open("test.c", "a")
    file.write(new_res)
    file.close()

    # remove useless variables in test.c
    # print("to_remove", to_remove)
    for rm in to_remove:
        # print("rm :", rm)
        os.system("sed -n -i \'/{} = strto/!p\' test.c".format(rm))

