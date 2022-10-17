# -*- coding: utf-8 -*-

import angr
# from angrutils import *
import os
import subprocess
import claripy
import random
import multiprocessing
import time
import sys
import string
import collections
import re

compare = lambda x, y: collections.Counter(x) == collections.Counter(y)


def get_hex(text):
    valid_set = '0123456789abcdefABCDEF'
    sym_set = '+-x'
    res = ""
    index = 0
    '''
    for i in text:
        if '0' <= i <= '9' or 'A' <= i <= 'F' or 'a' <= i <= 'f':  # or i == '+' or i == '-':  # 0-9 a-f A-F + -
            res += i
            continue
        if index == 0 and (i == '+' or i == '-'):  # + -
            res += i
            continue
        if i == 'x' and (index == 1 or index == 2):  # 0x
            res += i
            continue
        # if i == ' ':
        if i not in set(string.printable) or i == ' ' or i == '`' or i == '@':
            break
        index += 1
    '''
    for i in text:
        if valid_set.find(i) != -1:
            # if valid_set.find(i) != -1 and (i == 'x' and (index == 1 or index == 2)):
            # and text[len(text) - 1] != '+' and text[len(text) - 1] != '-' and text[len(text) - 1] != 'x':
            res += i
        elif index == 1 and (text[0] != '-' or text[0] != '+') and text[index - 1] == '0' and text[index] == 'x':  # 0x
            res += i
        elif index == 2 and (text[0] == '-' or text[0] == '+') and text[index - 1] == '0' and text[index] == 'x':
            res += i
        elif index == 0 and (text[0] == '-' or text[0] == '+'):
            res += i
        else:
            break
        index += 1
    # print("before handling 0x : ", res)
    new_res = ""
    if len(res) == 0:
        new_res = "0"
        return new_res
    # if res.find('0x') != -1 and res[0] != '-' and res[0] != '+':
    #    return res
    if res.find('0x') != -1:  # it has 0x
        # new_res = res[0] + "0x" + res[1:]
        if res == "-0x" or res == "+0x" or res == "0x":
            return "0"
        else:
            new_res == res
    # else:
    #    new_res = "0x" + res
    #    return new_res
    # print("res ", res.find('0x'), res[0], new_res)
    if res.find('0x') == -1 and res[0] == '-':  # doesn't have 0x
        new_res = res[0] + '0x' + res[1:]
    elif res.find('0x') == -1 and res[0] == '+':  # doesn't have 0x
        new_res = res[0] + '0x' + res[1:]
    elif res.find('0x') == -1 and res[0] != '-' and res[0] != '+':  # doesn't have 0x
        # return new_res
        new_res = '0x' + res
    else:
        new_res = res
        # return new_res
    # cut final "+-x"
    # print("before cutting: ", new_res)
    c = new_res[len(new_res) - 1]
    while c == '+' or c == '-' or c == 'x':
        new_res = new_res[:len(new_res) - 1]
        c = new_res[len(new_res) - 1]
    return new_res


def remove_dup(ss):
    return list(set(ss))


def remove_dup_con(con):
    ret = []
    ret_temp = []
    temp = set()
    for cc in con:
        for c in cc:
            temp.add(c)
    if temp not in ret_temp:
        ret.append(cc)
    return ret


def is_the_same(str_set1, str_set2):
    # covert the set to string list
    # if len(str_set1) == 0 or len(str_set2) == 0:  # skip zero cases? TODO
    #    return True
    str_list1 = []
    str_list2 = []
    for s1 in str_set1:
        s1_list = s1.split()
        str_list1.extend(s1_list)
    for s2 in str_set2:
        s2_list = s2.split()
        str_list2.extend(s2_list)
    # print(str_list1)
    # print(str_list2)
    if len(str_list1) == len(str_list2):  # have the same length
        str_list1_set = set(str_list1)
        str_list2_set = set(str_list2)
        print("str_list1_set : ", str_list1_set)
        print("str_list2_set : ", str_list2_set)
        if str_list1_set.issubset(str_list2_set) and str_list2_set.issubset(str_list1_set):
            return True
        else:
            return False
    else:
        return False


def checking_binary_diff(binary1, binary2, angr_set1, angr_set2):
    os.system("objdump -d b-marker1 | grep marker | grep \"call|\jmp\" | awk \'{print $9}\' > out1.txt")
    os.system("objdump -d b-marker2 | grep marker | grep \"call\|jmp\" | awk \'{print $9}\'> out2.txt")

    list1 = []
    with open("out1.txt") as file_in:
        for line in file_in:
            line = re.findall(r"\d+\.?\d*", line)
            list1.append(line)
    set1 = set()
    for ss in list1:
        for s in ss:
            set1.add(s)

    list2 = []
    with open("out2.txt") as file_in:
        for line in file_in:
            line = re.findall(r"\d+\.?\d*", line)
            list2.append(line)

    set2 = set()
    for ss in list2:
        for s in ss:
            set2.add(s)
    # n1 = set(list1)
    # n2 = set(list2)
    print("before comparing set1: ", set1)
    print("before comparing set2: ", set2)

    n1 = set1
    n2 = set2
    if n1.issubset(n2) is not True or n2.issubset(n1) is not True and len(n1) > 1 and len(n2) > 1:
        print("Find a diff of binary")
        dd1 = n1 - n2
        dd2 = n2 - n1
        diff = set()
        diff_se = set()
        for d1 in dd1:
            diff.add(d1)
        for d2 in dd2:
            diff.add(d2)
        for s1 in angr_set1:
            diff_se.add(s1)
        for s2 in angr_set2:
            diff_se.add(s2)
        if diff.issubset(diff_se) is True or diff_se.issubset(diff) is True:
            return True
        else:
            return False
    else:
        print("Nothing interesting :-(\n")
        return False


def test_native():
    # record name
    name_list = []
    with open("names.txt") as file_in:
        for line in file_in:
            name_list.append(line.rstrip('\n'))
    # print("name_list : ", name_list, len(name_list))

    # concrete_value can be many?
    # concrete_value_list = list()
    concrete_value = []
    with open("temp.txt") as file_in:
        for line in file_in:
            concrete_value.append(line.rstrip('\n'))
    print("concrete_value : ", concrete_value)
    # cut and split
    for index in range(len(concrete_value)):
        print("now testing concrete value : ", concrete_value[index])
        value_list = concrete_value[index].split(" ")
        value_list = value_list[:-1]
        # print("value_list : ", value_list, len(value_list))
        new_assign = []
        # cut the last ''
        if len(name_list) != len(value_list):
            print("Error: the number of name and concrete value is not matched ...")
            print("name : ", len(name_list))
            print("value_list", len(value_list))
            exit(1)
        for i in range(len(name_list)):
            s = name_list[i] + " = " + value_list[i] + " ;"
            new_assign.append(s)
        # print(new_assign)
        orig_assign = []
        for name in name_list:
            out = subprocess.check_output("grep \"%s = strto\" test.c" % name, shell=True)
            # print(out.decode())
            orig_assign.append(out.decode()[4:-2])
        # print(orig_assign)
        # replace
        os.system("cp test.c test-csmith.c")
        for j in range(len(name_list)):
            # print("orig_assign[i] : ", orig_assign[j])
            # print("new_assign[i] : ", new_assign[j])
            os.system("sed -i \'s/{} = strto.*/{}/g\' test-csmith.c".format(name_list[j], new_assign[j]))
            # os.system("cat test.c")
        print("Replace variables done and string native running and checking ...")
        # conduct compiler testing
        os.system("./compiler_test.pl 1 compiler_test.in")


def test_native_with_csmith_run():
    # record name
    name_list = []
    with open("names.txt") as file_in:
        for line in file_in:
            name_list.append(line.rstrip('\n'))
    # print("name_list : ", name_list, len(name_list))

    # concrete_value can be many?
    # concrete_value_list = list()
    concrete_value = []
    with open("temp.txt") as file_in:
        for line in file_in:
            concrete_value.append(line.rstrip('\n'))
    print("concrete_value : ", concrete_value)
    # cut and split
    for index in range(len(concrete_value)):
        print("now testing concrete value : ", concrete_value[index])
        value_list = concrete_value[index].split(" ")
        value_list = value_list[:-1]
        # print("value_list : ", value_list, len(value_list))
        # cut the last ''
        if len(name_list) != len(value_list):
            print("Error: the number of name and concrete value is not matched ...")
            print("name : ", len(name_list))
            print("value_list", len(value_list))
            exit(1)
        # step 1: get the seed number
        seed_number = subprocess.check_output("head -7 test.c | tail -1 | awk '{print $3}'", shell=True)
        print("seed_number : ", seed_number.decode("utf-8").strip("\n"))

        file_temp = open("testcase.txt", "w")
        for tt in value_list:
            file_temp.write(tt + ", ")
        file_temp.write("\n")
        file_temp.close()
        # write the value to the testcase.txt
        # generate the function using csmith-run
        os.system("csmith-run --max-funcs 10 --max-expr-complexity 10 -s %s > test-csmith.c" % int(seed_number))
        print("Replace variables done and string native running and checking ...")
        # conduct compiler testing
        os.system("./compiler_test.pl 1 compiler_test.in")


def test_native_no_recompiliation():
    # record name
    name_list = []
    with open("names.txt") as file_in:
        for line in file_in:
            name_list.append(line.rstrip('\n'))
    # print("name_list : ", name_list, len(name_list))

    # concrete_value can be many?
    # concrete_value_list = list()
    concrete_value = []
    with open("temp.txt") as file_in:
        for line in file_in:
            concrete_value.append(line.rstrip('\n'))
    print("concrete_value : ", concrete_value)
    # cut and split
    for index in range(len(concrete_value)):
        print("now testing concrete value : ", concrete_value[index])
        value_list = concrete_value[index].split(" ")
        value_list = value_list[:-1]
        # print("value_list : ", value_list, len(value_list))
        # cut the last ''
        if len(name_list) != len(value_list):
            print("Error: the number of name and concrete value is not matched ...")
            print("name : ", name_list, len(name_list))
            print("value_list", value_list, len(value_list))
            exit(1)
        num = int(random.random()*100000000)
        # os.system("cp test.c wrong-candidate-{}.c".format(num))
        # os.system("cat temp.txt >> wrong-candidate-{}.c".format(num))
        exit_code1 = subprocess.check_output("timeout 3 ./test1 %s > out1111.txt 2>&1; echo $?" % value_list, shell=True)
        exit_code2 = subprocess.check_output("timeout 3 ./test2 %s > out2222.txt 2>&1; echo $?" % value_list, shell=True)
        print("exit_code1 : ", exit_code1)
        print("exit_code2 : ", exit_code2)
        if exit_code1 == b'124\n' and exit_code2 == b'124\n':  # omit the timeout cases?
            print("both timeout?")
            break
        if exit_code1 != b'124\n' and exit_code2 == b'124\n':  # omit the timeout cases?
            os.system("cp test.c timeout-{}.c".format(num))
            os.system("echo \"/*\" >> wrong-{}.c".format(num))
            os.system("cat temp.txt >> wrong-{}.c".format(num))
            os.system("echo \"*/\" >> wrong-{}.c".format(num))
            break
        if exit_code1 == b'124\n' and exit_code2 != b'124\n':  # omit the timeout cases?
            os.system("cp test.c timeout-{}.c".format(num))
            os.system("echo \"/*\" >> wrong-{}.c".format(num))
            os.system("cat temp.txt >> wrong-{}.c".format(num))
            os.system("echo \"*/\" >> wrong-{}.c".format(num))
            break
        out1 = subprocess.check_output("cat out1111.txt", shell=True)
        out2 = subprocess.check_output("cat out2222.txt", shell=True)
        if (out1 != out2) is True:
            os.system("cp test.c wrong-{}.c".format(num))
            os.system("echo \"/*\" >> wrong-{}.c".format(num))
            os.system("echo \"The different results:\" >> wrong-{}.c".format(num))
            os.system("echo %s >> wrong-{}.c".format(num) % out1)
            os.system("echo %s >> wrong-{}.c".format(num) % out2)
            os.system("echo \"*/\" >> wrong-{}.c".format(num))
            print("out1 : ", exit_code1, out1)
            print("out2 : ", exit_code2, out2)
    os.system("rm out1111.txt out2222.txt")


# Main process

# 1. Get the sequences of type and size of each variable from `csmith-se`

# 2. Make those variables symbolic and control their range; TODO range can be done later

# 3. Conduct binary symbolic execution by angr

# 4. Compare and record results; path explored and record concrete values of symbolic variables

# 5. Get each set of concrete values and re-run with test program generated by `csmith-run`


# set compilers and options to test
#
# Step 1
#

results = subprocess.run(['tail', '-1', 'test.c'], stdout=subprocess.PIPE).stdout.decode("utf-8")

print(results[2:-1])
print(len(results[2:-1]))

len_results = len(results[2:-1])

if len_results % 2 != 0:
    print("Error: check return from source code test.c !")
    exit(1)

var_sym = []
var_size = []
dict_sym = {}

for i in range(0, len_results, 2):
    var_sym.append(results[2+i])
    var_size.append(results[2+i+1])

# print(var_sym)
# print("number of symbolic variable: ", var_size)

for i in range(len(var_sym)):
    dict_sym['arg{}'.format(i)] = [var_sym[i], var_size[i]]

# print(dict_sym)

#
# Step 2
#

# make symbolic for each variable
keys = []
for key, value in dict_sym.items():
    # print(key)
    locals()[key] = claripy.BVS(key, 8*int(value[1])*2)
    keys.append(locals()[key])

# for i in range(len(var_sym)):
#     keys += "arg" + str(i) + ", "
# print(keys)

# os.system("{} -w -{} -o b-{}-{}".format(cmp1, o, cmp1, o))
# os.system("{} -w -{} -o b-{}-{}".format(cmp2, o, cmp2, o))

target_binary1 = sys.argv[1]
#target_binary2 = sys.argv[2]
find_str = sys.argv[2:]
print("find_str : ", find_str)
# here find_bytes should be a sequence
find_str_dig = list()
# find_str_dig = re.findall(r'\d+', find_str)
for f in find_str:
    find_str_dig.append(f)
# find_str_dig = find_str_dig[1:len(find_str_dig)-1]
find_str_dig = find_str_dig  # no need to cut start/end
# print("find_str_dig seq : ", find_str_dig)
find_seq = ""
for s in find_str_dig:
    find_seq += s
find_seq = find_seq.replace(",", "")
find_seq = find_seq.replace("[", "")
find_seq = find_seq.replace("]", "")
find_seq = 'b' + find_seq + 'b'
print("find_seq: ", find_seq)

find_bytes = bytes(find_seq, "utf-8")
# os.system("./csmith-test.sh {} {}".format(cmp1, cmp2))

# os.system("./perform-ct-marker.sh {} {} {} {} {} {}".format(cmp1, cmp2, o, max_funcs, max_expr_complexity, csmith_options))

# for target_binary1
p1 = angr.Project(target_binary1, load_options={'auto_load_libs': False})
# state1 = p1.factory.entry_state(args=['./gcc-11-O1-test', keys], add_options={angr.options.TRACK_ACTION_HISTORY})
# cfg1 = p1.analyses.CFGEmulated(keep_state=True)
cfg1 = p1.analyses.CFGFast()
# state1 = p1.factory.entry_state(addr=main.rebased_addr, args=['./{}-{}-test'.format(cmp1, o), *keys])  # add_options={angr.options.TRACK_ACTION_HISTORY})
state1 = p1.factory.entry_state(args=[target_binary1, *keys], add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})

# add more constraints for signed/unsigned issue
for i in range(len(var_sym)):
    # print(keys[i])
    if var_sym[i] == 0 and var_type[i] == 1:  # int8_t
        state1.solver.add(0 <= keys[i] <= 127)
    if var_sym[i] == 0 and var_type[i] == 2:  # int16_t
        state1.solver.add(-32768 <= keys[i] <= 32767)
    if var_sym[i] == 0 and var_type[i] == 4:  # int32_t
        state1.solver.add(-2147483648 <= keys[i] <= 2147483647)
    if var_sym[i] == 0 and var_type[i] == 8:  # long or long long or int64_t
        state1.solver.add(-9223372036854775808 <= keys[i] <= 9223372036854775807)
        # state1.solver.add(0 < keys[i] < 9223372036854775807)
    if var_sym[i] == 1 and var_type[i] == 1:  # uint8_t
        state1.solver.add(0 <= keys[i] <= 255)
    if var_sym[i] == 1 and var_type[i] == 2:  # uint16_t
        state1.solver.add(0 <= keys[i] <= 65535)
    if var_sym[i] == 1 and var_type[i] == 4:  # uint32_t
        state1.solver.add(0 <= keys[i] <= 4294967295)
    if var_sym[i] == 1 and var_type[i] == 8:  # uint64_t
        state1.solver.add(0 <= keys[i] <= 18446744073709551615)


sm1 = p1.factory.simulation_manager(state1)
# sm1.run()

sm1.explore(find=lambda s: find_bytes in s.posix.dumps(1))
# print(sm1.deadended)
print(sm1)
# str11 = sm1.deadended[0].solver.constraints
# print(str11)
testcase1 = []
constraints1 = []
output1 = []
raw_results1 = []
for i in range(len(sm1.found)):
    o1 = sm1.found[i].posix.dumps(1).decode('utf-8')
    output1.append(o1)
    print(sm1.found[i].posix.dumps(1))

    temp_list = []
    raw = []
    for arg in keys:
        b = sm1.found[i].solver.eval(arg, cast_to=bytes).rstrip(b'\x00')
        b_strstr = str(b).split("\\x")[0]
        if b_strstr.find('\'') != -1:
            b_str = str(b).split("\\x")[0].split('\'')[1]
        else:
            b_str = ""
        raw.append(b_str)
        temp_list.append(get_hex(b_str))
    # print(temp_list)
    testcase1.append(temp_list)
    raw_results1.append(raw)

'''
# for target_binary2
p2 = angr.Project(target_binary2, load_options={'auto_load_libs': False})
cfg2 = p2.analyses.CFGFast()

state2 = p2.factory.entry_state(args=[target_binary2, *keys],
                                add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                             angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
# state2 = p2.factory.entry_state(args=['./gcc-trunk-O3-test', arg1])
# add more constraints for signed/unsigned issue
for i in range(len(var_sym)):
    if var_sym[i] == 0 and var_type[i] == 1:  # int8_t
        # state2.solver.add(-128 < keys[i] < 127)
        state2.solver.add(0 <= keys[i] <= 127)
    if var_sym[i] == 0 and var_type[i] == 2:  # int16_t
        state2.solver.add(-32768 <= keys[i] <= 32767)
        # state2.solver.add(0 < keys[i] < 32767)
    if var_sym[i] == 0 and var_type[i] == 4:  # int32_t
        state2.solver.add(-2147483648 <= keys[i] <= 2147483647)
        # state2.solver.add(0 < keys[i] < 2147483647)
    if var_sym[i] == 0 and var_type[i] == 8:  # long or long long or int64_t
        state2.solver.add(-9223372036854775808 <= keys[i] <= 9223372036854775807)
        # state2.solver.add(0 < keys[i] < 9223372036854775807)
    if var_sym[i] == 1 and var_type[i] == 1:  # uint8_t
        state2.solver.add(0 <= keys[i] <= 255)
    if var_sym[i] == 1 and var_type[i] == 2:  # uint16_t
        state2.solver.add(0 <= keys[i] <= 65535)
    if var_sym[i] == 1 and var_type[i] == 4:  # uint32_t
        state2.solver.add(0 <= keys[i] <= 4294967295)
    if var_sym[i] == 1 and var_type[i] == 8:  # uint64_t
        state2.solver.add(0 <= keys[i] <= 18446744073709551615)

sm2 = p2.factory.simulation_manager(state2)
# sm2.run()
sm2.explore(find=lambda s: find_bytes in s.posix.dumps(1))
# print(sm2.deadended)
print(sm2)
testcase2 = []
constraints2 = []
output2 = []
raw_results2 = []
for i in range(len(sm2.found)):
    o2 = sm2.found[i].posix.dumps(1).decode('utf-8')
    output2.append(o2)
    print(sm2.found[i].posix.dumps(1))
    # print(sm1.deadended[i].posix.dumps(1))
    temp_list = []
    raw = []
    for arg in keys:
        b = sm2.found[i].solver.eval(arg, cast_to=bytes).rstrip(b'\x00')
        # b = sm2.deadended[i].solver.eval(arg, cast_to=bytes)
        b_strstr = str(b).split("\\x")[0]
        if b_strstr.find('\'') != -1:
            b_str = str(b).split("\\x")[0].split('\'')[1]
        else:
            b_str = ""
        raw.append(b_str)
        temp_list.append(get_hex(b_str))
    testcase2.append(temp_list)
    raw_results2.append(raw)

    # deal with constraints
    # constraints2.append(sm1.deadended[i].solver.constraints)
    # print(testcase[i])
# print(testcase2)


if (len(testcase1) != 0) or (len(testcase2) != 0):
    str1 = []
    str2 = []
    for t1 in testcase1:
        # print(" ".join(str(tt1) for tt1 in t1))
        str1.append(", ".join(str(tt1) for tt1 in t1))
    for t2 in testcase2:
        # print(" ".join(str(tt2) for tt2 in t2))
        str2.append(", ".join(str(tt2) for tt2 in t2))
    # print(str1, str2)
    file = open("testcases.txt", "w")
    for s1 in str1:
        file.write(s1 + "\n")
    for s2 in str2:
        file.write(s2 + "\n")
    file.close()
'''
# compare results and perform recording
file_temp = open("temp.txt", "w")
# file_temp.write("/*\n")
# file_temp.write("++++++++++++++++ From output1 ++++++++++++++\n")
# file_temp.write("Information of {} \n".format(target_binary1))
# file_temp.write("--raw solver results:\n")
# for rr in raw_results1:
#    for r in rr:
#        file_temp.write(r + " ")
#    file_temp.write("\n")

# file_temp.write("--path information:\n")
# out1 = remove_dup(output1)
# for out in out1:
#    file_temp.write(out + " ")
#    file_temp.write("\n")

# file_temp.write("--recorded results (may be different from raw solver results):\n")
for tt in testcase1:
    for t in tt:
        file_temp.write(t + " ")
    file_temp.write("\n")
    # for t in tt:
    #    file_temp.write(t + " ")

# file_temp.write("\n")
file_temp.close()
'''
file_temp.write("++++++++++++++++ From output2 ++++++++++++++\n")
file_temp.write("Information of {} \n".format(target_binary2))
file_temp.write("--raw solver results:\n")
# for rr in raw_results1:
#    for r in rr:
#        file_temp.write(r + " ")
#    file_temp.write("\n")

file_temp.write("--path information:\n")
out2 = remove_dup(output2)
for out in out2:
    file_temp.write(out + " ")
    file_temp.write("\n")

file_temp.write("--recorded results (may be different from raw solver results):\n")
for tt in testcase2:
    for t in tt:
        file_temp.write(t + " ")
    file_temp.write("\n")

file_temp.write("*/\n")
file_temp.close()
# os.system("cat temp.txt")

print("############ Semantic Divergence Detection #################")
'''
# os.system("cat temp.txt")
# while len(sm.found) == 0:
#    sm.step()

# if (f1 == 0 and f2 >= 1) or (f1 >= 1 and f2 == 0):
if len(sm1.found) > 0:
    print("Found a difference HERE!")
    # native run
    num = int(random.random()*100000000)
    os.system("cp test.c wrong-candidate-{}.c".format(num))
    os.system("cat temp.txt >> wrong-candidate-{}.c".format(num))
    out = subprocess.run(['cat', 'temp.txt'], stdout=subprocess.PIPE).stdout.decode("utf-8")
    print("input is : ", out)
    # test_native_with_csmith_run()
    test_native_no_recompiliation()
else:
    print("No semantic divergence Found -:(\n")
    # os.system("rm b-mar*")
