# -*- coding: utf-8 -*-

import pydot
import networkx as nx
import angr
# from angrutils import plot_cfg, hook0, set_plot_style
# import bingraphvis
import os
import re
import sys
import subprocess
from natsort import natsorted
import random

def analyze(b, addr, name=None):
    start_state = b.factory.blank_state(addr=addr)
    start_state.stack_push(0x0)
    with hook0(b):
        cfg = b.analyses.CFGEmulated(fail_fast=True, starts=[addr], initial_state=start_state, context_sensitivity_level=2, keep_state=True, call_depth=100, normalize=True)
        #cfg = b.analyses.CFGFast()
    for addr,func in proj.kb.functions.items():
        if func.name in ['main','verify']:
            plot_cfg(cfg, "%s_%s_cfg" % (name, func.name), asminst=True, vexinst=False, func_addr={addr:True}, debug_info=False, remove_imports=True, remove_path_terminator=True)
            plot_cfg(cfg, "%s_%s_cfg" % (name, func.name), asminst=True, vexinst=False, func_addr={addr:True}, debug_info=False, remove_imports=True, remove_path_terminator=True, format="dot")

    # plot_cfg(cfg, "%s_cfg_full" % (name), asminst=True, vexinst=True, debug_info=True, remove_imports=False, remove_path_terminator=False)

    # plot_cfg(cfg, "%s_cfg_classic" % (name), asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True)
    # plot_cfg(cfg, "%s_cfg_classic" % (name), asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True, format="raw")
    plot_cfg(cfg, "%s_cfg_classic" % (name), asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True, format="dot")

    # for style in ['thick', 'dark', 'light', 'black', 'kyle']:
    #    set_plot_style(style)
    #    plot_cfg(cfg, "%s_cfg_%s" % (name, style), asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True)

# os.system("gcc-trunk -w -O3 csmith-test.c -o test1")

# proj = angr.Project("./test1", load_options={'auto_load_libs':False})
# main = proj.loader.main_object.get_symbol("main")
# analyze(proj, main.rebased_addr, "csmith-test")


def getFunAddDict(binary):
    markersAddrFunc = {}
    # print("b = ", b)
    os.system("objdump -S {} > {}.S".format(binary, binary))
    os.system("grep \">$\" {}.S | grep \"<marker_\" > markers-temp-{}.txt".format(binary, binary))
    outFun = subprocess.check_output("cat markers-temp-%s.txt | awk '{print $NF}'" % binary, shell=True)
    # print(outFun.decode())
    outAdd = subprocess.check_output("cat markers-temp-%s.txt | awk '{print $8}'" % binary, shell=True)
    # print(outAdd.decode())
    m = re.findall(r'\d+', outFun.decode())
    n = re.findall(r'[0-9a-zA-Z]+', outAdd.decode())
    # print("m : ", len(m), m)
    # print("n : ", len(n), n)
    # i = 0
    # for key1 in m:
    #    markersFuncAddr[key1] = n[i]
    #    i += 1

    j = 0
    for key2 in n:
        markersAddrFunc[key2] = m[j]
        j += 1
    # print(markersFuncAddr)
    # print(markersAddrFunc)
    # testing markers
    # for j in range(len(m)):
    #    os.system("sed -i \'s/call 0x{}/{}/g\' ./test1-markers.dot".format(n[j], m[j]))
    return markersAddrFunc


def getCfgDot(binary_file):
    os.system("rm func_*")
    # find the function name, may not be func_1 directly

    # no need to know the name for now as all functions are inlined
    # funcname = subprocess.check_output("objdump -S %s | awk '{print $2}' | grep func_1" % binary_file, shell=True)
    # funcname = funcname[1:-3]
    # print("funcname : ", funcname.decode())
    # os.system("bcov -m dump -f \"{}\" -i {}".format(funcname.decode(), binary_file))
    try:
        subprocess.check_output("timeout -k 3s 2m bcov -m dump -f \"main\" -i %s" % binary_file, shell=True)
    except Exception as e:
        return ""
    # remove some noise assemble code
    os.system("rm func_*rev* func_*dom*")
    os.system("cp func_*.dot {}.dot".format(binary_file))


def getCfgNodeNum(dot_file):
    graphs = pydot.graph_from_dot_file(dot_file)
    graph = graphs[0]
    # convert to nx
    g = nx.drawing.nx_pydot.from_pydot(graph)
    return g.number_of_nodes()


def getAllPaths(dot_file, binary):

    if dot_file == "":
        return

    graphs = pydot.graph_from_dot_file(dot_file)
    # graphs = pydot.graph_from_dot_file("./main.dot")
    # graphs = pydot.graph_from_dot_file("./test-csmith.dot")

    graph = graphs[0]

    # write to png
    # graph.write_png("{}.png".format(dot_file))

    # convert to nx
    g = nx.drawing.nx_pydot.from_pydot(graph)
    print("number of nodes : ", g.number_of_nodes())
    print("number of edges : ", g.number_of_edges())

    # not interesting graph
    if (g.number_of_edges() < 1) or (g.number_of_nodes() < 1):
        print("Not an interesting binary, just skip it ...")
        return

    # g.draw("networkx-test.png")
    i = 1
    start_node = ""
    end_node = ""
    markers = list()
    markers_dict = {}
    markersAddrFunc = getFunAddDict(binary)
    # print("markersAddrFunc : ", markersAddrFunc)
    for node in g.nodes():
        # print(node)
        if node != "" and len(g.nodes()[node]) == 4:
            # print(g.nodes()[node]['label'])
            # print(len(g.nodes()[node]))
            # print(g.nodes()[node])
            # find the marker_start
            str1 = g.nodes()[node]["label"]
            # if (str1.find("start") != -1):
            '''
            if i == 1:
                start_node = node
                # print("found the start node ! It is ", node)
            if i == g.number_of_nodes() - 1:
                end_node = node
                # print("found the end node ! It is ", node)
            '''
            if (str1.find("call") != -1):
                markers.append(node)
                # str1 = str1.replace('\\', '')
                # print("new str1 ", str1)
                # print("match : ", re.findall(r"marker_(.+?)\\", str1))
                temp_nodes = re.findall(r"call (.+?)\\", str1)  # TODO can not match \n for now
                # filter '\\\\n'
                new_temp_nodes = list()
                for temp in temp_nodes:
                    new_temp = temp.replace("\\\n", "")
                    new_temp_nodes.append(new_temp[2:])
                # print("temp_nodes: ", temp_nodes)
                # print("new_temp_nodes: ", new_temp_nodes)
                # print("new_temp_node[0]: ", new_temp_nodes[0])
                if (new_temp_nodes[0] in markersAddrFunc):
                    # print("replacing ++++ ", markersAddrFunc[new_temp_nodes[0]])
                    markers_dict[node] = markersAddrFunc[new_temp_nodes[0]]
                    # set start and node
                    if markersAddrFunc[new_temp_nodes[0]] == "10000":
                        start_node = node
                    if markersAddrFunc[new_temp_nodes[0]] == "19999":
                        end_node = node
                else:
                    markers_dict[node] = -1
                # print("found the marker node ! It is ", node)
        i = i + 1
    # print("markers_dict : ", markers_dict)
    # TODO write the infor to a temp file and used for filter markers before symbolic execution

    # no need to know exact paths in CFG, only count the nodes in the CFG and find the difference
    nodes_in_cfg = list()
    for key, value in markers_dict.items():
        if value != -1:
            nodes_in_cfg.append(value)
    '''
    # find all simple path
    print("### explore paths")
    print("start_node = ", start_node)
    print("end_node = ", end_node)
    if start_node == "" or end_node == "":
        return
    ng = nx.drawing.nx_pydot.from_pydot(graph)
    paths = nx.all_simple_paths(ng, source=start_node, target=end_node, cutoff=150)
    print("Number of total paths : ", len(list(paths)))
    if (len(list(paths))) > 10000:  # TODO skip big number of path
        return
    # print("Nodes only hold markers : ", markers)

    # dict
    # print("markers_dict : ")
    # print(markers_dict)

    # markersAddrFunc = getFunAddDict(binary)
    # print("markersAddrFunc: ")
    # print(markersAddrFunc)

    # print("markers ")
    # print(markers)
    # print all simple path in the graph
    # step 1: remove nodes that have no markers
    pn = 1
    seq_list = list()
    for path in nx.all_simple_paths(ng, source=start_node, target=end_node, cutoff=150):
        # print("No.", pn, ":", path)
        lp = list()
        for p in path:
            # print("p : ", p)
            if p in markers:
                lp.append(markers_dict[p])  # add value from dict
        seq_list.append(lp)
        pn = pn + 1
        # break

    # print("seq_list(have dups) len = ", len(seq_list))
    # print(seq_list)

    # remove duplicate lists
    seq_list_unique = list()
    for sublist in seq_list:
        # print("P: ", sublist)
        if sublist not in seq_list_unique:
            seq_list_unique.append(sublist)
    # print("## path in seq_list_unique")
    # print("number of marker seq : ", len(seq_list_unique))

    seq_list_unique_new = list()
    for ss in seq_list_unique:
        # if (s[0] == 'marker_1'):
        # print(ss)
        temp = list()
        for s in ss:
            # for st in s:
            temp.append(s)
        if temp not in seq_list_unique_new:
            seq_list_unique_new.append(temp)

    # print seq_list_unique_new
    # for ss in seq_list_unique_new:
    #    print(ss)
    # remove -1 markers
    for seq in seq_list_unique_new:
        # seq.remove(-1)try:
        try:
            while True:
                seq.remove(-1)
        except ValueError:
            pass
        # print("P: ", seq)
    print("Number of unique paths : ", len(seq_list_unique_new))
    for s in seq_list_unique_new:
        pass  # print("Path: ", s)
    return seq_list_unique_new
    '''
    # print("nodes_in_cfg : ", nodes_in_cfg)
    return nodes_in_cfg


def checkDiff(list1, list2):
    set1 = set()
    set2 = set()
    for li in list1:
        for l1 in li:
            set1.add(l1)
    for li in list2:
        for l2 in li:
            set2.add(l2)

    n1 = set1
    n2 = set2
    if n1.issubset(n2) is not True or n2.issubset(n1) is not True and len(n1) > 1 and len(n2) > 1:
        print("Find a diff of paths")
        dd1 = n1 - n2
        dd2 = n2 - n1
        diff = set()
        ret = set()
        for d1 in dd1:
            diff.add(d1)
        for d2 in dd2:
            diff.add(d2)
        print("differ : ", diff)
        # check whether they are indeed not existed in .asm
        for d in diff:
            print("Further checking ", d)
            os.system("grep {} test1.asm > /dev/null; echo $? > out1.txt".format(d))
            os.system("grep {} test2.asm > /dev/null; echo $? > out2.txt".format(d))
            grep1 = subprocess.run(['cat', 'out1.txt'], stdout=subprocess.PIPE).stdout.decode("utf-8")
            grep2 = subprocess.run(['cat', 'out2.txt'], stdout=subprocess.PIPE).stdout.decode("utf-8")
            if grep1 != grep2:
                ret.add(d)
            else:
                print("May be interesting; skip for now")
    else:
        print("Nothing interesting :-(\n")
        return ret


def getBinaries(max_funcs, max_expr_complexity, csmith_options, max_sym_var, cmd_list):
    # genertate a test program
    os.system("csmith-marker --max-funcs {} --max-expr-complexity {} {} \
            > test.c".format(max_funcs, max_expr_complexity, csmith_options))
    # Filter useless symbolic variables
    os.system("grep strto test.c | awk \'{print $1}\' > names.txt")
    os.system("grep if test.c > if-stmts.txt")
    # os.system("python3 filter.py")
    os.system("grep strto test.c | awk \'{print $1}\' > names.txt")

    # only keep interesting but not too much symbolic variables as targets
    os.system("grep strtol test.c | wc -l > sym_count.txt")
    sym_var_count = subprocess.run(['cat', 'sym_count.txt'], stdout=subprocess.PIPE).stdout.decode("utf-8")
    print("number of symbolic variables : ", sym_var_count)
    while int(sym_var_count) > max_sym_var or int(sym_var_count) == 0:
        print("Not an interesting test program, Re-gerating it for now ...")
        os.system("csmith-marker --max-funcs {} --max-expr-complexity {} {} \
                > test.c".format(max_funcs, max_expr_complexity, csmith_options))
        # Filter useless symbolic variables
        os.system("grep strto test.c | awk \'{print $1}\' > names.txt")
        os.system("grep if test.c > if-stmts.txt")
        os.system("grep strtol test.c | wc -l > sym_count.txt")
        # os.system("python3 filter.py")
        os.system("grep strto test.c | awk \'{print $1}\' > names.txt")
        sym_var_count = subprocess.run(['cat', 'sym_count.txt'], stdout=subprocess.PIPE).stdout.decode("utf-8")
        print("number of symbolic variables in while loop: ", sym_var_count)
    # generate binaries
    index = 1
    binaries = list()
    for cmd in cmd_list:
        os.system(cmd + " test.c -o test{}".format(index))
        binaries.append("test{}".format(index))
        index += 1
    return binaries


# interesting means markers are union(all path) - intersect(all path)
def storeAllPaths(binary):
    all_path_dict = {}
    for b in binary:
        getCfgDot(b)
        # print("file exist? ", os.path.isfile(b))
        if os.path.isfile("{}.dot".format(b)) is True:  # .dot is generated
            paths = getAllPaths("{}.dot".format(b), b)
            all_path_dict[b] = paths
        else:
            break
    return all_path_dict


# interesting means markers are union(all path) - intersect(all path)
def getInterestingMarkerSetV1(d):
    markers = set()
    new_dict = {}
    binary = []
    for key, value in d.items():
        # print("key : ", key)
        # print("value : ", value)
        binary.append(key)
        # transfer list to set first
        m = set()
        if value is None:
            return None
        for ss in value:
            m.add(ss)
        new_dict[key] = m
    # print("new_dict : ", new_dict)
    b_len = len(new_dict)
    if b_len < 2:
        return
    # print("b_len : ", b_len)
    marker_intersect = list()
    for i in range(b_len):
        # print(markers_all[binary[i]])
        # print(markers_all[binary[i+1]])
        marker_intersect = new_dict[binary[i]] & new_dict[binary[i+1]]
        if i+1 == b_len - 1:
            break
    # get interesting markers
    for i in range(b_len):
        markers.update(new_dict[binary[i]] - marker_intersect)
    return markers


def remove_common(a, b):
    for i in a[:]:
        if i in b:
            a.remove(i)
            b.remove(i)
    return a, b


def check_markers_in_cfg(b1, b2, marker):
    os.system("objdump -S {} > {}.S".format(b1, b1))
    os.system("grep \">$\" {}.S | grep \"<marker_{}\" > markers-{}.txt".format(b1, marker, b1))
    os.system("objdump -S {} > {}.S".format(b2, b2))
    os.system("grep \">$\" {}.S | grep \"<marker_{}\" > markers-{}.txt".format(b2, marker, b2))
    grep1 = subprocess.run(['cat', 'markers-test1.txt'], stdout=subprocess.PIPE).stdout.decode("utf-8")
    grep2 = subprocess.run(['cat', 'markers-test2.txt'], stdout=subprocess.PIPE).stdout.decode("utf-8")
    os.system("cat markers-test1.txt")
    os.system("cat markers-test2.txt")
    if grep1 == grep2:
        return True
    else:
        return False


# interesting means markers are set per path
def getInterestingMarkerSetV2(d):
    markers = set()
    new_dict = {}
    # first remove the same path in d
    if d["test1"] is None or d['test2'] is None:
        return None

    print("test ---------------")
    print(type(d['test1']))
    a, b = remove_common(d['test1'], d['test2'])
    print("a : ", a)
    print("b : ", b)
    new_dict = {}
    new_dict["test1"] = a
    new_dict["test2"] = b
    len_test1 = len(new_dict['test1'])
    len_test2 = len(new_dict['test2'])
    print("len_test1 : ", len_test1)
    print("len_test2 : ", len_test2)
    if len_test1 == 0 and len_test2 == 0:   # no interesting paths
        return None
    if len_test1 != 0 and len_test2 != 0:
        print("test ---------------")
        # path to path comparison
        for t1 in new_dict["test1"]:
            for t2 in new_dict["test2"]:
                list_temp = set(t1).union(set(t2)) - set(t1).intersection(set(t2))
                for m in list_temp:
                    markers.add(m)
    else:
        if len_test1 == 0:  # test1 is empty
            print("test1 is empty; to be added")  # TODO return none for now
            return None
        else:  # test2 is empty
            print("test2 is empty")  # TODO return none for now
            return None
    return markers


# interesting means markers in a cycle
def getInterestingMarkerSetV3(d):
    markers = set()
    path_set1 = set()
    path_set2 = set()
    paths1 = d["test1"]
    paths2 = d['test2']
    if paths1 is not None:
        for path1 in paths1:
            for p1 in path1:
                path_set1.add(p1)
    if paths2 is not None:
        for path2 in paths2:
            for p2 in path2:
                path_set2.add(p2)
    interesting_marker1 = path_set1.union(path_set2) - path_set1
    interesting_marker2 = path_set1.union(path_set2) - path_set2
    markers = interesting_marker1 | interesting_marker2  # add two sets to be one
    return markers


# dead code version
def getInterestingMarkerSetV4(d):
    markers = dict()
    path_set1 = set()
    path_set2 = set()
    paths1 = d["test1"]
    paths2 = d['test2']
    if paths1 is not None:
        for path1 in paths1:
            # for p1 in path1:
            path_set1.add(path1)
    if paths2 is not None:
        for path2 in paths2:
            # for p2 in path2:
            path_set2.add(path2)
    intersect = path_set1.intersection(path_set2)
    print("intersect : ", intersect)
    interesting_marker1 = path_set1 - intersect
    interesting_marker2 = path_set2 - intersect
    markers["test1"] = interesting_marker1
    markers["test2"] = interesting_marker2
    return markers


def filter_intersection(orig_intersect, dot_file, binary):
    # basic idea: get the original marker list, and cut the markers in the same path
    # step 1: preparing the checking, i.e., dictionary that records the mapping between node and markers
    if dot_file == "":
        return

    graphs = pydot.graph_from_dot_file(dot_file)

    graph = graphs[0]

    # convert to nx
    g = nx.drawing.nx_pydot.from_pydot(graph)
    i = 1
    start_node = ""
    end_node = ""
    markers = list()
    markers_dict = {}
    markersAddrFunc = getFunAddDict(binary)
    # print("markersAddrFunc : ", markersAddrFunc)
    for node in g.nodes():
        # print(node)
        if node != "" and len(g.nodes()[node]) == 4:
            str1 = g.nodes()[node]["label"]
            # if (str1.find("start") != -1):
            if (str1.find("call") != -1):
                markers.append(node)
                temp_nodes = re.findall(r"call (.+?)\\", str1)  # TODO can not match \n for now
                new_temp_nodes = list()
                for temp in temp_nodes:
                    new_temp = temp.replace("\\\n", "")
                    new_temp_nodes.append(new_temp[2:])
                if (new_temp_nodes[0] in markersAddrFunc):
                    # print("replacing ++++ ", markersAddrFunc[new_temp_nodes[0]])
                    markers_dict[node] = markersAddrFunc[new_temp_nodes[0]]
                    # set start and node
                    if markersAddrFunc[new_temp_nodes[0]] == "10000":
                        start_node = node
                    if markersAddrFunc[new_temp_nodes[0]] == "19999":
                        end_node = node
                else:
                    markers_dict[node] = -1
        i = i + 1
    # print the markers_dict
    # print("markers_dict : ", markers_dict)
    # no need to know exact paths in CFG, only count the nodes in the CFG and find the difference
    nodes_in_cfg = list()
    for key, value in markers_dict.items():
        if value != -1:
            nodes_in_cfg.append(value)
    # print("test filter_intersection : ", nodes_in_cfg)

    # check and whether every node is in the CFG
    orig_intersect_new = list()
    for m in orig_intersect:
        if m in nodes_in_cfg:
            orig_intersect_new.append(m)

    if len(orig_intersect_new) == 0:
        print("Do not exist in this CFG ...")
        return None

    # directly return if there is only one node in the intersection
    if len(orig_intersect_new) < 2:
        return orig_intersect_new
    # check whether some of the nodes are in the same path
    # order first
    ordered_ori_list = natsorted(orig_intersect_new)
    print("ordered_ori_list : ", ordered_ori_list)
    # every time check two nodes TODO better solution?
    final_list = list()
    pindex = 0
    sources_temp = list()
    '''
    for key, value in markers_dict.items():
        if value == ordered_ori_list[0]:
            sources_temp.append(key)
            print("value 1: ", value)
        if value == ordered_ori_list[1]:
            sources_temp.append(key)
            print("value 2: ", value)
    '''
    nindex = 0
    while (pindex + 1) < len(orig_intersect):
        # print("while?")
        # find the node in the dictory
        if len(sources_temp) < 2:
            # print("< 2 : nindex", nindex)
            # print("< 2 : pindex", pindex)
            for key, value in markers_dict.items():
                if nindex + 1 + pindex >= len(ordered_ori_list):
                    return final_list
                if value == ordered_ori_list[nindex + pindex]:
                    sources_temp.append(key)
                    # print("value 1: ", value)
                if value == ordered_ori_list[nindex + 1 + pindex]:
                    sources_temp.append(key)
                    # print("value 2: ", value)
            nindex += 2
        else:
            # last two elements
            # print("> 2 : nindex", nindex)
            # print("> 2 : pindex", pindex)
            for key, value in markers_dict.items():
                if nindex + 1 + pindex >= len(ordered_ori_list):
                    return final_list
                if value == ordered_ori_list[nindex + pindex]:
                    sources_temp.append(key)
                    # print("value ?: ", value)
            # pindex += 1
        if nx.is_simple_path(g, sources_temp) is True and nindex < len(ordered_ori_list):
            print("in the same path")
            # check whether pindex is pointing to the last two elements
            if pindex == len(ordered_ori_list) - 2:
                if markers_dict[sources_temp[0]] not in final_list:
                    final_list.append(markers_dict[sources_temp[0]])
                pindex += 1
        else:
            print("not in the same path")
            if markers_dict[sources_temp[0]] not in final_list:
                final_list.append(markers_dict[sources_temp[0]])
            pindex += len(sources_temp) - 1
            # same_path_count += 1
            sources_temp.clear()  # clear the list
            nindex = 0
        # pindex += len(sources_temp)
        # print("final_list : ", final_list)
        # if (index + 1) != len(ordered_ori_list):
        #    index += 1
    return final_list


def testMain(binary):
    # get all markers
    markers = set()
    d = storeAllPaths(binary)
    print("all paths: ", d)
    if len(d) != 2:
        return
    markers = getInterestingMarkerSetV4(d)
    print("marker interesting : ", markers)
    # print("marker1 interesting : ", markers["test1"])
    # print("marker2 interesting : ", markers["test2"])
    # check markers first, if it is empty, just return
    if len(markers["test1"]) == 0 and len(markers["test2"]) == 0:
        print("No interesting markers ...")
        return
    for b in binary:
        print("Dealing with ", b)
        print("Geting the cfg dot files from ", b)
        getCfgDot(b)

        # print("file exist? ", os.path.isfile(b))
        if os.path.isfile("{}.dot".format(b)) is False:  # .dot is not generated
            continue
        # get paths of all the binaries
        print("Geting the paths over cfgs ...")
        # paths = d[b]  # getAllPaths("{}.dot".format(b), b)
        # print(paths)
        if len(markers[b]) == 0:
            continue
        reduced_markers = filter_intersection(markers[b], "{}.dot".format(b), b)
        if reduced_markers is None:
            print("Do not exist in this CFG ...")
            continue
        if len(markers) != len(reduced_markers):
            print("orig_intersect : ", markers)
            print("reduced_intersect : ", reduced_markers)
        for inter in reduced_markers:
            # if check_markers_in_cfg("test1", "test2", inter) is False:
            #     print("do not explore : ", inter)
            #     continue
            # else:
            print("do explore : ", inter)
            print("This is an interesting path, starting to conducting binary symbolic execution")
            # pass the sequences to SE conduct SE
            # print("*** finding the direct path via binary symbolic execution : ", path)
            os.system("timeout -k 3s 2m python3 se-confirm-v3.py %s %s" % (b, inter))
            # exit(1)


if __name__ == "__main__":
    print("### Test main ###")
    os.system("rm test*")
    # get cmd from ./compiler_test.in
    cmd_list = []
    with open("./compiler_test.in") as file_in:
        for line in file_in:
            cmd_list.append(line.rstrip('\n'))
    print("cmd_list : ", cmd_list)
    # print(name_list)
    for i in range(100000000):
        print("Geting binaries ... ", i)
        binaries = getBinaries(10, 8, "", 200, cmd_list)
        # binaries = getBinaries(1, 6, "", 50, cmd6, cmd7, cmd8, cmd9, cmd10)
        # binaries = getBinaries(1, 6, "", 50, cmd1, cmd2, cmd3, cmd4, cmd5)
        # binaries = ["test1", "test2"]
        print("Analyzing binaries ...")
        testMain(binaries)
        # d = storeAllPaths(binaries)
        # markers = getInterestingMarkerSet(d)
        # print("unique markers : ", markers)
        # print("all path dict : ", d)
        # os.system("./bcov-test.sh")
        # getCfgDot("test1")
        # markersAddrFunc = getFunAddDict("test1")
        # getAllPaths("test2.dot", "test2")
        # os.system("python networkx-test.py")
        os.system("rm test*")

    # os.system("rm *")
