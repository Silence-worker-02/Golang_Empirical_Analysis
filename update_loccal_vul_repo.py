# coding=gbk
import os
import subprocess
from multiprocessing import Queue, Process


def write(q, commit_list):
    for value in commit_list:
        q.put(value)


def read(q):
    if q.qsize() > 0:
        value = q.get(True)
        return value
    else:
        return None


def download_vul_libs_thread(q):
    lib = read(q)
    while lib is not None:
        paths = lib.split('/')
        origin = "./new_vul_repos/"
        if not os.path.exists(origin + paths[0]):
            os.mkdir(origin + paths[0])
        if not os.path.exists(origin + paths[0] + '/' + paths[1]):
            os.mkdir(origin + paths[0] + '/' + paths[1])
        if not os.path.exists(origin + paths[0] + '/' + paths[1] + '/' + paths[2]):
            try:
                cmd = "cd " + origin + paths[0] + '/' + paths[1] + f"&&git clone https://foo:bar@{lib}.git"
                print(cmd)
                subprocess.check_output(cmd, shell=True)
            except:
                k = open('./download_vul_fault.txt', 'a')
                k.write(lib + '\n')
                k.close()
                lib = read(q)
                continue
        k = open('./already_download_vul.txt', 'a')
        k.write(lib + '\n')
        k.close()
        lib = read(q)


def download_vul_libs():
    if not os.path.exists('./already_download_vul.txt'):
        f = open('./already_download_vul.txt', 'w')
        f.close()
    if not os.path.exists('./new_vul_repos'):
        os.mkdir('./new_vul_repos')
    if not os.path.exists('./download_vul_fault.txt'):
        f = open('./download_vul_fault.txt', 'w')
        f.close()
    f = open('lib_name_address.txt', 'r')
    lib_list = []
    for i in f.read().split('\n'):
        lib = i.split(' ')[-1].replace('./vul_repos/', '')
        lib_list.append(lib)
        print(lib)
    f.close()
    q = Queue()
    write(q, lib_list)
    for i in range(1):
        p = Process(target=download_vul_libs_thread, args=(q,))
        p.start()


def complete_update_vul_libs_thread(q):
    lib = read(q)
    n = 0
    while lib is not None:
        try:
            cmd = "git fetch --all && git reset --hard HEAD^ && git pull"
            subprocess.check_output(cmd, shell=True, cwd=lib)
        except:
            n = n + 1
            if n == 5:
                k = open('./fault_update_vul.txt', 'a')
                k.write(lib + '\n')
                k.close()
                n = 0
                lib = read(q)
            continue
        k = open('./already_update_vul.txt', 'a')
        k.write(lib + '\n')
        k.close()
        lib = read(q)
        n = 0


def complete_update_vul_libs(origin):
    lib_list = []
    f = open('./already_update_vul.txt', 'r')
    already = f.read().split('\n')
    f.close()
    for i in os.listdir(origin):
        for j in os.listdir(origin + '/' + i):
            for k in os.listdir(origin + '/' + i + '/' + j):
                if origin + '/' + i + '/' + j + '/' + k in already:
                    continue
                lib_list.append(origin + '/' + i + '/' + j + '/' + k)
                print(origin + '/' + i + '/' + j + '/' + k)
    q = Queue()
    write(q, lib_list)
    for i in range(5):
        p = Process(target=complete_update_vul_libs_thread, args=(q,))
        p.start()


if __name__ == '__main__':
    if not os.path.exists('./already_update_vul.txt'):
        f = open('./already_update_vul.txt','w')
        f.close()
    if not os.path.exists('./fault_update_vul.txt'):
        f = open('./fault_update_vul.txt', 'w')
        f.close()
    download_vul_libs()