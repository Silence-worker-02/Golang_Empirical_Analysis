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


def download_libs(q):
    lib = read(q)
    while lib is not None:
        paths = lib.split('/')
        origin = "./new_libs_location/"
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


if __name__ == '__main__':
    if not os.path.exists('./already_download_vul.txt'):
        f = open('./already_download_vul.txt', 'w')
        f.close()
    if not os.path.exists('./new_libs_location'):
        os.mkdir('./new_libs_location')
    if not os.path.exists('./download_vul_fault.txt'):
        f = open('./download_vul_fault.txt', 'w')
        f.close()
    f = open('./need_download_libs_vul.txt', 'r')
    lib_list = f.read().split('\n')
    f.close()
    q = Queue()
    write(q, lib_list)
    for i in range(10):
        p = Process(target=download_libs, args=(q,))
        p.start()