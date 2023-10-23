# coding=gbk
import json
import os
import re
import subprocess
import time

import pandas as pd
from multiprocessing import Process, Queue


def write(q, needs):
    for value in needs:
        q.put(value)


def read(q):
    if q.qsize() > 0:
        value = q.get(True)
        return value
    else:
        return None


def run(base_Dir, vul_base_Dir):
    if not os.path.exists('./fault_fixing.txt'):
        f = open('./fault_fixing.txt', 'w')
        f.close()
    if not os.path.exists('./result_fixing.txt'):
        f = open('./result_fixing.txt', 'w')
        f.close()
    if not os.path.exists('./already_run_fixing.txt'):
        f = open('./already_run_fixing.txt', 'w')
        f.close()
    with open('./dependency_first.json', encoding='utf-8') as a:
        dependency = json.load(a)
    already = open('./already_run_fixing.txt', 'r').read().split('\n')
    needs = set()
    for lib in dependency.keys():
        if lib in already:
            continue
        needs.add(lib)
    q = Queue()
    write(q, needs)
    # for i in range(1):
    for i in range(30):
        p = Process(target=thread_get_exactly_patch_time_by_go_sum, args=(q, base_Dir, vul_base_Dir,))
        p.start()


with open('./safe_json.json', encoding='utf-8') as f:
    safe_range = json.load(f)
with open('./dependency_first.json', encoding='utf-8') as a:
    dependency = json.load(a)


def thread_get_exactly_patch_time_by_go_sum(q, base_Dir, vul_base_Dir):
    lib = read(q)
    while lib is not None:
        print(q.qsize())
        result = []
        lib_locate = lib
        lib_address = base_Dir + lib_locate
        if os.path.exists(base_Dir + lib) is False:
            temps = []
            for i in lib.split('/'):
                pattern = re.compile('/v[0-9]*')
                if pattern.search(i) is None:
                    temps.append(i)
            lib_locate = '/'.join(temps)
            lib_address = base_Dir + lib_locate
        if os.path.exists(lib_address) is False:
            f = open('./already_run_fixing.txt', 'a')
            f.write(lib + '\n')
            f.close()
            lib = read(q)
            continue
        lib_locate = '/'.join(lib_locate.split('/')[3:])
        if lib_locate != '':
            lib_locate = lib_locate + '/'
        if os.path.exists(lib_address + '/' + 'go.sum') is False or os.path.exists(
                lib_address + '/' + 'go.mod') is False:
            cmd = 'git log --all'
            try:
                p = subprocess.check_output(cmd, shell=True, cwd=lib_address)
            except:
                print('git show latest has fault', lib_address)
                f = open('./already_run_fixing.txt', 'a')
                f.write(lib + '\n')
                f.close()
                lib = read(q)
                continue
            re_str = re.compile(r'commit(.+?)\\n\\n')
            resp = re_str.findall(str(p))
            try:
                for i in resp:
                    re_str = re.compile(r'[\s\S]*\\nAuthor[\s\S]*\\nDate[\s\S]*')
                    sign = re_str.findall(str(i))
                    if len(sign) == 0:
                        continue
                    commit_date = pd.Timestamp(i.split('\\nDate:')[-1].strip()).tz_convert(tz='Asia/Shanghai')
                    break
            except Exception as e:
                print(cmd, resp, e)
                f = open('./already_run_fixing.txt', 'a')
                f.write(lib + '\n')
                f.close()
                lib = read(q)
            f = open('./fault_fixing.txt', 'a')
            f.write(
                lib + ' ' + lib_address + ' not exist go.sum or go.mod' + ';' + str(commit_date) + '\n')
            f.close()
            f = open('./already_run_fixing.txt', 'a')
            f.write(lib + '\n')
            f.close()
            lib = read(q)
            continue
        cmd = 'git log --all'
        try:
            p = subprocess.check_output(cmd, shell=True, cwd=lib_address)
        except:
            print('git show latest has fault', lib_address)
            f = open('./already_run_fixing.txt', 'a')
            f.write(lib + '\n')
            f.close()
            lib = read(q)
            continue

        cmd = 'git log --all go.sum'
        try:
            p = subprocess.check_output(cmd, shell=True, cwd=lib_address)
        except:
            print('git log go.sum command has fault', lib_address)
            f = open('./already_run_fixing.txt', 'a')
            f.write(lib + '\n')
            f.close()
            lib = read(q)
            continue
        re_str = re.compile(r'commit(.+?)\\n\\n')
        resp = re_str.findall(str(p))
        latest_commit_id = ''
        latest_commit_date = ''
        try:
            for i in resp:
                re_str = re.compile(r'[\s\S]*\\nAuthor[\s\S]*\\nDate[\s\S]*')
                sign = re_str.findall(str(i))
                if len(sign) == 0:
                    continue
                latest_commit_id = i.split('\\n')[0].strip()
                latest_commit_date = pd.Timestamp(i.split('\\nDate:')[-1].strip()).tz_convert(tz='Asia/Shanghai')
                break
        except Exception as e:
            print(cmd, resp, e)
            f = open('./already_run_fixing.txt', 'a')
            f.write(lib + '\n')
            f.close()
            lib = read(q)
        re_str = re.compile(r'commit(.+?)\\n\\n')
        resp = re_str.findall(str(p))
        git_log_list = []
        try:
            for i in resp:
                re_str = re.compile(r'[\s\S]*\\nAuthor[\s\S]*\\nDate[\s\S]*')
                sign = re_str.findall(str(i))
                if len(sign) == 0:
                    continue
                commit_id = i.split('\\n')[0].strip()
                commit_date = pd.Timestamp(i.split('\\nDate:')[-1].strip()).tz_convert(tz='Asia/Shanghai')
                git_log_list.append([commit_id, commit_date])
        except Exception as e:
            print(cmd, resp, e)
            f = open('./already_run_fixing.txt', 'a')
            f.write(lib + '\n')
            f.close()
            lib = read(q)
        bigVersion = None
        pattern_module = re.compile('/v(\d*)($|/)')
        if pattern_module.search(lib) is not None:
            bigVersion = pattern_module.findall(lib)[0][0]
        for vul in dependency[lib].keys():
            earliest_fix_commit = ''
            earliest_fix_commit_date = ''
            earliset_fix_version = ''
            current_commit = 0
            after_fix = 0
            after_commit = -1
            after_fix_version = []
            # after_fix: 0是初始状态，1表示通过除去漏洞依赖修复漏洞，2表示通过更新漏洞依赖修复漏洞
            for i in range(current_commit, len(git_log_list)):
                if bigVersion is not None:
                    cmd = 'git show ' + git_log_list[i][0] + ':' + lib_locate + 'go.mod'
                    try:
                        p = subprocess.check_output(cmd, shell=True, cwd=lib_address)
                    except:
                        current_commit = current_commit + 1
                        continue
                    curMod = ''
                    for mod in p.splitlines():
                        temp = re.findall(r'module (.*?)\'', str(mod))
                        if len(temp) > 0:
                            curMod = temp[0]
                            break
                    if pattern_module.search(curMod) is not None:
                        curBigVersion = pattern_module.findall(curMod)[0][0]
                        if int(curBigVersion) < int(bigVersion):
                            current_commit = current_commit + 1
                            continue
                    else:
                        current_commit = current_commit + 1
                        continue
                current_fix_version = []
                cmd = 'git show ' + git_log_list[i][0] + ':' + lib_locate + 'go.sum'
                try:
                    p = subprocess.check_output(cmd, shell=True, cwd=lib_address)
                except:
                    current_commit = current_commit + 1
                    continue
                current_version = set()
                vul_lib_module = dependency[lib][vul]['module']
                vul_lib_commits_module = dependency[lib][vul]['commits_module']
                vul_lib_address = vul_base_Dir + dependency[lib][vul]['path']
                pattern = re.compile(vul_lib_module + '/v[0-9]*')
                for line in p.splitlines():
                    temp = str(line)[1:].replace('\'', '')
                    if len(str(line).strip().split(' ')) >= 3:
                        if vul_lib_module == temp.split(' ')[-3] or pattern.search(temp) is not None:
                            if '/go.mod' not in temp:
                                version = temp.strip().split(' ')[-2]
                                current_version.add(version)
                if len(current_version) == 0:
                    after_commit = after_commit + 1
                    after_fix = 1
                    after_fix_version = []
                    continue
                fix = 0
                for version in current_version:
                    if len(version.split('-')) > 2 and re.search(
                            r"(\d{4}\d{2}\d{2}\d{2}\d{2}\d{2})",
                            version.split('-')[-2]) is not None:
                        cmd_version = version.split('-')[-1]
                    else:
                        cmd_version = version.replace('+incompatible', '')
                    cmd = 'git show -s --pretty=format:%H ' + cmd_version.replace('\'', '')
                    try:
                        p = subprocess.check_output(cmd, shell=True, cwd=vul_lib_address)
                    except:
                        print(vul_lib_module, vul_lib_commits_module, cmd_version, 'not tag')
                        f = open('./fault_fixing.txt', 'a')
                        f.write(
                            vul + ' ' + vul_lib_commits_module + ' ' + vul_lib_module + ' vul_lib not tag\n')
                        f.write(cmd + '\n')
                        f.close()
                        continue
                    try:
                        vul_commit_id = str(p.splitlines()[-1]).replace('\'', '')[1:]
                        if int(vul) in safe_range[vul_lib_commits_module]['safe_range'][str(vul_commit_id)]:
                            if fix == 2:
                                continue
                            fix = 1
                        else:
                            fix = 2
                            current_fix_version.append(version)
                            earliest_fix_commit = git_log_list[current_commit][0]
                            earliest_fix_commit_date = git_log_list[current_commit][1]
                            earliset_fix_version = version
                            continue
                    except:
                        print(cmd, p.splitlines())
                        continue
                # 结果中1是移除修复，2是更新修复，3是未修复
                if fix == 1 and (after_fix == 1 or after_fix == 2):
                    if len(after_fix_version) > 0:
                        result.append(lib + ';' + str(vul) + ';' + str(git_log_list[after_commit][0]) + ';' + str(
                            git_log_list[after_commit][1]) + ';' + ','.join(after_fix_version) + ';' + str(
                            latest_commit_id) + ';' + str(latest_commit_date) + ';' + str(2))
                    else:
                        result.append(lib + ';' + str(vul) + ';' + str(git_log_list[after_commit][0]) + ';' + str(
                            git_log_list[after_commit][1]) + ';' + str(latest_commit_id) + ';' + str(
                            latest_commit_date) + ';' + str(earliest_fix_commit) + ';' + str(
                            earliset_fix_version) + ';' + str(earliest_fix_commit_date) + ';' + str(1))
                    break
                else:
                    if after_fix == 0 and fix == 1:
                        result.append(lib + ';' + str(vul) + ';' + str(git_log_list[current_commit][0]) + ';' + str(
                            git_log_list[current_commit][1]) + ';' + str(latest_commit_id) + ';' + str(
                            latest_commit_date) + ';' + str(3))
                        break
                    after_commit = after_commit + 1
                    after_fix_version = current_fix_version
                    if len(after_fix_version) > 0:
                        after_fix = 2
                    else:
                        after_fix = 1
        k = open('./result_fixing.txt', 'a')
        for i in result:
            k.write(i + '\n')
        k.close()
        f = open('./already_run_fixing.txt', 'a')
        f.write(lib + '\n')
        f.close()
        lib = read(q)


if __name__ == '__main__':
    run('new_libs_location/', 'new_vul_repos/')
