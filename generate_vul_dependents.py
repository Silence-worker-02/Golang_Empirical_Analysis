# coding=gbk
import glob
import json
import os
import re
import subprocess
import sys
from pymongo import MongoClient


def connect_mongodb():
    client = MongoClient('mongodb://localhost:27017/')
    mongodb = client['Golang_Vulnerabilities']
    return mongodb


def check_empty_go_mod(go_mod_file):
    with open(go_mod_file, 'r', encoding='utf-8') as file:
        content = file.read()
    # 使用正则表达式匹配require或replace段是否为空
    pattern = r"require\s+([\w./@-]+)\s+v?([\w.-]+)"
    matches = re.findall(pattern, content)

    # 判断匹配结果是否为空
    if not matches:
        return True  # go.mod文件中没有引用其他依赖
    else:
        return False  # go.mod文件中引用了其他依赖


def search_modules_name(origin_path):
    result = dict()
    # 获取所有的 go.mod 文件路径
    go_mod_files = glob.glob(os.path.join(origin_path, '**/go.mod'), recursive=True)
    # 遍历每个 go.mod 文件并解析 module 名称
    for go_mod_file in go_mod_files:
        module_path = go_mod_file.replace('\\', '/').replace('/go.mod', '')
        # with open(go_mod_file, 'r') as file:
        #     for line in file:
        #         if line.startswith('module'):
        #             module_name = line.strip().split(' ')[1].replace('\"', '')
        #             result[module_name] = module_path
        #             break
        if os.path.exists(module_path + '/go.sum'):
            with open(go_mod_file, 'r', encoding='utf-8') as file:
                for line in file:
                    if line.startswith('module'):
                        module_name = line.strip().split(' ')[1]
                        result[module_name] = module_path
                        break
        else:
            if check_empty_go_mod(go_mod_file):
                with open(go_mod_file, 'r', encoding='utf-8') as file:
                    for line in file:
                        if line.startswith('module'):
                            module_name = line.strip().split(' ')[1]
                            result[module_name] = module_path
                            break
    return result


def check_empty_go_mod(go_mod_file):
    with open(go_mod_file, 'r', encoding='utf-8') as file:
        content = file.read()
    # 使用正则表达式匹配require或replace段是否为空
    pattern = r"require\s+([\w./@-]+)\s+v?([\w.-]+)"
    matches = re.findall(pattern, content)

    # 判断匹配结果是否为空
    if not matches:
        return True  # go.mod文件中没有引用其他依赖
    else:
        return False  # go.mod文件中引用了其他依赖


def search_modules_name(origin_path):
    result = dict()
    # 获取所有的 go.mod 文件路径
    go_mod_files = glob.glob(os.path.join(origin_path, '**/go.mod'), recursive=True)
    # 遍历每个 go.mod 文件并解析 module 名称
    for go_mod_file in go_mod_files:
        module_path = go_mod_file.replace('\\', '/').replace('/go.mod', '')
        # with open(go_mod_file, 'r') as file:
        #     for line in file:
        #         if line.startswith('module'):
        #             module_name = line.strip().split(' ')[1].replace('\"', '')
        #             result[module_name] = module_path
        #             break
        if os.path.exists(module_path + '/go.sum'):
            with open(go_mod_file, 'r', encoding='utf-8') as file:
                for line in file:
                    if line.startswith('module'):
                        module_name = line.strip().split(' ')[1]
                        result[module_name] = module_path
                        break
        else:
            if check_empty_go_mod(go_mod_file):
                with open(go_mod_file, 'r', encoding='utf-8') as file:
                    for line in file:
                        if line.startswith('module'):
                            module_name = line.strip().split(' ')[1]
                            result[module_name] = module_path
                            break
    return result


def remove_pattern_one(string):
    pattern = r"/v\d+/"
    return re.sub(pattern, "/", string)


def remove_pattern_two(string):
    pattern = r"/v\d+$"
    return re.sub(pattern, "", string)


def generate_origin_depts():
    db = connect_mongodb()
    repo_table = db['repo_info']
    dependencies_table = db['dependencies']
    vul_table = db['vulnerabilities_info']
    result = dict()
    for repo in repo_table.find():
        result[repo['repo']] = {}
        vul_packages = set()
        modules = search_modules_name('./new_vul_repos/' + repo['repo'])
        if len(modules.keys()) == 0:
            continue
        for vul in vul_table.find({'_id': {'$in': repo['vuls']}}):
            for package in vul['vul_packages']:
                for package_path in package.keys():
                    vul_packages.add(package_path)
        for package_path in vul_packages:
            sign = 0
            for module in modules.keys():
                if modules[module].replace('./new_vul_repos/', '') in package_path or module in package_path:
                    sign = 1
                    if modules[module].replace('./new_vul_repos/', '') in package_path:
                        result[repo['repo']][package_path] = {}
                        result[repo['repo']][package_path]['location'] = package_path
                    else:
                        result[repo['repo']][package_path] = {}
                        result[repo['repo']][package_path]['location'] = modules[module].replace('./new_vul_repos/',
                                                                                                 '') + package_path.replace(
                            module.replace('./new_vul_repos/', ''), '')
                    break
            if os.path.exists('./new_vul_repos/' + package_path) and sign == 0:
                sign = 1
                result[repo['repo']][package_path] = {}
                result[repo['repo']][package_path]['location'] = package_path
            if os.path.exists('./new_vul_repos/' + remove_pattern_one(package_path)) and sign == 0:
                sign = 1
                result[repo['repo']][package_path] = {}
                result[repo['repo']][package_path]['location'] = remove_pattern_one(package_path)
            if os.path.exists('./new_vul_repos/' + remove_pattern_two(package_path)) and sign == 0:
                sign = 1
                result[repo['repo']][package_path] = {}
                result[repo['repo']][package_path]['location'] = remove_pattern_two(package_path)
    f = open('./module_path.json', 'w')
    json.dump(result, f)
    f.close()


def search_sub_module():
    with open('./module_path.json', encoding='utf-8') as a:
        module_path = json.load(a)
    for repo in module_path.keys():
        for package_path in module_path[repo].keys():
            address = './new_vul_repos/' + module_path[repo][package_path]['location']
            temps = address.split('/')
            sub_module = ''
            go_mod = ''
            for i in range(len(temps)):
                if os.path.exists('/'.join(temps[:len(temps) - i]) + '/go.mod'):
                    go_mod = '/'.join(temps[:len(temps) - i]) + '/go.mod'
                    f = open(go_mod, 'r')
                    temp = f.read().split('\n')
                    f.close()
                    for i in temp:
                        if '//' not in i and 'module' in i:
                            sub_module = i.split(' ')[-1]
                            break
                    break
            if go_mod != '':
                module_path[repo][package_path]['sub_module'] = sub_module
                pattern = re.compile('(.*)/v[0-9]')
                if pattern.search(sub_module) is not None:
                    search_module = '/'.join(sub_module.split('/')[:-1])
                    module_path[repo][package_path]['search_module'] = search_module
                else:
                    module_path[repo][package_path]['search_module'] = sub_module.replace('\"', '').replace('\'', '')
    f = open('./module_path_first.json', 'w')
    json.dump(module_path, f)
    f.close()


def manu_add_sub_module():
    with open('./module_path_first.json', encoding='utf-8') as a:
        module_path = json.load(a)
    module_path['github.com/go-yaml/yaml']['gopkg.in/yaml.v2'] = {'vul_module': 'gopkg.in/yaml.v2'}
    module_path['github.com/go-yaml/yaml']['gopkg.in/yaml.v3'] = {'vul_module': 'gopkg.in/yaml.v3'}
    module_path['github.com/AdguardTeam/AdGuardHome']['github.com/adguardteam/adguardhome/home'] = {
        'sub_module': 'github.com/AdguardTeam/AdGuardHome', 'search_module': 'github.com/AdguardTeam/AdGuardHome'}
    module_path['github.com/IceWhaleTech/CasaOS']['github.com/icewhaletech/casaos/web'] = {
        'sub_module': 'github.com/IceWhaleTech/CasaOS', 'search_module': 'github.com/IceWhaleTech/CasaOS'}
    module_path['github.com/mattermost/mattermost-server']['github.com/mattermost/mattermost-server/app'] = {
        'sub_module': 'github.com/mattermost/mattermost-server/v6',
        'search_module': 'github.com/mattermost/mattermost-server'}
    module_path['github.com/mattermost/mattermost-server'][
        'github.com/mattermost/mattermost-server/v6/store/sqlstore'] = {
        'sub_module': 'github.com/mattermost/mattermost-server/v6',
        'search_module': 'github.com/mattermost/mattermost-server'}
    module_path['github.com/mattermost/mattermost-server']['github.com/mattermost/mattermost-server/model'] = {
        'sub_module': 'github.com/mattermost/mattermost-server/v6',
        'search_module': 'github.com/mattermost/mattermost-server'}
    module_path['github.com/mattermost/mattermost-server']['github.com/mattermost/mattermost-server/v6/api4'] = {
        'sub_module': 'github.com/mattermost/mattermost-server/v6',
        'search_module': 'github.com/mattermost/mattermost-server'}
    module_path['github.com/mattermost/mattermost-server']['github.com/mattermost/mattermost-server/store/sqlstore'] = {
        'sub_module': 'github.com/mattermost/mattermost-server/v6',
        'search_module': 'github.com/mattermost/mattermost-server'}
    module_path['github.com/mattermost/mattermost-server']['github.com/mattermost/mattermost-server/v6/model'] = {
        'sub_module': 'github.com/mattermost/mattermost-server/v6',
        'search_module': 'github.com/mattermost/mattermost-server'}
    module_path['github.com/Terry-Mao/goim']['github.com/terry-mao/goim/api/comet/grpc'] = {
        'sub_module': 'github.com/Terry-Mao/goim', 'search_module': 'github.com/Terry-Mao/goim'}
    f = open('./module_path_first.json', 'w')
    json.dump(module_path, f)
    f.close()


def need_download_depts():
    with open('./module_path_first.json', encoding='utf-8') as a:
        module_path = json.load(a)
    search_modules = set()
    for repo in module_path.keys():
        for package in module_path[repo].keys():
            if 'search_module' in module_path[repo][package].keys():
                search_modules.add(module_path[repo][package]['search_module'])
    db = connect_mongodb()
    dependencies_table = db['dependencies']
    # 定义关键字列表
    keywords = list(search_modules)

    # 构建查询条件
    query = {
        "$or": [
            {"dependency_name": {"$in": keywords}},
            {"dependency_name": {"$regex": r"/v\[\d+\]$|\b(" + "|".join(keywords) + r")\b", "$options": "i"}}
        ]
    }

    # 执行查询
    results = dependencies_table.find(query)
    f = open('./origin.txt', 'w')
    for i in results:
        f.write(i['module_name'] + ',' + i['module_version'] + ';' + i['dependency_name'] + ',' + i[
            'dependency_version'] + '\n')
    f.close()


def generate_first_dataset():
    db = connect_mongodb()
    repo_table = db['repo_info']
    f = open('./origin.txt', 'r')
    content = f.read().split('\n')
    with open('./module_path_first.json', encoding='utf-8') as a:
        module_path = json.load(a)
    repos = []
    for i in repo_table.find():
        repos.append(i)
    for i in repos:
        repo = i['repo']
        search_modules = set()
        for package in module_path[repo].keys():
            if 'search_module' in module_path[repo][package].keys():
                search_modules.add(module_path[repo][package]['search_module'])
        content_write = set()
        for j in content:
            if j == '':
                continue
            temp = j.split(';')[1].split(',')[0]
            for module in search_modules:
                pattern = re.compile(module + '/v[0-9]*')
                if temp == module or pattern.search(temp) is not None:
                    content_write.add(j)
        file = open('./first/' + repo.replace('/', '^') + '.txt', 'w')
        for c in content_write:
            file.write(c)
            file.write('\n')
        file.close()


def generate_second_dataset():
    db = connect_mongodb()
    repo_table = db['repo_info']
    commits_table = db['commits_info']
    first_dir = './first/'
    libs_file = os.listdir(first_dir)
    second = dict()
    with open('./module_path_first.json', encoding='utf-8') as a:
        module_path = json.load(a)
    n = 1
    count = len(libs_file)
    for i in libs_file:
        print(n, count)
        origin_file = open(first_dir + i, 'r')
        dependency_list = origin_file.read().split('\n')
        repo = i.replace('^', '/').replace('.txt', '')
        search_modules = set()
        for package in module_path[repo].keys():
            if 'search_module' in module_path[repo][package].keys():
                search_modules.add(module_path[repo][package]['search_module'])
        second[repo] = {}
        commits = dict()
        repo_query = {'repo': repo}
        repo_info = repo_table.find_one(repo_query)
        query = {'repo_id': repo_info['_id']}
        temps = commits_table.find(query)
        for temp in temps:
            commits.update(temp['commits'])
        for o in dependency_list:
            if len(o) == 0:
                continue
            info_list = o.split(';')
            dependency_name = info_list[1].split(',')[0]
            dependency_version = info_list[1].split(',')[1]
            if dependency_name not in second[repo].keys():
                for module in search_modules:
                    pattern = re.compile(module + '/v[0-9]*')
                    if dependency_name == module or pattern.search(dependency_name) is not None:
                        second[repo][dependency_name] = {}
            if dependency_name not in second[repo].keys():
                continue
            if dependency_version not in second[repo][dependency_name].keys():
                second[repo][dependency_name][dependency_version] = {}
                second[repo][dependency_name][dependency_version]['dependents'] = {}
            if info_list[0].split(',')[0] not in second[repo][dependency_name][dependency_version]['dependents'].keys():
                second[repo][dependency_name][dependency_version]['dependents'][info_list[0].split(',')[0]] = []
            second[repo][dependency_name][dependency_version]['dependents'][info_list[0].split(',')[0]].append(
                info_list[0].split(',')[1])
        for submodule in second[repo].keys():
            for version in second[repo][submodule].keys():
                if len(version.split('-')) > 2 and re.search(r"(\d{4}\d{2}\d{2}\d{2}\d{2}\d{2})",
                                                             version.split('-')[-2]) is not None:
                    commit_info = version.split('-')[-1]
                else:
                    cmd = 'git show -s --pretty=format:%H ' + version.replace('+incompatible', '')
                    try:
                        lib_address = './new_vul_repos/' + repo
                        p = subprocess.check_output(cmd, shell=True, cwd=lib_address)
                    except:
                        second[repo][submodule][version]['fault'] = 'not tag'
                        continue
                    commit_info = str(p.splitlines()[-1]).replace('\'', '')[1:]
                if commit_info not in commits.keys():
                    sign = 0
                    for commit in commits.keys():
                        if commit_info in commit:
                            vul_info = list(set(commits[commit]['vul']))
                            sign = 1
                            break
                    if sign == 0:
                        second[repo][submodule][version]['fault'] = 'not commit'
                        continue
                else:
                    vul_info = list(set(commits[commit_info]['vul']))
                second[repo][submodule][version]['vul_info'] = vul_info
        n = n + 1
    f = open('./dependency.json', 'w')
    json.dump(second, f)
    f.close()


def get_lib_name(temp_lib):
    if temp_lib.startswith('github.com/'):
        temp = temp_lib.split('/')
        if len(temp) < 4:
            r = temp_lib
        else:
            r = temp[0] + '/' + temp[1] + '/' + temp[2]
        return r
    return None


def get_need_download_vul_libs():
    with open('./dependency.json', encoding='utf-8') as a:
        dependency = json.load(a)
    dependents = set()
    for repo in dependency.keys():
        for submodule in dependency[repo].keys():
            for version in dependency[repo][submodule].keys():
                if 'fault' not in dependency[repo][submodule][version].keys():
                    if 'vul_info' in dependency[repo][submodule][version].keys():
                        if len(dependency[repo][submodule][version]['vul_info']) > 0:
                            for dependent in dependency[repo][submodule][version]['dependents'].keys():
                                lib = get_lib_name(dependent)
                                if lib is not None:
                                    dependents.add(lib)
    f = open('need_download_libs_vul.txt', 'w')
    f.write('\n'.join(list(dependents)))
    f.close()


def need_analyzing_dependencies():
    with open('./dependency.json', encoding='utf-8') as a:
        dependencies = json.load(a)
    dependency_first = dict()
    for repo in dependencies.keys():
        for vul_module in dependencies[repo].keys():
            for version in dependencies[repo][vul_module].keys():
                if 'vul_info' in dependencies[repo][vul_module][version].keys() \
                        and 'fault' not in dependencies[repo][vul_module][version].keys() and \
                        len(dependencies[repo][vul_module][version]['vul_info']) > 0:
                    if 'dependents' in dependencies[repo][vul_module][version].keys():
                        for dependent in dependencies[repo][vul_module][version]['dependents'].keys():
                            if dependent.startswith('github.com'):
                                if dependent not in dependency_first.keys():
                                    dependency_first[dependent] = {}
                                for vul in dependencies[repo][vul_module][version]['vul_info']:
                                    if vul not in dependency_first[dependent].keys():
                                        dependency_first[dependent][vul] = {}
                                        dependency_first[dependent][vul]['commits_module'] = repo
                                        dependency_first[dependent][vul]['module'] = vul_module
                                        dependency_first[dependent][vul]['path'] = repo
    f = open('./dependency_first.json', 'w')
    json.dump(dependency_first, f)
    f.close()


def get_vul_repos():
    db = connect_mongodb()
    repo_table = db['repo_info']
    repos = set()
    for repo in repo_table.find():
        repos.add(repo['repo'])
    f = open('need_download_vul_repos.txt', 'w')
    f.write('\n'.join(list(repos)))
    f.close()


if __name__ == '__main__':
    generate_origin_depts()
    # search_sub_module()
    # manu_add_sub_module function need change by manual
    # manu_add_sub_module()
    # need_download_depts()
    # generate_first_dataset()
    # generate_second_dataset()
    # get_need_download_vul_libs()
    # need_analyzing_dependencies()
