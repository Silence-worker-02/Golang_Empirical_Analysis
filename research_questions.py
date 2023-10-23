# coding=gbk
import datetime
import json
import os.path
import re
import subprocess
import time
from datetime import datetime, timedelta, timezone
from multiprocessing import Queue, Process
import numpy as np
import pandas as pd
import pytz
import requests
from dateutil.relativedelta import relativedelta
from pymongo import MongoClient

from crawl_snyk_files import convert2json_list


def connect_mongodb():
    client = MongoClient('mongodb://localhost:27017/')
    mongodb = client['Golang_Vulnerabilities']
    return mongodb


def convert_to_utc(time_str):
    # 解析为 datetime 对象
    time_obj = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S %z")

    # 将时间对象转换为 UTC 时间
    utc_time = time_obj.astimezone(pytz.utc)
    return utc_time


def write(q, commit_list):
    for value in commit_list:
        q.put(value)


def read(q):
    if q.qsize() > 0:
        value = q.get(True)
        return value
    else:
        return None


def insert_mongo(table, insert_data_dict: dict):  # 这个性能更好
    """
    往mongodb中插入数据, _id为自增, 注意_id为数值类型
    :param table: 表名
    :param insert_data_dict: 插入的数据,例如{"name": "zhang"}
    :return: insert_id
    """
    last_data = table.find_one(sort=[('_id', -1)])  # 取出最后一条数据
    if not last_data:
        insert_data_dict["_id"] = 1
    else:
        insert_data_dict["_id"] = last_data["_id"] + 1
    return table.insert_one(insert_data_dict).inserted_id


def search_tag_index():
    db = connect_mongodb()
    repos_table = db['repo_info']
    if 'fix_tag_index_info' not in db.list_collection_names():
        # 创建集合
        db.create_collection('fix_tag_index_info')
    tag_index_table = db['fix_tag_index_info']
    repos = []
    for repo in repos_table.find():
        query = {'repo': repo['repo']}
        if tag_index_table.find_one(query):
            continue
        repos.append(repo)
    q = Queue()
    write(q, repos)
    for i in range(6):
        p = Process(target=thread_search_tag_index, args=(q,))
        p.start()


def thread_search_tag_index(q):
    repo = read(q)
    with open('../processing/module_path_first.json', encoding='utf-8') as a:
        module_path = json.load(a)
    db = connect_mongodb()
    vuls_table = db['vulnerabilities_info']
    commits_table = db['commits_info_new']
    index_table = db['golang_index']
    tag_index_table = db['fix_tag_index_info']
    while repo is not None:
        result = dict()
        print(repo['repo'], 'begin')
        result[repo['repo']] = {}
        result[repo['repo']]['repo'] = repo['repo']
        result[repo['repo']]['vuls'] = {}
        query = {'repo_id': repo['_id']}
        temps = commits_table.find(query)
        commits = dict()
        for temp in temps:
            commits.update(temp['commits'])
        tags = repo['tags']
        indexs = dict()
        modules = set()
        for package_path in module_path[repo['repo']].keys():
            if 'search_module' not in module_path[repo['repo']][package_path].keys():
                continue
            modules.add(module_path[repo['repo']][package_path]['search_module'])
        for module in modules:
            query = {'Path': {'$regex': '^' + module}}
            temps = index_table.find(query)
            indexs[module] = {}
            for temp in temps:
                if temp['Path'] not in indexs[module].keys():
                    indexs[module][temp['Path']] = {}
                if temp['Version'] not in indexs[module][temp['Path']].keys():
                    indexs[module][temp['Path']][temp['Version']] = temp['Timestamp']
        for vul_id in repo['vuls']:
            vul_info = vuls_table.find_one({'_id': vul_id})
            result[repo['repo']]['vuls'][str(vul_id)] = {}
            result[repo['repo']]['vuls'][str(vul_id)]['cwe'] = vul_info['cwe']
            result[repo['repo']]['vuls'][str(vul_id)]['cve'] = vul_info['cve']
            safe_commits = dict()
            for commit in commits.keys():
                if vul_id not in commits[commit]['vul']:
                    safe_commits[commit] = commits[commit]
            earliest_time = ''
            earliest_commit = ''
            for commit in safe_commits.keys():
                if earliest_time == '':
                    earliest_time = convert_to_utc(safe_commits[commit]['publish_time'])
                    earliest_commit = commit
                else:
                    temp_time = convert_to_utc(safe_commits[commit]['publish_time'])
                    if temp_time < earliest_time:
                        earliest_time = temp_time
                        earliest_commit = commit
            result[repo['repo']]['vuls'][str(vul_id)]['fix_commit'] = {}
            result[repo['repo']]['vuls'][str(vul_id)]['fix_commit']['earliest_time'] = str(earliest_time)
            result[repo['repo']]['vuls'][str(vul_id)]['fix_commit']['earliest_commit_id'] = earliest_commit
            safe_tags = dict()
            for tag_commit in tags.keys():
                if tag_commit in safe_commits.keys():
                    safe_tags[tag_commit] = tags[tag_commit]
            earliest_tag_time = ''
            earliest_tag_commit = ''
            for tag_commit in safe_tags.keys():
                if earliest_tag_time == '':
                    earliest_tag_time = datetime.fromisoformat(safe_tags[tag_commit]['tag_release_time']).astimezone(
                        pytz.UTC)
                    earliest_tag_commit = tag_commit
                else:
                    temp_time = datetime.fromisoformat(safe_tags[tag_commit]['tag_release_time']).astimezone(pytz.UTC)
                    if temp_time < earliest_tag_time:
                        earliest_tag_time = temp_time
                        earliest_tag_commit = tag_commit
            result[repo['repo']]['vuls'][str(vul_id)]['patch_tag'] = {}
            result[repo['repo']]['vuls'][str(vul_id)]['patch_tag']['earliest_time'] = str(earliest_tag_time)
            result[repo['repo']]['vuls'][str(vul_id)]['patch_tag']['earliest_commit_id'] = earliest_tag_commit
            if earliest_tag_commit == '':
                result[repo['repo']]['vuls'][str(vul_id)]['patch_tag']['tag'] = ''
            else:
                result[repo['repo']]['vuls'][str(vul_id)]['patch_tag']['tag'] = tags[earliest_tag_commit]['tag']
            result[repo['repo']]['vuls'][str(vul_id)]['tag_index'] = {}
            for module in modules:
                earliest_tag_time_index = ''
                earliest_tag_commit_index = ''
                for tag_commit in safe_tags.keys():
                    version = tags[tag_commit]['tag']
                    if len(version.split('/')) > 0:
                        version = version.split('/')[-1]
                    for Path in indexs[module].keys():
                        if version in indexs[module][Path].keys():
                            utc_time_str = indexs[module][Path][version]
                            utc_time = datetime.strptime(utc_time_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                            formatted_time = utc_time.strftime('%Y-%m-%d %H:%M:%S.%f') + '+00:00'
                            if earliest_tag_time_index == '':
                                earliest_tag_time_index = formatted_time
                                earliest_tag_commit_index = tag_commit
                            else:
                                if formatted_time < earliest_tag_time_index:
                                    earliest_tag_time_index = formatted_time
                                    earliest_tag_commit_index = tag_commit
                        if version + '+incompatible' in indexs[module][Path].keys():
                            utc_time_str = indexs[module][Path][version + '+incompatible']
                            utc_time = datetime.strptime(utc_time_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                            formatted_time = utc_time.strftime('%Y-%m-%d %H:%M:%S.%f') + '+00:00'
                            if earliest_tag_time_index == '':
                                earliest_tag_time_index = formatted_time
                                earliest_tag_commit_index = tag_commit
                            else:
                                if formatted_time < earliest_tag_time_index:
                                    earliest_tag_time_index = formatted_time
                                    earliest_tag_commit_index = tag_commit
                result[repo['repo']]['vuls'][str(vul_id)]['tag_index'][module] = {}
                result[repo['repo']]['vuls'][str(vul_id)]['tag_index'][module]['earliest_time'] = str(
                    earliest_tag_time_index)
                result[repo['repo']]['vuls'][str(vul_id)]['tag_index'][module][
                    'earliest_commit_id'] = earliest_tag_commit_index
                if earliest_tag_commit_index == '':
                    result[repo['repo']]['vuls'][str(vul_id)]['tag_index'][module]['tag'] = ''
                else:
                    result[repo['repo']]['vuls'][str(vul_id)]['tag_index'][module]['tag'] = \
                        tags[earliest_tag_commit_index]['tag']
        insert_mongo(tag_index_table, result[repo['repo']])
        print(repo['repo'], 'success')
        repo = read(q)


def search_tag_index_for_one(repo_name):
    db = connect_mongodb()
    repos_table = db['repo_info']
    if 'fix_tag_index_info' not in db.list_collection_names():
        # 创建集合
        db.create_collection('fix_tag_index_info')
    tag_index_table = db['fix_tag_index_info']
    index_table = db['golang_index']
    query = {'repo': repo_name}
    repo = repos_table.find_one(query)
    if tag_index_table.find_one(query) is None:
        insert_mongo(tag_index_table, {'repo': repo_name, 'vuls': dict()})
    commits_table = db['commits_info_new']
    query = {'repo_id': repo['_id']}
    temps = commits_table.find(query)
    commits = dict()
    for temp in temps:
        commits.update(temp['commits'])
    with open('../processing/module_path_first.json', encoding='utf-8') as a:
        module_path = json.load(a)
    q = Queue()
    write(q, repo['vuls'])
    indexs = dict()
    modules = set()
    for package_path in module_path[repo['repo']].keys():
        if 'search_module' not in module_path[repo['repo']][package_path].keys():
            continue
        modules.add(module_path[repo['repo']][package_path]['search_module'])
    for module in modules:
        query = {'Path': {'$regex': '^' + module}}
        temps = index_table.find(query)
        indexs[module] = {}
        for temp in temps:
            if temp['Path'] not in indexs[module].keys():
                indexs[module][temp['Path']] = {}
            if temp['Version'] not in indexs[module][temp['Path']].keys():
                indexs[module][temp['Path']][temp['Version']] = temp['Timestamp']
    for i in range(3):
        p = Process(target=thread_search_tag_index_for_one, args=(q, commits, repo, indexs,))
        p.start()


def thread_search_tag_index_for_one(q, commits, repo, indexs):
    vul_id = read(q)
    with open('../processing/module_path_first.json', encoding='utf-8') as a:
        module_path = json.load(a)
    db = connect_mongodb()
    vuls_table = db['vulnerabilities_info']
    tag_index_table = db['fix_tag_index_info']
    tags = repo['tags']
    while vul_id is not None:
        print(vul_id)
        query = {'repo': repo['repo'], 'vuls.' + str(vul_id): {'$exists': 'true'}}
        if tag_index_table.find_one(query) is not None:
            vul_id = read(q)
            continue
        result = dict()
        vul_info = vuls_table.find_one({'_id': vul_id})
        result[str(vul_id)] = {}
        result[str(vul_id)]['cwe'] = vul_info['cwe']
        result[str(vul_id)]['cve'] = vul_info['cve']
        safe_commits = dict()
        for commit in commits.keys():
            if vul_id not in commits[commit]['vul']:
                safe_commits[commit] = commits[commit]
        earliest_time = ''
        earliest_commit = ''
        for commit in safe_commits.keys():
            if earliest_time == '':
                earliest_time = convert_to_utc(safe_commits[commit]['publish_time'])
                earliest_commit = commit
            else:
                temp_time = convert_to_utc(safe_commits[commit]['publish_time'])
                if temp_time < earliest_time:
                    earliest_time = temp_time
                    earliest_commit = commit
        result[str(vul_id)]['fix_commit'] = {}
        result[str(vul_id)]['fix_commit']['earliest_time'] = str(earliest_time)
        result[str(vul_id)]['fix_commit']['earliest_commit_id'] = earliest_commit
        safe_tags = dict()
        for tag_commit in tags.keys():
            if tag_commit in safe_commits.keys():
                safe_tags[tag_commit] = safe_commits[tag_commit]
        earliest_tag_time = ''
        earliest_tag_commit = ''
        for tag_commit in safe_tags.keys():
            if earliest_tag_time == '':
                earliest_tag_time = convert_to_utc(safe_tags[tag_commit]['publish_time'])
                earliest_tag_commit = tag_commit
            else:
                temp_time = convert_to_utc(safe_tags[tag_commit]['publish_time'])
                if temp_time < earliest_tag_time:
                    earliest_tag_time = temp_time
                    earliest_tag_commit = tag_commit
        result[str(vul_id)]['patch_tag'] = {}
        result[str(vul_id)]['patch_tag']['earliest_time'] = str(earliest_tag_time)
        result[str(vul_id)]['patch_tag']['earliest_commit_id'] = earliest_tag_commit
        if earliest_tag_commit == '':
            result[str(vul_id)]['patch_tag']['tag'] = ''
        else:
            result[str(vul_id)]['patch_tag']['tag'] = tags[earliest_tag_commit]['tag']
        modules = set()
        for package_path in module_path[repo['repo']].keys():
            if 'search_module' not in module_path[repo['repo']][package_path].keys():
                continue
            modules.add(module_path[repo['repo']][package_path]['search_module'])
        result[str(vul_id)]['tag_index'] = {}
        for module in modules:
            earliest_tag_time_index = ''
            earliest_tag_commit_index = ''
            for tag_commit in safe_tags.keys():
                version = tags[tag_commit]['tag']
                if len(version.split('/')) > 0:
                    version = version.split('/')[-1]
                for Path in indexs[module].keys():
                    if version in indexs[module][Path].keys():
                        utc_time_str = indexs[module][Path][version]
                        utc_time = datetime.strptime(utc_time_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                        formatted_time = utc_time.strftime('%Y-%m-%d %H:%M:%S.%f') + '+00:00'
                        if earliest_tag_time_index == '':
                            earliest_tag_time_index = formatted_time
                            earliest_tag_commit_index = tag_commit
                        else:
                            if formatted_time < earliest_tag_time_index:
                                earliest_tag_time_index = formatted_time
                                earliest_tag_commit_index = tag_commit
                    if version + '+incompatible' in indexs[module][Path].keys():
                        utc_time_str = indexs[module][Path][version + '+incompatible']
                        utc_time = datetime.strptime(utc_time_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                        formatted_time = utc_time.strftime('%Y-%m-%d %H:%M:%S.%f') + '+00:00'
                        if earliest_tag_time_index == '':
                            earliest_tag_time_index = formatted_time
                            earliest_tag_commit_index = tag_commit
                        else:
                            if formatted_time < earliest_tag_time_index:
                                earliest_tag_time_index = formatted_time
                                earliest_tag_commit_index = tag_commit
            result[str(vul_id)]['tag_index'][module] = {}
            result[str(vul_id)]['tag_index'][module]['earliest_time'] = str(
                earliest_tag_time_index)
            result[str(vul_id)]['tag_index'][module][
                'earliest_commit_id'] = earliest_tag_commit_index
            if earliest_tag_commit_index == '':
                result[str(vul_id)]['tag_index'][module]['tag'] = ''
            else:
                result[str(vul_id)]['tag_index'][module]['tag'] = \
                    tags[earliest_tag_commit_index]['tag']
        query = {'repo': repo['repo']}
        new_data = {
            "$set": {"vuls." + str(vul_id): result[str(vul_id)]}}
        tag_index_table.update_one(query, new_data)
        vul_id = read(q)


def get_vul_module_tag_intervals_by_branch():
    db = connect_mongodb()
    tag_index_table = db['fix_tag_index_info']
    if not os.path.exists('./vul_tag_intervals_branch.txt'):
        f = open('./vul_tag_intervals_branch.txt', 'w')
        f.close()
    f = open('./vul_tag_intervals_branch.txt', 'r')
    ready = f.read().split('\n')
    f.close()
    already = set()
    for i in ready:
        if i == '':
            continue
        already.add(i.split(';')[0])
    need = set()
    for tag_index in tag_index_table.find():
        if tag_index['repo'] not in already:
            need.add(tag_index['repo'])
    q = Queue()
    write(q, need)
    for i in range(4):
        p = Process(target=thread_get_vul_module_tag_intervals_by_branch, args=(q,))
        p.start()


def thread_get_vul_module_tag_intervals_by_branch(q):
    repo = read(q)
    while repo is not None:
        path = 'E:/vul_repos/' + repo
        cmd = 'git tag'
        p = subprocess.check_output(cmd, shell=True, cwd=path)
        tags = set()
        for i in p.splitlines():
            tag = str(i)[1:].replace('\'', '')
            tags.add(tag)
        tag_interval = dict()
        for tag in tags:
            cmd = '`git show -s --pretty=format:%H,%cd` ' + tag
            p = subprocess.check_output(cmd, shell=True, cwd=path)
            temps = str(p.splitlines()[-1])[1:].replace('\'', '').split(',')
            try:
                tag_release_time = str(pd.Timestamp(temps[1]).tz_convert(pytz.UTC))
            except:
                print(repo, temps)
                continue
            cmd = 'git branch -a --contains ' + tag
            p = subprocess.check_output(cmd, shell=True, cwd=path)
            for i in p.splitlines():
                if str(i) not in tag_interval.keys():
                    tag_interval[str(i)] = []
                tag_interval[str(i)].append(tag_release_time)
        f = open('./vul_tag_intervals_branch.txt', 'a')
        for branch in tag_interval.keys():
            f.write(repo + ';' + branch + ';' + ','.join(tag_interval[branch]) + '\n')
        f.close()
        print(repo)
        repo = read(q)


def generate_tag_intervals_json():
    f = open('./vul_tag_intervals_branch.txt', 'r')
    vul_tag_intervals = dict()
    for i in f.read().split('\n'):
        if i == '':
            continue
        temps = i.split(';')
        repo = temps[0]
        branch = temps[1]
        tag_times = temps[2].split(',')
        if repo not in vul_tag_intervals.keys():
            vul_tag_intervals[repo] = {}
        if branch not in vul_tag_intervals[repo].keys():
            tag_times.sort()
            vul_tag_intervals[repo][branch] = tag_times
    f.close()
    f = open('./vul_tag_intervals.json', 'w')
    json.dump(vul_tag_intervals, f)
    f.close()


def generate_vul_tag_intervals_hour():
    with open('./vul_tag_intervals.json', encoding='utf-8') as a:
        vul_tag_intervals = json.load(a)
    if not os.path.exists('./data/vul_tag_intervals_branch_hour.txt'):
        f = open('./vul_tag_intervals_branch_hour.txt', 'w')
        f.close()
    for lib in vul_tag_intervals.keys():
        intervals = []
        for branch in vul_tag_intervals[lib].keys():
            if len(vul_tag_intervals[lib][branch]) < 2:
                continue
            current = vul_tag_intervals[lib][branch][0]
            for i in vul_tag_intervals[lib][branch][1:]:
                time_temp = (datetime.strptime(i.split('+00')[0], '%Y-%m-%d %H:%M:%S') - datetime.strptime(
                    current.split('+00')[0], '%Y-%m-%d %H:%M:%S'))
                time_temp_interval = time_temp.total_seconds() / 60 / 60
                intervals.append(str(time_temp_interval))
                current = i
        if len(intervals) == 0:
            continue
        f = open('./vul_tag_intervals_branch_hour.txt', 'a')
        f.write(lib + ';' + ','.join(intervals) + '\n')


def generate_vul_tag_normal_intervals():
    f = open('./vul_tag_intervals_branch_hour.txt', 'r')
    tag_intervals = f.read().split('\n')
    f.close()
    normal_intervals = dict()
    for i in tag_intervals:
        if i == '':
            continue
        lib_name = i.split(';')[0]
        temps = i.split(';')[1].split(',')
        intervals = []
        for j in temps:
            if j == '0.0':
                continue
            intervals.append(float(j))
        s = pd.Series(intervals)

        # std_threshold = 3  # 设置为3倍标准差
        # s_mean = s.mean()
        # s_std = s.std()
        # s[(s - s_mean).abs() > std_threshold * s_std] = np.nan

        # 使用 quantile 函数计算四分位数，并设置阈值
        q1 = s.quantile(0.25)
        q3 = s.quantile(0.75)
        iqr_threshold = 1.5  # 设置为1.5倍四分位距
        iqr = q3 - q1
        s[s < (q1 - iqr_threshold * iqr)] = np.nan
        s[s > (q3 + iqr_threshold * iqr)] = np.nan

        # 获取正常取值范围
        normal_range = (s.dropna().min(), s.dropna().max())
        normal_intervals[lib_name] = normal_range
    f = open('./normal_intervals.json', 'w')
    json.dump(normal_intervals, f)
    f.close()


def get_fixing_commits_intervals():
    db = connect_mongodb()
    fix_tag_index_table = db['fix_tag_index_info']
    if not os.path.exists('./fixing_commits_intervals.txt'):
        f = open('./fixing_commits_intervals.txt', 'w')
        f.close()
    need = []
    for repo in fix_tag_index_table.find():
        for vul_id in repo['vuls'].keys():
            if repo['vuls'][vul_id]['fix_commit']['earliest_time'] != '' and \
                    repo['vuls'][vul_id]['patch_tag']['earliest_time'] != '':
                temp = dict()
                temp['repo'] = repo['repo']
                temp['vul_id'] = vul_id
                temp['patch_commit'] = repo['vuls'][vul_id]['patch_tag']['earliest_commit_id']
                temp['patch_tag'] = repo['vuls'][vul_id]['patch_tag']['tag']
                temp['patch_tag_time'] = repo['vuls'][vul_id]['patch_tag']['earliest_time']
                need.append(temp)
    q = Queue()
    write(q, need)
    for i in range(1):
        p = Process(target=thread_get_fixing_commits_intervals, args=(q,))
        p.start()


def thread_get_fixing_commits_intervals(q):
    info = read(q)
    db = connect_mongodb()
    repo_table = db['repo_info']
    commits_table = db['commits_info_new']
    while info is not None:
        repo = info['repo']
        vul_id = info['vul_id']
        query = {'repo': repo}
        temps = commits_table.find(query)
        commits = dict()
        for temp in temps:
            commits.update(temp['commits'])
        repo_info = repo_table.find_one(query)
        tags = set()
        for commit in repo_info['tags'].keys():
            tags.add(commit)
        fixing_commits = set()
        fixing_commits.add(info['patch_commit'])
        pre_unsafe_commits = set()
        temps = Queue()
        for temp in fixing_commits:
            temps.put(temp)
        while temps.qsize() > 0:
            temp = temps.get()
            for o in commits[temp]['fathers']:
                if o in pre_unsafe_commits:
                    continue
                pre_unsafe_commits.add(o)
                temps.put(o)
        result = pre_unsafe_commits & tags
        current_time = ''
        current_tag = ''
        current_commit_id = ''
        for i in result:
            if current_time == '' or repo_info['tags'][i]['tag_release_time'] > current_time:
                current_time = repo_info['tags'][i]['tag_release_time']
                current_tag = repo_info['tags'][i]['tag']
                current_commit_id = i
        f = open('fixing_commits_intervals.txt', 'a')
        f.write(str(vul_id) + ';' + info['patch_tag'] + ';' + info['patch_tag_time'] + ';' + info[
            'patch_commit'] + ';' + current_tag + ';' + current_time + ';' + current_commit_id)
        f.write('\n')
        f.close()
        info = read(q)


def generate_research_question_two_data():
    f = open('fixing_commits_intervals.txt')
    result = dict()
    content = f.read().split('\n')
    f.close()
    for line in content:
        if line == '':
            continue
        temps = line.split(';')
        vul_id = temps[0]
        time1 = temps[2]
        time2 = temps[5]
        if time2 == '':
            continue
        dt1 = datetime.fromisoformat(time1)
        dt2 = datetime.fromisoformat(time2)
        dt1_utc = dt1.astimezone(pytz.UTC)
        dt2_utc = dt2.astimezone(pytz.UTC)
        time_diff = dt1_utc - dt2_utc
        time_temp_interval = time_diff.total_seconds() / 60 / 60
        result[vul_id] = str(time_temp_interval)
    f = open('./vul_fixing_tag_interval.json', 'w')
    json.dump(result, f)
    f.close()


def generate_vul_tag_interval():
    db = connect_mongodb()
    vul_table = db['vulnerabilities_info']
    if 'vul_tag_interval' not in db.list_collection_names():
        # 创建集合
        db.create_collection('vul_tag_interval')
    vul_tag_interval_table = db['vul_tag_interval']
    with open('./normal_intervals.json', encoding='utf-8') as a:
        normal_intervals = json.load(a)
    with open('./vul_fixing_tag_interval.json', encoding='utf-8') as a:
        vul_fixing_tag_interval = json.load(a)
    for vul_id in vul_fixing_tag_interval.keys():
        vul_info = vul_table.find_one({'_id': int(vul_id)})
        repo = vul_info['repo']
        if repo in normal_intervals.keys():
            max_normal_interval = normal_intervals[repo][1]
        else:
            max_normal_interval = -1
        insert_mongo(vul_tag_interval_table,
                     {'vul_id': int(vul_id), 'repo': repo, 'cve': vul_info['cve'], 'cwe': vul_info['cwe'],
                      'fixing_commit_belong_tag_interval': float(vul_fixing_tag_interval[vul_id]),
                      'max_normal_interval': float(max_normal_interval)})


def update_fix_tag_index():
    db = connect_mongodb()
    fix_tag_index_table = db['fix_tag_index_info']
    vul_tag_interval_table = db['vul_tag_interval']
    for interval in vul_tag_interval_table.find():
        query = {'repo': interval['repo']}
        fix_tag_index = fix_tag_index_table.find_one(query)
        temp = dict()
        temp["T_fix"] = fix_tag_index['vuls'][str(interval['vul_id'])]['fix_commit']['earliest_time']
        temp["T_ver"] = fix_tag_index['vuls'][str(interval['vul_id'])]['patch_tag']['earliest_time']
        index_time = ''
        for vul_module in fix_tag_index['vuls'][str(interval['vul_id'])]['tag_index'].keys():
            if fix_tag_index['vuls'][str(interval['vul_id'])]['tag_index'][vul_module]['earliest_time'] != "":
                index_time = fix_tag_index['vuls'][str(interval['vul_id'])]['tag_index'][vul_module]['earliest_time']
                break
        temp["T_index"] = index_time
        new_data = {"$set": temp}
        query = {'_id': interval['_id']}
        vul_tag_interval_table.update_one(query, new_data)


def update_lags():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    query = {'T_fix': {'$gte': '2019-04-10 00:00:00+00:00'}, 'T_ver': {'$ne': ''}}
    for fix_vul_tag in vul_tag_interval_table.find(query):
        t_fix = datetime.strptime(fix_vul_tag['T_fix'].split('+00')[0], '%Y-%m-%d %H:%M:%S')
        t_ver = datetime.strptime(fix_vul_tag['T_ver'].split('+00')[0], '%Y-%m-%d %H:%M:%S')
        lag_ver = (t_ver - t_fix).total_seconds() / 60 / 60
        lag_index = ''
        if fix_vul_tag['T_index'] != '':
            t_index = datetime.strptime(fix_vul_tag['T_index'].split('.')[0], '%Y-%m-%d %H:%M:%S')
            lag_index = (t_index - t_ver).total_seconds() / 60 / 60
        new_data = {"$set": {'Lag_ver': lag_ver, 'Lag_index': lag_index}}
        query = {'_id': fix_vul_tag['_id']}
        vul_tag_interval_table.update_one(query, new_data)


def update_vul_tag_interval_no_tag():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    fix_tag_index_table = db['fix_tag_index_info']
    for fix_tag_index in fix_tag_index_table.find():
        for vul in fix_tag_index['vuls'].keys():
            if vul_tag_interval_table.find_one({'vul_id': int(vul)}):
                continue
            temp = dict()
            temp['vul_id'] = int(vul)
            temp['repo'] = fix_tag_index['repo']
            temp['cve'] = fix_tag_index['vuls'][vul]['cve']
            temp['cwe'] = fix_tag_index['vuls'][vul]['cwe']
            temp['T_fix'] = fix_tag_index['vuls'][vul]['fix_commit']['earliest_time']
            temp['T_ver'] = fix_tag_index['vuls'][vul]['patch_tag']['earliest_time']
            temp['T_index'] = ''
            insert_mongo(vul_tag_interval_table, temp)


def update_addition_lags():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    query = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'Lag_ver': {
            '$exists': False
        }
    }
    for vul_tag_interval in vul_tag_interval_table.find(query):
        if vul_tag_interval['T_fix'] == '' or vul_tag_interval['T_ver'] == '':
            new_data = {"$set": {'Lag_ver': '', 'Lag_index': ''}}
            query = {'_id': vul_tag_interval['_id']}
            vul_tag_interval_table.update_one(query, new_data)
        else:
            if vul_tag_interval['T_index'] == '':
                t_fix = datetime.strptime(vul_tag_interval['T_fix'].split('+00')[0], '%Y-%m-%d %H:%M:%S')
                t_ver = datetime.strptime(vul_tag_interval['T_ver'].split('+00')[0], '%Y-%m-%d %H:%M:%S')
                lag_ver = (t_ver - t_fix).total_seconds() / 60 / 60
                new_data = {"$set": {'Lag_ver': lag_ver, 'Lag_index': ''}}
                query = {'_id': vul_tag_interval['_id']}
                vul_tag_interval_table.update_one(query, new_data)
            else:
                t_fix = datetime.strptime(vul_tag_interval['T_fix'].split('+00')[0], '%Y-%m-%d %H:%M:%S')
                t_ver = datetime.strptime(vul_tag_interval['T_ver'].split('+00')[0], '%Y-%m-%d %H:%M:%S')
                t_index = datetime.strptime(vul_tag_interval['T_index'].split('.')[0], '%Y-%m-%d %H:%M:%S')
                lag_ver = (t_ver - t_fix).total_seconds() / 60 / 60
                lag_index = (t_index - t_ver).total_seconds() / 60 / 60
                new_data = {"$set": {'Lag_ver': lag_ver, 'Lag_index': lag_index}}
                query = {'_id': vul_tag_interval['_id']}
                vul_tag_interval_table.update_one(query, new_data)


def find_dependents_count_of_non_t_ver():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    with open('../processing/dependency.json', encoding='utf-8') as a:
        dependency = json.load(a)
    query = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_ver': ''
    }
    for interval in vul_tag_interval_table.find(query):
        dependents = set()
        repo = interval['repo']
        vul_id = interval['vul_id']
        for module in dependency[repo].keys():
            for version in dependency[repo][module].keys():
                if 'fault' in dependency[repo][module][version].keys():
                    continue
                if 'vul_info' in dependency[repo][module][version].keys():
                    if vul_id in dependency[repo][module][version]['vul_info']:
                        for dependent in dependency[repo][module][version]['dependents'].keys():
                            dependents.add(dependent)
        print(interval['repo'], '\'vul_id\':', interval['vul_id'], '\'cve\':', interval['cve'], '\'cwe\':',
              interval['cwe'], '\'T_fix\':', interval['T_fix'], len(dependents))


def compute_lag_ver():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    query = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_ver': {
            '$ne': ''
        }
    }
    simu = 0
    simu_unusual = 0
    simu_not_exist = 0
    one_day = 0
    one_day_unusual = 0
    one_day_not_exist = 0
    one_week = 0
    one_week_unusual = 0
    one_week_not_exist = 0
    one_month = 0
    one_month_unusual = 0
    one_month_not_exist = 0
    three_month = 0
    three_month_unusual = 0
    three_month_not_exist = 0
    six_month = 0
    six_month_unusual = 0
    six_month_not_exist = 0
    one_year = 0
    one_year_unusual = 0
    one_year_not_exist = 0
    over_year = 0
    over_year_unusual = 0
    over_year_not_exist = 0
    for vul_tag_interval in vul_tag_interval_table.find(query):
        fixing_commit_belong_tag_interval = None
        if 'Lag_ver_new' not in vul_tag_interval.keys():
            lag_ver = vul_tag_interval['Lag_ver']
        else:
            lag_ver = vul_tag_interval['Lag_ver_new']
        if 'max_normal_interval' in vul_tag_interval.keys():
            sign = 1
            max_normal_interval = vul_tag_interval['max_normal_interval']
        if 'fixing_commit_belong_tag_interval' in vul_tag_interval.keys():
            fixing_commit_belong_tag_interval = vul_tag_interval['fixing_commit_belong_tag_interval']
        else:
            sign = 0
        if lag_ver == 0:
            simu = simu + 1
            if sign == 0:
                simu_not_exist = simu_not_exist + 1
            else:
                if fixing_commit_belong_tag_interval is not None:
                    if fixing_commit_belong_tag_interval > max_normal_interval:
                        simu_unusual = simu_unusual + 1
        if 0 < lag_ver <= 24:
            one_day = one_day + 1
            if sign == 0:
                one_day_not_exist = one_day_not_exist + 1
            else:
                if fixing_commit_belong_tag_interval is not None:
                    if fixing_commit_belong_tag_interval > max_normal_interval:
                        one_day_unusual = one_day_unusual + 1
        if 24 < lag_ver <= 168:
            one_week = one_week + 1
            if sign == 0:
                one_week_not_exist = one_week_not_exist + 1
            else:
                if fixing_commit_belong_tag_interval is not None:
                    if fixing_commit_belong_tag_interval > max_normal_interval:
                        one_week_unusual = one_week_unusual + 1
        if 168 < lag_ver <= 720:
            one_month = one_month + 1
            if sign == 0:
                one_month_not_exist = one_month_not_exist + 1
            else:
                if fixing_commit_belong_tag_interval is not None:
                    if fixing_commit_belong_tag_interval > max_normal_interval:
                        one_month_unusual = one_month_unusual + 1
        if 720 < lag_ver <= 2160:
            three_month = three_month + 1
            if sign == 0:
                three_month_not_exist = three_month_not_exist + 1
            else:
                if fixing_commit_belong_tag_interval is not None:
                    if fixing_commit_belong_tag_interval > max_normal_interval:
                        three_month_unusual = three_month_unusual + 1
        if 2160 < lag_ver <= 4320:
            six_month = six_month + 1
            if sign == 0:
                six_month_not_exist = six_month_not_exist + 1
            else:
                if fixing_commit_belong_tag_interval is not None:
                    if fixing_commit_belong_tag_interval > max_normal_interval:
                        six_month_unusual = six_month_unusual + 1
        if 4320 < lag_ver <= 8760:
            one_year = one_year + 1
            if sign == 0:
                one_year_not_exist = one_year_not_exist + 1
            else:
                if fixing_commit_belong_tag_interval is not None:
                    if fixing_commit_belong_tag_interval > max_normal_interval:
                        one_year_unusual = one_year_unusual + 1
        if lag_ver > 8760:
            over_year = over_year + 1
            if sign == 0:
                over_year_not_exist = over_year_not_exist + 1
            else:
                if fixing_commit_belong_tag_interval is not None:
                    if fixing_commit_belong_tag_interval > max_normal_interval:
                        over_year_unusual = over_year_unusual + 1
    print('simu: ', simu - simu_unusual, simu_unusual, simu_not_exist)
    print('one day: ', one_day - one_day_unusual, one_day_unusual, one_day_not_exist)
    print('one week: ', one_week - one_week_unusual, one_week_unusual, one_week_not_exist)
    print('one month: ', one_month - one_month_unusual, one_month_unusual, one_month_not_exist)
    print('three month: ', three_month - three_month_unusual, three_month_unusual, three_month_not_exist)
    print('six month: ', six_month - six_month_unusual, six_month_unusual, six_month_not_exist)
    print('one year: ', one_year - one_year_unusual, one_year_unusual, one_year_not_exist)
    print('over year: ', over_year - over_year_unusual, over_year_unusual, over_year_not_exist)


def compute_lag_index():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    query_1 = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_ver': {
            '$ne': ''
        },
        'T_index': {
            '$ne': ''
        },
        'Lag_index': {
            '$gt': 0,
            '$lte': 1
        }
    }
    query_2 = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_ver': {
            '$ne': ''
        },
        'T_index': {
            '$ne': ''
        },
        'Lag_index': {
            '$gt': 1,
            '$lte': 24
        }
    }
    query_3 = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_ver': {
            '$ne': ''
        },
        'T_index': {
            '$ne': ''
        },
        'Lag_index': {
            '$gt': 24,
            '$lte': 72
        }
    }
    query_4 = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_ver': {
            '$ne': ''
        },
        'T_index': {
            '$ne': ''
        },
        'Lag_index': {
            '$gt': 72,
            '$lte': 168
        }
    }
    query_5 = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_ver': {
            '$ne': ''
        },
        'T_index': {
            '$ne': ''
        },
        'Lag_index': {
            '$gt': 168,
            '$lte': 360
        }
    }
    query_6 = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_ver': {
            '$ne': ''
        },
        'T_index': {
            '$ne': ''
        },
        'Lag_index': {
            '$gt': 360,
            '$lte': 720
        }
    }
    query_7 = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_ver': {
            '$ne': ''
        },
        'T_index': {
            '$ne': ''
        },
        'Lag_index': {
            '$gt': 720,
            '$lte': 2160
        }
    }
    query_8 = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_ver': {
            '$ne': ''
        },
        'T_index': {
            '$ne': ''
        },
        'Lag_index': {
            '$gt': 2160,
            '$lte': 4320
        }
    }
    query_9 = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_ver': {
            '$ne': ''
        },
        'T_index': {
            '$ne': ''
        },
        'Lag_index': {
            '$gt': 4320,
            '$lte': 8760
        }
    }
    query_10 = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_ver': {
            '$ne': ''
        },
        'T_index': {
            '$ne': ''
        },
        'Lag_index': {
            '$gt': 8760
        }
    }
    query_11 = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_index': {
            '$eq': ''
        },
        'Lag_index': {
            '$eq': ''
        },
    }
    count_1 = vul_tag_interval_table.count_documents(query_1)
    count_2 = vul_tag_interval_table.count_documents(query_2)
    count_3 = vul_tag_interval_table.count_documents(query_3)
    count_4 = vul_tag_interval_table.count_documents(query_4)
    count_5 = vul_tag_interval_table.count_documents(query_5)
    count_6 = vul_tag_interval_table.count_documents(query_6)
    count_7 = vul_tag_interval_table.count_documents(query_7)
    count_8 = vul_tag_interval_table.count_documents(query_8)
    count_9 = vul_tag_interval_table.count_documents(query_9)
    count_10 = vul_tag_interval_table.count_documents(query_10)
    count_11 = vul_tag_interval_table.count_documents(query_11)
    print(count_1, count_2, count_3, count_4, count_5, count_6, count_7, count_8, count_9, count_10, count_11)
    count = count_1 + count_2 + count_3 + count_4 + count_5 + count_6 + count_7 + count_8 + count_9 + count_10 + count_11
    counts = [count_1, count_2, count_3, count_4, count_5, count_6, count_7, count_8, count_9, count_10, count_11]
    temp = 0
    temps = []
    for i in counts:
        temp = temp + i
        temps.append(temp / count)
    print(temps[0], temps[1], temps[2], temps[3], temps[4], temps[5], temps[6], temps[7], temps[8], temps[9], temps[10])
    print(count)


# repo,vul_id,cve,cwe,T_fix,dependents,state of patch version(0:未发布,1:发布),
# state of merge(0:未存在于主分支,1:存在于主分支,2:存在于主分支但是未通过check,3:不存在于主分支且未通过check),star,last commit time
def insert_no_patch_version_info_table():
    f = open('./no_patch_version_info.txt', 'r')
    content = f.read().split('\n')
    f.close()
    db = connect_mongodb()
    if 'no_patch_version_info' not in db.list_collection_names():
        # 创建集合
        db.create_collection('no_patch_version_info')
    table = db['no_patch_version_info']
    for i in content:
        data = dict()
        temps = i.split(',')
        data['repo'] = temps[0]
        data['vul_id'] = int(temps[1])
        data['cve'] = temps[2]
        data['cwe'] = temps[3]
        data['T_fix'] = temps[4]
        data['count_of_dependents'] = int(temps[5])
        data['state_of_patch_version'] = int(temps[6])
        data['state_of_merge'] = int(temps[7])
        data['star'] = temps[8]
        data['last_commit_time'] = temps[9]
        query = {'vul_id': data['vul_id']}
        if table.find_one(query):
            continue
        insert_mongo(table, data)


def update_no_patch_version_info_table():
    db = connect_mongodb()
    no_patch_table = db['no_patch_version_info']
    fix_tag_index_table = db['fix_tag_index_info']
    for i in no_patch_table.find():
        query = {'repo': i['repo']}
        fix_tag_index = fix_tag_index_table.find_one(query)
        new_data = {
            '$set': {'fix_commit_id': fix_tag_index['vuls'][str(i['vul_id'])]['fix_commit']['earliest_commit_id']}}
        query = {'_id': i['_id']}
        no_patch_table.update_one(query, new_data)


def process_go_sum_result():
    tag_release_time = dict()
    f = open('./go_sum_result.json', 'w')
    result_fixing = open('./result_fixing.txt', 'r').read().split('\n')
    for i in result_fixing:
        if i == '':
            continue
        temps = i.split(';')
        module = temps[0]
        vul_id = temps[1]
        commit_id = temps[2]
        pub_time = temps[3]
        fixing_sign = temps[-1]
        if vul_id not in tag_release_time.keys():
            tag_release_time[vul_id] = {}
        if fixing_sign not in tag_release_time[vul_id].keys():
            tag_release_time[vul_id][fixing_sign] = {}
        if module not in tag_release_time[vul_id][fixing_sign].keys():
            tag_release_time[vul_id][fixing_sign][module] = {}
        tag_release_time[vul_id][fixing_sign][module]['commit_id'] = commit_id
        tag_release_time[vul_id][fixing_sign][module]['commit_pub_date'] = pub_time
        if fixing_sign == '1':
            latest_commit_id = temps[4]
            latest_commit_time = temps[5]
            earliest_fixing_commit = temps[6]
            earliest_fixing_version = temps[7]
            earliest_fixing_commit_date = temps[8]
            tag_release_time[vul_id][fixing_sign][module]['latest_commit_id'] = latest_commit_id
            tag_release_time[vul_id][fixing_sign][module]['latest_commit_time'] = latest_commit_time
            tag_release_time[vul_id][fixing_sign][module]['earliest_fixing_commit'] = earliest_fixing_commit
            tag_release_time[vul_id][fixing_sign][module]['earliest_fixing_version'] = earliest_fixing_version
            tag_release_time[vul_id][fixing_sign][module]['earliest_fixing_commit_date'] = earliest_fixing_commit_date
        if fixing_sign == '2':
            fixing_version = temps[4]
            latest_commit_id = temps[5]
            latest_commit_time = temps[6]
            tag_release_time[vul_id][fixing_sign][module]['fixing_version'] = fixing_version
            tag_release_time[vul_id][fixing_sign][module]['latest_commit_id'] = latest_commit_id
            tag_release_time[vul_id][fixing_sign][module]['latest_commit_time'] = latest_commit_time
        if fixing_sign == '3':
            latest_commit_id = temps[4]
            latest_commit_time = temps[5]
            tag_release_time[vul_id][fixing_sign][module]['latest_commit_id'] = latest_commit_id
            tag_release_time[vul_id][fixing_sign][module]['latest_commit_time'] = latest_commit_time
    json.dump(tag_release_time, f)
    f.close()


def is_pseudo_version(version):
    pattern = r'.*\d{14}-[a-f0-9]+$'
    return re.match(pattern, version) is not None


def count_of_fixing_result():
    with open('./go_sum_result.json', encoding='utf-8') as a:
        go_sum_result = json.load(a)
    print(len(go_sum_result.keys()))
    remove = 0
    update_tag = 0
    update_pseudo = 0
    no_fix = 0
    dependents = set()
    for vul_id in go_sum_result.keys():
        if '1' in go_sum_result[vul_id].keys():
            remove = remove + len(go_sum_result[vul_id]['1'].keys())
        if '2' in go_sum_result[vul_id].keys():
            for module in go_sum_result[vul_id]['2'].keys():
                if is_pseudo_version(go_sum_result[vul_id]['2'][module]['fixing_version']):
                    update_pseudo = update_pseudo + 1
                else:
                    update_tag = update_tag + 1
        if '3' in go_sum_result[vul_id].keys():
            no_fix = no_fix + len(go_sum_result[vul_id]['3'].keys())
        for fixing_sign in go_sum_result[vul_id].keys():
            for module in go_sum_result[vul_id][fixing_sign].keys():
                dependents.add(module)
    print(remove, update_pseudo, update_tag, no_fix)
    print(len(dependents))


def count_not_exist_go_sum():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    need_analysis_vuls = set()
    query = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        }
    }
    for i in vul_tag_interval_table.find(query):
        need_analysis_vuls.add(i['vul_id'])
    with open('../processing/dependency.json', encoding='utf-8') as a:
        dependency = json.load(a)
    need_download_dependents = set()
    need_download_dependents_github = set()
    for repo in dependency.keys():
        for module in dependency[repo].keys():
            for version in dependency[repo][module].keys():
                if 'vul_info' in dependency[repo][module][version].keys():
                    sign = 0
                    for vul in dependency[repo][module][version]['vul_info']:
                        if vul in need_analysis_vuls:
                            sign = 1
                            break
                    if sign == 1:
                        for dependent in dependency[repo][module][version]['dependents']:
                            need_download_dependents.add(dependent)
                            if str(dependent).startswith('github.com/'):
                                need_download_dependents_github.add(dependent)
    print(len(need_download_dependents), len(need_download_dependents_github))
    f = open('./fault_fixing.txt', 'r')
    dependents_before_2019 = set()
    dependents_2019 = set()
    dependents_2020 = set()
    dependents_2021 = set()
    dependents_2022 = set()
    dependents_2023 = set()
    dependents = set()
    for i in f.read().split('\n'):
        if i == '':
            continue
        if 'not exist go.sum or go.mod' in i:
            if i.split(' ')[0] not in need_download_dependents_github:
                continue
            dependents.add(i.split(' ')[0])
            date = i.split(';')[-1]
            if date < '2019-01-01 00:00:00+08:00':
                dependents_before_2019.add(i.split(' ')[0])
            if '2019-01-01 00:00:00+08:00' <= date < '2020-01-01 00:00:00+08:00':
                dependents_2019.add(i.split(' ')[0])
            if '2020-01-01 00:00:00+08:00' <= date < '2021-01-01 00:00:00+08:00':
                dependents_2020.add(i.split(' ')[0])
            if '2021-01-01 00:00:00+08:00' <= date < '2022-01-01 00:00:00+08:00':
                dependents_2021.add(i.split(' ')[0])
            if '2022-01-01 00:00:00+08:00' <= date < '2023-01-01 00:00:00+08:00':
                dependents_2022.add(i.split(' ')[0])
            if '2023-01-01 00:00:00+08:00' <= date:
                dependents_2023.add(i.split(' ')[0])
    print(len(dependents))
    print(len(dependents_before_2019), len(dependents_2019), len(dependents_2020), len(dependents_2021),
          len(dependents_2022), len(dependents_2023))
    print(len(dependents_before_2019) + len(dependents_2019) + len(dependents_2020) + len(dependents_2021) + len(
        dependents_2022) + len(dependents_2023))


def count_exist_go_sum():
    with open('./go_sum_result_first.json', encoding='utf-8') as a:
        go_sum_result = json.load(a)
    dependents_before_2019 = set()
    dependents_2019 = set()
    dependents_2020 = set()
    dependents_2021 = set()
    dependents_2022 = set()
    dependents_2023 = set()
    dependents = set()
    for i in go_sum_result.keys():
        for j in go_sum_result[i].keys():
            for k in go_sum_result[i][j].keys():
                dependents.add(k)
                date = go_sum_result[i][j][k]['latest_commit_time']
                if date < '2019-01-01 00:00:00+08:00':
                    dependents_before_2019.add(k)
                if '2019-01-01 00:00:00+08:00' <= date < '2020-01-01 00:00:00+08:00':
                    dependents_2019.add(k)
                if '2020-01-01 00:00:00+08:00' <= date < '2021-01-01 00:00:00+08:00':
                    dependents_2020.add(k)
                if '2021-01-01 00:00:00+08:00' <= date < '2022-01-01 00:00:00+08:00':
                    dependents_2021.add(k)
                if '2022-01-01 00:00:00+08:00' <= date < '2023-01-01 00:00:00+08:00':
                    dependents_2022.add(k)
                if '2023-01-01 00:00:00+08:00' <= date:
                    dependents_2023.add(k)
    print(len(dependents))
    print(len(dependents_before_2019), len(dependents_2019), len(dependents_2020), len(dependents_2021),
          len(dependents_2022), len(dependents_2023))
    print(len(dependents_before_2019) + len(dependents_2019) + len(dependents_2020) + len(dependents_2021) + len(
        dependents_2022) + len(dependents_2023))


def dataset_of_rq1():
    with open('./go_sum_result_first.json', encoding='utf-8') as a:
        go_sum_result_first = json.load(a)
    resolve = set()
    vul = set()
    for vul_id in go_sum_result_first.keys():
        if '1' in go_sum_result_first[vul_id].keys():
            resolve = resolve | set(go_sum_result_first[vul_id]['1'].keys())
        if '2' in go_sum_result_first[vul_id].keys():
            resolve = resolve | set(go_sum_result_first[vul_id]['2'].keys())
        if '3' in go_sum_result_first[vul_id].keys():
            vul = vul | set(go_sum_result_first[vul_id]['3'].keys())
    print(len(resolve))
    print(len(vul))
    print(len(vul - resolve))
    print(len(resolve - vul))


def update_wrong_commit_date():
    with open('./go_sum_result.json', encoding='utf-8') as a:
        go_sum_result = json.load(a)
    go_sum_result['1263']['3']['github.com/e1732a364fed/v2ray_simple']['commit_pub_date'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['1263']['3']['github.com/e1732a364fed/v2ray_simple'][
        'latest_commit_time'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['90']['3']['github.com/e1732a364fed/v2ray_simple']['commit_pub_date'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['90']['3']['github.com/e1732a364fed/v2ray_simple'][
        'latest_commit_time'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['91']['2']['github.com/e1732a364fed/v2ray_simple']['commit_pub_date'] = '2022-12-28 17:36:00+08:00'
    go_sum_result['91']['2']['github.com/e1732a364fed/v2ray_simple'][
        'latest_commit_time'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['92']['2']['github.com/e1732a364fed/v2ray_simple']['commit_pub_date'] = '2022-10-26 08:21:00+08:00'
    go_sum_result['92']['2']['github.com/e1732a364fed/v2ray_simple'][
        'latest_commit_time'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['93']['3']['github.com/e1732a364fed/v2ray_simple']['commit_pub_date'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['93']['3']['github.com/e1732a364fed/v2ray_simple'][
        'latest_commit_time'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['345']['2']['github.com/e1732a364fed/v2ray_simple']['commit_pub_date'] = '2022-12-28 17:36:00+08:00'
    go_sum_result['345']['2']['github.com/e1732a364fed/v2ray_simple'][
        'latest_commit_time'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['1103']['2']['github.com/e1732a364fed/v2ray_simple']['commit_pub_date'] = '2022-04-29 19:46:00+08:00'
    go_sum_result['1103']['2']['github.com/e1732a364fed/v2ray_simple'][
        'latest_commit_time'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['1263']['3']['github.com/hahahrfool/v2ray_simple']['commit_pub_date'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['1263']['3']['github.com/hahahrfool/v2ray_simple'][
        'latest_commit_time'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['90']['3']['github.com/hahahrfool/v2ray_simple']['commit_pub_date'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['90']['3']['github.com/hahahrfool/v2ray_simple'][
        'latest_commit_time'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['91']['2']['github.com/hahahrfool/v2ray_simple']['commit_pub_date'] = '2022-12-28 17:36:00+08:00'
    go_sum_result['91']['2']['github.com/hahahrfool/v2ray_simple'][
        'latest_commit_time'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['92']['2']['github.com/hahahrfool/v2ray_simple']['commit_pub_date'] = '2022-10-26 08:21:00+08:00'
    go_sum_result['92']['2']['github.com/hahahrfool/v2ray_simple'][
        'latest_commit_time'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['93']['3']['github.com/hahahrfool/v2ray_simple']['commit_pub_date'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['93']['3']['github.com/hahahrfool/v2ray_simple'][
        'latest_commit_time'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['345']['2']['github.com/hahahrfool/v2ray_simple']['commit_pub_date'] = '2022-12-28 17:36:00+08:00'
    go_sum_result['345']['2']['github.com/hahahrfool/v2ray_simple'][
        'latest_commit_time'] = '2023-01-06 08:55:00+08:00'
    go_sum_result['1103']['2']['github.com/hahahrfool/v2ray_simple']['commit_pub_date'] = '2022-04-29 19:46:00+08:00'
    go_sum_result['1103']['2']['github.com/hahahrfool/v2ray_simple'][
        'latest_commit_time'] = '2023-01-06 08:55:00+08:00'
    f = open('./go_sum_result.json', 'w')
    json.dump(go_sum_result, f)
    f.close()


def count_of_rq1():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    need_analysis_vuls = set()
    query = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        }
    }
    for i in vul_tag_interval_table.find(query):
        need_analysis_vuls.add(i['vul_id'])
    with open('./dependency.json', encoding='utf-8') as a:
        dependency = json.load(a)
    need_download_dependents = set()
    need_download_dependents_github = set()
    for repo in dependency.keys():
        for module in dependency[repo].keys():
            for version in dependency[repo][module].keys():
                if 'vul_info' in dependency[repo][module][version].keys():
                    sign = 0
                    for vul in dependency[repo][module][version]['vul_info']:
                        if vul in need_analysis_vuls:
                            sign = 1
                            break
                    if sign == 1:
                        for dependent in dependency[repo][module][version]['dependents']:
                            need_download_dependents.add(dependent)
                            if str(dependent).startswith('github.com/'):
                                need_download_dependents_github.add(dependent)
    print(len(need_download_dependents), len(need_download_dependents_github))
    with open('./go_sum_result_dependent.json', encoding='utf-8') as a:
        go_sum_result_dependent = json.load(a)
    success_download = set()
    for dependent in go_sum_result_dependent.keys():
        if dependent in need_download_dependents_github:
            success_download.add(dependent)
    print(len(go_sum_result_dependent.keys()), len(success_download))
    with open('./go_sum_result_first.json', encoding='utf-8') as a:
        go_sum_result_first = json.load(a)
    print(len(go_sum_result_first.keys()))
    with open('./go_sum_result_dependent_first.json', encoding='utf-8') as a:
        go_sum_result_dependent_first = json.load(a)
    print(len(go_sum_result_dependent_first.keys()))


def generate_go_sum_result_first():
    with open('./go_sum_result.json', encoding='utf-8') as a:
        go_sum_result = json.load(a)
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    need_analysis_vuls = set()
    query = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        }
    }
    for i in vul_tag_interval_table.find(query):
        need_analysis_vuls.add(i['vul_id'])
    go_sum_result_first = dict()
    for vul_id in go_sum_result.keys():
        if int(vul_id) in need_analysis_vuls:
            go_sum_result_first[vul_id] = go_sum_result[vul_id]
    go_sum_result_dependent_first = dict()
    for vul_id in go_sum_result_first.keys():
        for fixing_sign in go_sum_result_first[vul_id].keys():
            for dependent in go_sum_result_first[vul_id][fixing_sign].keys():
                if dependent not in go_sum_result_dependent_first.keys():
                    go_sum_result_dependent_first[dependent] = {}
                    go_sum_result_dependent_first[dependent]['1'] = {}
                    go_sum_result_dependent_first[dependent]['2'] = {}
                    go_sum_result_dependent_first[dependent]['3'] = {}
                if vul_id not in go_sum_result_dependent_first[dependent][fixing_sign].keys():
                    go_sum_result_dependent_first[dependent][fixing_sign][vul_id] = \
                        go_sum_result_first[vul_id][fixing_sign][dependent]
    f = open('./go_sum_result_first.json', 'w')
    json.dump(go_sum_result_first, f)
    f.close()
    f = open('./go_sum_result_dependent_first.json', 'w')
    json.dump(go_sum_result_dependent_first, f)
    f.close()


def count_rq1_bigquery():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    need_analysis_vuls = set()
    query = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        }
    }
    for i in vul_tag_interval_table.find(query):
        need_analysis_vuls.add(i['vul_id'])
    with open('./dependency.json', encoding='utf-8') as a:
        dependency = json.load(a)
    repos = set()
    for repo in dependency.keys():
        for module in dependency[repo].keys():
            repo_sign = 0
            for version in dependency[repo][module].keys():
                if 'vul_info' in dependency[repo][module][version].keys():
                    for vul in dependency[repo][module][version]['vul_info']:
                        if vul in need_analysis_vuls:
                            repo_sign = 1
                            break
                    if repo_sign == 1:
                        break
            if repo_sign == 0:
                repos.add(repo)
    origin = '../processing/first/'
    big_query = dict()
    link_count = 0
    for file in os.listdir(origin):
        if file.replace('^', '/').replace('.txt', '') in repos:
            continue
        f = open(origin + file, 'r')
        for i in f.read().split('\n'):
            if i == '':
                continue
            temps = i.split(';')
            dependent_name = temps[0].split(',')[0]
            dependent_version = temps[0].split(',')[1]
            # vul_module_name = temps[1].split(',')[0]
            # vul_module_version = temps[1].split(',')[1]
            if dependent_name not in big_query.keys():
                big_query[dependent_name] = {}
            if dependent_version not in big_query[dependent_name].keys():
                big_query[dependent_name][dependent_version] = {}
            link_count = link_count + 1
    print(link_count)
    print(len(big_query.keys()))
    count = 0
    for dependent in big_query.keys():
        count = count + len(big_query[dependent].keys())
    print(count)


def count_of_bigquery_total():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    big_query_table = db['dependencies']
    need_analysis_vuls = set()
    query = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        }
    }
    for i in vul_tag_interval_table.find(query):
        need_analysis_vuls.add(i['vul_id'])
    with open('./dependency.json', encoding='utf-8') as a:
        dependency = json.load(a)
    need_download_dependents = dict()
    for repo in dependency.keys():
        for module in dependency[repo].keys():
            for version in dependency[repo][module].keys():
                if 'vul_info' in dependency[repo][module][version].keys():
                    sign = 0
                    for vul in dependency[repo][module][version]['vul_info']:
                        if vul in need_analysis_vuls:
                            sign = 1
                            break
                    if sign == 1:
                        for dependent in dependency[repo][module][version]['dependents']:
                            if dependent not in need_download_dependents.keys():
                                need_download_dependents[dependent] = {}
                            for dependent_version in dependency[repo][module][version]['dependents'][dependent]:
                                if dependent_version not in need_download_dependents[dependent].keys():
                                    need_download_dependents[dependent][dependent_version] = {}
    total_modules = dict()
    for i in big_query_table.find():
        if i['module_name'] not in total_modules.keys():
            total_modules[i['module_name']] = {}
        if i['module_version'] not in total_modules[i['module_name']].keys():
            total_modules[i['module_name']][i['module_version']] = {}
        if i['dependency_name'] not in total_modules.keys():
            total_modules[i['dependency_name']] = {}
        if i['dependency_version'] not in total_modules[i['dependency_name']].keys():
            total_modules[i['dependency_name']][i['dependency_version']] = {}
    count_1 = 0
    print(len(need_download_dependents.keys()))
    for dependent in need_download_dependents.keys():
        count_1 = count_1 + len(need_download_dependents[dependent].keys())
    print(count_1)
    count_2 = 0
    print(len(total_modules.keys()))
    for dependent in total_modules.keys():
        count_2 = count_2 + len(total_modules[dependent].keys())
    print(count_2)


def figure_of_trend_of_non_fix():
    with open('./go_sum_result_dependent_first.json', encoding='utf-8') as a:
        go_sum_result_dependent_first = json.load(a)
    fix_before_2019 = 0
    fix_2019 = 0
    fix_2020 = 0
    fix_2021 = 0
    fix_2022 = 0
    fix_2023 = 0
    for dependent in go_sum_result_dependent_first.keys():
        if len(go_sum_result_dependent_first[dependent]['1']) > 0 or len(
                go_sum_result_dependent_first[dependent]['2']) > 0:
            date = ''
            for vul in go_sum_result_dependent_first[dependent]['1']:
                if date == '' or date > go_sum_result_dependent_first[dependent]['1'][vul]['commit_pub_date']:
                    date = go_sum_result_dependent_first[dependent]['1'][vul]['commit_pub_date']
            for vul in go_sum_result_dependent_first[dependent]['2']:
                if date == '' or date > go_sum_result_dependent_first[dependent]['2'][vul]['commit_pub_date']:
                    date = go_sum_result_dependent_first[dependent]['2'][vul]['commit_pub_date']
            if date < '2019-01-01 00:00:00+08:00':
                fix_before_2019 = fix_before_2019 + 1
            if '2019-01-01 00:00:00+08:00' <= date < '2020-01-01 00:00:00+08:00':
                fix_2019 = fix_2019 + 1
            if '2020-01-01 00:00:00+08:00' <= date < '2021-01-01 00:00:00+08:00':
                fix_2020 = fix_2020 + 1
            if '2021-01-01 00:00:00+08:00' <= date < '2022-01-01 00:00:00+08:00':
                fix_2021 = fix_2021 + 1
            if '2022-01-01 00:00:00+08:00' <= date < '2023-01-01 00:00:00+08:00':
                fix_2022 = fix_2022 + 1
            if '2023-01-01 00:00:00+08:00' <= date:
                fix_2023 = fix_2023 + 1
    print(fix_before_2019, fix_2019, fix_2020, fix_2021, fix_2022, fix_2023)
    print(len(go_sum_result_dependent_first.keys()))
    print(fix_before_2019 + fix_2019 + fix_2020 + fix_2021 + fix_2022 + fix_2023)


def insert_mongo_many(table, insert_data_dict_list: [dict]):  # 这个性能更好
    """
    往mongodb中插入数据, _id为自增, 注意_id为数值类型
    :param insert_data_dict_list: 插入的数据,例如{"name": "zhang"}
    :param table: 表名
    :return: insert_id
    """
    last_data = table.find_one(sort=[('_id', -1)])  # 取出最后一条数据
    if not last_data:
        insert_origin = 1
        for insert_data_dict in insert_data_dict_list:
            insert_data_dict["_id"] = insert_origin
            insert_origin = insert_origin + 1
    else:
        insert_origin = last_data["_id"] + 1
        for insert_data_dict in insert_data_dict_list:
            insert_data_dict["_id"] = insert_origin
            insert_origin = insert_origin + 1
    table.insert_many(insert_data_dict_list)


def search_golang_repo_stars():
    db = connect_mongodb()
    with open('./go_sum_result_dependent_first.json', encoding='utf-8') as a:
        go_sum_result_dependent_first = json.load(a)
    if 'golang_repo_info' not in db.list_collection_names():
        # 创建集合
        db.create_collection('golang_repo_info')
    golang_table = db['golang_repo_info']
    already = set()
    for i in golang_table.find():
        already.add(i['repo'])
    tokens = ['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', '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',
              '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', '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',
              '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', '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']
    # hjc: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,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
    # hjc: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
    # zm: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
    # hjc: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
    # wyh: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
    # yyc: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
    result = set()
    for dependent in go_sum_result_dependent_first.keys():
        temps = str(dependent).split('/')
        owner = temps[1]
        repo = temps[2]
        result.add(owner + '/' + repo)
    result = result - already
    q = Queue()
    write(q, result)
    for i in range(12):
        p = Process(target=thread_search_golang_repo_stars, args=(q, tokens[int(i / 2)],))
        p.start()


def thread_search_golang_repo_stars(q, token):
    db = connect_mongodb()
    golang_table = db['golang_repo_info']
    url = 'https://api.github.com/repos/'
    repo = read(q)
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    while repo is not None:
        response = requests.get(url + repo, headers=headers)
        data = response.json()
        if 'stargazers_count' not in data.keys():
            print(repo, data)
            if 'message' in data.keys():
                if data['message'] == 'Not Found':
                    new_data = {'repo': repo, 'exist': 'Not Found'}
                    golang_table.insert_one(new_data)
                if 'API rate limit exceeded' in data['message']:
                    time.sleep(60)
            repo = read(q)
            continue
        stars = data['stargazers_count']
        new_data = {'repo': repo, 'stars': stars}
        golang_table.insert_one(new_data)
        repo = read(q)


def analysis_of_rq4():
    with open('./go_sum_result_dependent_first.json', encoding='utf-8') as a:
        go_sum_result_dependent_first = json.load(a)
    repos = set()
    for dependent in go_sum_result_dependent_first.keys():
        if len(str(dependent).split('/')) > 3:
            temps = str(dependent).split('/')
            repo = temps[0] + '/' + temps[1] + '/' + temps[2]
        else:
            repo = dependent
        repos.add(repo)
    print(len(repos))


def rq1_figure_exist_vul():
    with open('./go_sum_result_dependent.json', encoding='utf-8') as a:
        go_sum_result_dependent = json.load(a)
    result = dict()
    pattern = r"\d{4}"
    # matches = re.findall(pattern, string)
    db = connect_mongodb()
    vulnerability_table = db['vulnerabilities_info']
    for i in vulnerability_table.find():
        for vul in i['vul_packages'][0].keys():
            year = re.findall(pattern, i['vul_packages'][0][vul]['publish'])[0]
            if year not in result.keys():
                result[year] = {}
            break
    for year in result.keys():
        result[year]['affect'] = {}
        result[year]['dependents'] = 0
        result[year]['affect_dependents'] = 0
        result[year]['vuls'] = []
        for temp in result.keys():
            if temp < year:
                continue
            if temp not in result[year]['affect'].keys():
                result[year]['affect'][temp] = 0
    for dependent in go_sum_result_dependent.keys():
        generate_year = ''
        temps = set()
        end_year = ''
        for fixing_sign in go_sum_result_dependent[dependent].keys():
            for vul_id in go_sum_result_dependent[dependent][fixing_sign].keys():
                commit_pub_date = go_sum_result_dependent[dependent][fixing_sign][vul_id]['commit_pub_date']
                affect_year = re.findall(pattern, commit_pub_date)[0]
                if end_year != '2023':
                    if fixing_sign == '1' or fixing_sign == '2':
                        if end_year == '' or affect_year > end_year:
                            end_year = affect_year
                    if fixing_sign == '3':
                        end_year = '2023'
                vul_info = vulnerability_table.find_one({'_id': int(vul_id)})
                for vul in vul_info['vul_packages'][0].keys():
                    year = re.findall(pattern, vul_info['vul_packages'][0][vul]['publish'])[0]
                    temps.add(year)
                    if generate_year == '' or year < generate_year:
                        generate_year = year
                    break
        fix_year = ''
        for temp in temps:
            result[temp]['dependents'] += 1
            if fix_year == '' or fix_year < temp:
                fix_year = temp
        result[generate_year]['affect_dependents'] += 1
        for temp in result.keys():
            if temp > fix_year:
                result[temp]['affect_dependents'] -= 1
        for temp in result[generate_year]['affect'].keys():
            if end_year >= temp:
                result[generate_year]['affect'][temp] += 1
    f = open('./fig3_rq1.json', 'w')
    json.dump(result, f)
    f.close()


def rq1_figure_exist_vul_base_vul():
    with open('./go_sum_result.json', encoding='utf-8') as a:
        go_sum_result = json.load(a)
    result = dict()
    pattern = r"\d{4}"
    db = connect_mongodb()
    vulnerability_table = db['vulnerabilities_info']
    for i in vulnerability_table.find():
        for vul in i['vul_packages'][0].keys():
            year = re.findall(pattern, i['vul_packages'][0][vul]['publish'])[0]
            if year not in result.keys():
                result[year] = {}
                result[year]['vuls'] = []
            result[year]['vuls'].append(i['_id'])
            break
    for year in result.keys():
        result[year]['affect'] = {}
        result[year]['affect_dependents'] = 0
        for temp in result.keys():
            if temp < year:
                continue
            if temp not in result[year]['affect'].keys():
                result[year]['affect'][temp] = 0
    for year in result.keys():
        dependents = dict()
        vuls = result[year]['vuls']
        for vul_id in vuls:
            if str(vul_id) not in go_sum_result.keys():
                continue
            for fixing_sign in go_sum_result[str(vul_id)].keys():
                for dependent in go_sum_result[str(vul_id)][fixing_sign].keys():
                    if fixing_sign == '1' or fixing_sign == '2':
                        if dependent not in dependents.keys():
                            dependents[dependent] = \
                                re.findall(pattern,
                                           go_sum_result[str(vul_id)][fixing_sign][dependent]['commit_pub_date'])[
                                    0]
                        else:
                            if dependents[dependent] == '2023':
                                continue
                            temp = \
                                re.findall(pattern,
                                           go_sum_result[str(vul_id)][fixing_sign][dependent]['commit_pub_date'])[
                                    0]
                            if temp > dependents[dependent]:
                                dependents[dependent] = temp
                    else:
                        dependents[dependent] = '2023'
        result[year]['dependents'] = dependents
    f = open('./fig3_rq1_based_vul.json', 'w')
    json.dump(result, f)
    f.close()


def rq1_figure_exist_vul_total_vuls():
    with open('../processing/dependency.json', encoding='utf-8') as a:
        dependencies = json.load(a)
    result = dict()
    pattern = r"\d{4}"
    db = connect_mongodb()
    vulnerability_table = db['vulnerabilities_info']
    for i in vulnerability_table.find():
        for vul in i['vul_packages'][0].keys():
            year = re.findall(pattern, i['vul_packages'][0][vul]['publish'])[0]
            if year not in result.keys():
                result[year] = {}
                result[year]['vuls'] = {}
                result[year]['affect_dependents'] = set()
            if i['repo'] not in result[year]['vuls'].keys():
                result[year]['vuls'][i['repo']] = []
            result[year]['vuls'][i['repo']].append(i['_id'])
            break
    for year in result.keys():
        for repo in result[year]['vuls'].keys():
            for module in dependencies[repo].keys():
                for version in dependencies[repo][module].keys():
                    if 'vul_info' in dependencies[repo][module][version].keys():
                        sign = 0
                        for vul in dependencies[repo][module][version]['vul_info']:
                            if vul in result[year]['vuls'][repo]:
                                sign = 1
                                break
                        if sign == 1:
                            result[year]['affect_dependents'] = result[year]['affect_dependents'] | set(
                                dependencies[repo][module][version]['dependents'].keys())
    dependents = set()
    f = open('./fig3_rq1_total_vuls.json', 'w')
    for year in result.keys():
        dependents = dependents | result[year]['affect_dependents']
        result[year]['affect_dependents'] = list(result[year]['affect_dependents'])
    json.dump(result, f)
    f.close()
    print(len(dependents))


def rq2_normal_period_analysis():
    query = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'fixing_commit_belong_tag_interval': {
            '$exists': True
        }
    }
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    a = 0
    a1 = 0
    a2 = 0
    b = 0
    result = []
    for i in vul_tag_interval_table.find(query):
        if i['fixing_commit_belong_tag_interval'] <= i['max_normal_interval']:
            a = a + 1
            if i['Lag_ver'] > 168:
                a1 = a1 + 1
            else:
                a2 = a2 + 1
        else:
            b = b + 1
            result.append(i)
    sorted_data = sorted(result, key=lambda x: x['Lag_ver'], reverse=True)
    dependents = set()
    c1 = 0
    c2 = 0
    dependents_1 = set()
    dependents_2 = set()
    lag_ver_popularity = dict()
    for i in sorted_data:
        if i['Lag_ver'] > 168:
            c1 = c1 + 1
            dependents_1.add(i['repo'])
            if i['repo'] not in lag_ver_popularity.keys():
                lag_ver_popularity[i['repo']] = {}
                lag_ver_popularity[i['repo']]['vuls'] = {}
            if i['vul_id'] not in lag_ver_popularity[i['repo']]['vuls'].keys():
                lag_ver_popularity[i['repo']]['vuls'][i['vul_id']] = {}
                lag_ver_popularity[i['repo']]['vuls'][i['vul_id']] = i
            print(i)
        else:
            c2 = c2 + 1
            dependents_2.add(i['repo'])
        dependents.add(i['repo'])
    print(a, b)
    print(len(dependents))
    print(c1, c2)
    print(len(dependents_1), len(dependents_2))
    # f = open('./popularity_of_Lag_ver.json', 'w')
    # json.dump(lag_ver_popularity, f)
    # f.close()

    # print(a1, a2)


def dataset_of_fig3_rq1():
    with open('./fig3_rq1_based_vul.json', encoding='utf-8') as a:
        fig3_rq1_based_vul = json.load(a)
    years = list(fig3_rq1_based_vul.keys())
    years.sort()
    dependents = dict()
    dependents_per_year = dict()
    for year in years:
        dependents[year] = set()
    for year in years:
        for dependent in fig3_rq1_based_vul[year]['dependents']:
            for key in dependents.keys():
                if fig3_rq1_based_vul[year]['dependents'][dependent] >= key >= year:
                    dependents[key].add(dependent)
    for year in years:
        dependents_per_year[year] = {}
        for temp in fig3_rq1_based_vul[year]['affect'].keys():
            dependents_per_year[year][temp] = set()
        for dependent in fig3_rq1_based_vul[year]['dependents']:
            for key in dependents_per_year[year].keys():
                if key <= fig3_rq1_based_vul[year]['dependents'][dependent]:
                    dependents_per_year[year][key].add(dependent)
    for year in years:
        print(year, len(dependents[year]))
        affect_years = list(dependents_per_year[year].keys())
        affect_years.sort()
        result = []
        for temp in affect_years:
            result.append(len(dependents_per_year[year][temp]))
        print(result)


def generate_rq1_fig3_dataset():
    with open('./dependency.json', encoding='utf-8') as a:
        dependencies = json.load(a)
    with open('./addition_dependency.json', encoding='utf-8') as a:
        addition_dependencies = json.load(a)
    with open('./addition_vul_modules.json', encoding='utf-8') as a:
        addition_vul_modules = json.load(a)
    addition_result = dict()
    for vul in addition_vul_modules.keys():
        if vul not in addition_result.keys():
            addition_result[vul] = {}
            addition_result[vul]['safe'] = {}
            addition_result[vul]['unsafe'] = {}
        for module in addition_vul_modules[vul].keys():
            if module in addition_dependencies.keys():
                for version in addition_dependencies[module].keys():
                    if version in addition_vul_modules[vul][module]:
                        for dependent in addition_dependencies[module][version].keys():
                            if dependent not in addition_result[vul]['unsafe'].keys():
                                addition_result[vul]['unsafe'][dependent] = []
                            for dependent_version in addition_dependencies[module][version][dependent]:
                                if dependent_version not in addition_result[vul]['unsafe'][dependent]:
                                    addition_result[vul]['unsafe'][dependent].append(dependent_version)
                    else:
                        for dependent in addition_dependencies[module][version].keys():
                            if dependent not in addition_result[vul]['safe'].keys():
                                addition_result[vul]['safe'][dependent] = []
                            for dependent_version in addition_dependencies[module][version][dependent]:
                                if dependent_version not in addition_result[vul]['safe'][dependent]:
                                    addition_result[vul]['safe'][dependent].append(dependent_version)
    f = open('./addition_rq1_dataset.json', 'w')
    json.dump(addition_result, f)
    f.close()
    result = dict()
    for repo in dependencies.keys():
        vuls = []
        for module in dependencies[repo].keys():
            for version in dependencies[repo][module].keys():
                if 'vul_info' in dependencies[repo][module][version].keys():
                    for vul in dependencies[repo][module][version]['vul_info']:
                        if vul not in vuls:
                            vuls.append(vul)
        for vul in vuls:
            if str(vul) not in result.keys():
                result[str(vul)] = {}
                result[str(vul)]['safe'] = {}
                result[str(vul)]['unsafe'] = {}
            for module in dependencies[repo].keys():
                for version in dependencies[repo][module].keys():
                    if 'vul_info' in dependencies[repo][module][version].keys():
                        if vul in dependencies[repo][module][version]['vul_info']:
                            for dependent in dependencies[repo][module][version]['dependents']:
                                if dependent not in result[str(vul)]['unsafe'].keys():
                                    result[str(vul)]['unsafe'][dependent] = []
                                for dependent_version in dependencies[repo][module][version]['dependents'][dependent]:
                                    if dependent_version not in result[str(vul)]['unsafe'][dependent]:
                                        result[str(vul)]['unsafe'][dependent].append(dependent_version)
                        else:
                            for dependent in dependencies[repo][module][version]['dependents']:
                                if dependent not in result[str(vul)]['safe'].keys():
                                    result[str(vul)]['safe'][dependent] = []
                                for dependent_version in dependencies[repo][module][version]['dependents'][dependent]:
                                    if dependent_version not in result[str(vul)]['safe'][dependent]:
                                        result[str(vul)]['safe'][dependent].append(dependent_version)
    f = open('./rq1_dataset.json', 'w')
    json.dump(result, f)
    f.close()


def rq1_fig3_add_vuls_dataset():
    with open('./addition_rq1_dataset.json', encoding='utf-8') as a:
        addition_rq1_dataset = json.load(a)
    with open('./rq1_dataset.json', encoding='utf-8') as a:
        rq1_dataset = json.load(a)
    db = connect_mongodb()
    vulnerability_table = db['vulnerabilities_info']
    pattern_one = r"\d{4}"
    pattern_two = r"-\d{4}-"
    result = dict()
    count = 0
    total = len(rq1_dataset.keys())
    for vul in rq1_dataset.keys():
        count += 1
        print('origin: ' + str(count) + '/' + str(total))
        vul_info = vulnerability_table.find_one({'_id': int(vul)})
        year = ''
        for package in vul_info['vul_packages'][0].keys():
            year = re.findall(pattern_one, vul_info['vul_packages'][0][package]['publish'])[0]
            if year not in result.keys():
                result[year] = {}
                result[year]['total'] = {}
                result[year]['remove_fix'] = {}
            break
        for dependent in rq1_dataset[vul]['unsafe']:
            if dependent not in result[year]['total'].keys():
                result[year]['total'][dependent] = set()
            result[year]['total'][dependent] = result[year]['total'][dependent] | \
                                               set(rq1_dataset[vul]['unsafe'][dependent])
            if dependent not in rq1_dataset[vul]['safe']:
                if dependent not in result[year]['remove_fix'].keys():
                    result[year]['remove_fix'][dependent] = set()
                result[year]['remove_fix'][dependent] = result[year]['remove_fix'][dependent] | \
                                                        set(rq1_dataset[vul]['unsafe'][dependent])
    count = 0
    total = len(addition_rq1_dataset.keys())
    for vul in addition_rq1_dataset.keys():
        count += 1
        print('addition: ' + str(count) + '/' + str(total))
        if not vulnerability_table.find_one({'cve': vul}):
            temps = re.findall(pattern_two, vul)
            if len(temps) == 0:
                continue
            year = re.findall(pattern_two, vul)[0].replace('-', '')
            if year not in result.keys():
                result[year] = {}
                result[year]['total'] = {}
                result[year]['remove_fix'] = {}
            for dependent in addition_rq1_dataset[vul]['unsafe']:
                if dependent not in result[year]['total'].keys():
                    result[year]['total'][dependent] = set()
                result[year]['total'][dependent] = result[year]['total'][dependent] | \
                                                   set(addition_rq1_dataset[vul]['unsafe'][dependent])
                if dependent not in addition_rq1_dataset[vul]['safe']:
                    if dependent not in result[year]['remove_fix'].keys():
                        result[year]['remove_fix'][dependent] = set()
                    result[year]['remove_fix'][dependent] = result[year]['remove_fix'][dependent] | \
                                                            set(addition_rq1_dataset[vul]['unsafe'][dependent])
    for year in result.keys():
        for key in result[year].keys():
            for dependent in result[year][key].keys():
                result[year][key][dependent] = list(result[year][key][dependent])
    f = open('./rq1_fig3_dataet_2023_7_17.json', 'w')
    json.dump(result, f)
    f.close()


def rq2_normal_period_analysis_star_research():
    with open('./popularity_of_Lag_ver.json', encoding='utf-8') as a:
        popularity_of_Lag_ver = json.load(a)
    for dependent in popularity_of_Lag_ver.keys():
        token = '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'
        url = 'https://api.github.com/repos/'
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        popularity_of_Lag_ver[dependent]['stars'] = ''
        popularity_of_Lag_ver[dependent]['latest_commit_time'] = ''
        response = requests.get(url + str(dependent).replace('github.com/', ''), headers=headers)
        data = response.json()
        if 'stargazers_count' not in data.keys():
            continue
        stars = data['stargazers_count']
        latest_commit_time = data['pushed_at']
        popularity_of_Lag_ver[dependent]['stars'] = stars
        popularity_of_Lag_ver[dependent]['latest_commit_time'] = latest_commit_time
    f = open('./popularity_of_Lag_ver.json', 'w')
    json.dump(popularity_of_Lag_ver, f)
    f.close()


def rq2_normal_period_analysis_stars_result():
    with open('./popularity_of_Lag_ver.json', encoding='utf-8') as a:
        popularity_of_Lag_ver = json.load(a)
    with open('./go_sum_result.json', encoding='utf-8') as a:
        go_sum_result = json.load(a)
    result = []
    for dependent in popularity_of_Lag_ver.keys():
        result.append({'repo': dependent, 'stars': popularity_of_Lag_ver[dependent]['stars'],
                       'latest_commit_time': popularity_of_Lag_ver[dependent]['latest_commit_time']})
    sorted_data = sorted(result, key=lambda x: x['stars'], reverse=True)
    popularity_of_Lag_ver_result = dict()
    for i in sorted_data:
        popularity_of_Lag_ver_result[i['repo']] = {}
        popularity_of_Lag_ver_result[i['repo']]['stars'] = i['stars']
        popularity_of_Lag_ver_result[i['repo']]['latest_commit_time'] = i['latest_commit_time']
        count = 0
        max_normal_interval = 0
        popularity_of_Lag_ver_result[i['repo']]['vuls'] = {}
        for vul in popularity_of_Lag_ver[i['repo']]['vuls'].keys():
            if vul in go_sum_result.keys():
                pseudo_count = 0
                dependents = set()
                if '2' in go_sum_result[vul].keys():
                    for dependent in go_sum_result[vul]['2'].keys():
                        if is_pseudo_version(go_sum_result[vul]['2'][dependent]['fixing_version']):
                            pseudo_count += 1
                for fixing_sign in go_sum_result[vul].keys():
                    for dependent in go_sum_result[vul][fixing_sign].keys():
                        dependents.add(dependent)
                popularity_of_Lag_ver_result[i['repo']]['vuls'][vul] = {}
                popularity_of_Lag_ver_result[i['repo']]['vuls'][vul]['pseudo_count'] = pseudo_count
                popularity_of_Lag_ver_result[i['repo']]['vuls'][vul]['dependent_count'] = len(dependents)
            count += popularity_of_Lag_ver[i['repo']]['vuls'][vul]['Lag_ver']
            max_normal_interval = popularity_of_Lag_ver[i['repo']]['vuls'][vul]['max_normal_interval']
        average_lag_ver = count / (len(popularity_of_Lag_ver[i['repo']]['vuls'].keys()))
        popularity_of_Lag_ver_result[i['repo']]['average_lag_ver'] = average_lag_ver
        popularity_of_Lag_ver_result[i['repo']]['max_normal_interval'] = max_normal_interval
    f = open('./popularity_of_Lag_ver_result.json', 'w')
    json.dump(popularity_of_Lag_ver_result, f)
    f.close()


def rq2_no_t_index_analysis():
    query = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_index': {
            '$eq': ''
        }
    }
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    result = []
    lag_index_popularity = dict()
    for i in vul_tag_interval_table.find(query):
        result.append(i)
    for i in result:
        if i['repo'] not in lag_index_popularity.keys():
            lag_index_popularity[i['repo']] = {}
            lag_index_popularity[i['repo']]['vuls'] = {}
        if i['vul_id'] not in lag_index_popularity[i['repo']]['vuls'].keys():
            lag_index_popularity[i['repo']]['vuls'][i['vul_id']] = {}
            lag_index_popularity[i['repo']]['vuls'][i['vul_id']] = i
    f = open('./popularity_of_Lag_index.json', 'w')
    json.dump(lag_index_popularity, f)
    f.close()


def rq2_no_t_index_analysis_star_research():
    with open('./popularity_of_Lag_index.json', encoding='utf-8') as a:
        popularity_of_Lag_index = json.load(a)
    for dependent in popularity_of_Lag_index.keys():
        token = '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'
        url = 'https://api.github.com/repos/'
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        popularity_of_Lag_index[dependent]['stars'] = ''
        popularity_of_Lag_index[dependent]['latest_commit_time'] = ''
        response = requests.get(url + str(dependent).replace('github.com/', ''), headers=headers)
        data = response.json()
        if 'stargazers_count' not in data.keys():
            continue
        stars = data['stargazers_count']
        latest_commit_time = data['pushed_at']
        popularity_of_Lag_index[dependent]['stars'] = stars
        popularity_of_Lag_index[dependent]['latest_commit_time'] = latest_commit_time
    f = open('./popularity_of_Lag_index.json', 'w')
    json.dump(popularity_of_Lag_index, f)
    f.close()


def rq2_no_t_index_analysis_stars_result():
    with open('./popularity_of_Lag_index.json', encoding='utf-8') as a:
        popularity_of_Lag_index = json.load(a)
    with open('./go_sum_result.json', encoding='utf-8') as a:
        go_sum_result = json.load(a)
    result = []
    for dependent in popularity_of_Lag_index.keys():
        result.append({'repo': dependent})
    popularity_of_Lag_index_result = dict()
    dependents_total = set()
    fix_dependents_pseudo = set()
    fix_dependents_tag = set()
    for i in result:
        popularity_of_Lag_index_result[i['repo']] = {}
        # popularity_of_Lag_index_result[i['repo']]['stars'] = i['stars']
        # popularity_of_Lag_index_result[i['repo']]['latest_commit_time'] = i['latest_commit_time']
        popularity_of_Lag_index_result[i['repo']]['vuls'] = {}
        for vul in popularity_of_Lag_index[i['repo']]['vuls'].keys():
            if vul in go_sum_result.keys():
                pseudo_count = 0
                dependents = set()
                if '2' in go_sum_result[vul].keys():
                    for dependent in go_sum_result[vul]['2'].keys():
                        if is_pseudo_version(go_sum_result[vul]['2'][dependent]['fixing_version']):
                            pseudo_count += 1
                            fix_dependents_pseudo.add(dependent)
                        else:
                            fix_dependents_tag.add(dependent)
                for fixing_sign in go_sum_result[vul].keys():
                    for dependent in go_sum_result[vul][fixing_sign].keys():
                        dependents.add(dependent)
                        dependents_total.add(dependent)
                popularity_of_Lag_index_result[i['repo']]['vuls'][vul] = {}
                popularity_of_Lag_index_result[i['repo']]['vuls'][vul]['pseudo_count'] = pseudo_count
                popularity_of_Lag_index_result[i['repo']]['vuls'][vul]['dependent_count'] = len(dependents)
    print(len(dependents_total), len(fix_dependents_pseudo), len(fix_dependents_tag))
    f = open('./popularity_of_Lag_index_result.json', 'w')
    json.dump(popularity_of_Lag_index_result, f)
    f.close()


def rq3_calculate_portion_of_fixing_sign():
    with open('./go_sum_result_first.json', encoding='utf-8') as a:
        go_sum_result_first = json.load(a)
    with open('./go_sum_result_dependent_first.json', encoding='utf-8') as a:
        go_sum_result_dependent_first = json.load(a)
    count = 0
    count_1 = 0
    count_2 = 0
    count_3 = 0
    count_4 = 0
    for vul in go_sum_result_first.keys():
        for fixing_sign in go_sum_result_first[vul].keys():
            count += len(go_sum_result_first[vul][fixing_sign].keys())
            if fixing_sign == '1':
                count_1 += len(go_sum_result_first[vul][fixing_sign].keys())
            if fixing_sign == '2':
                for dependent in go_sum_result_first[vul][fixing_sign].keys():
                    if is_pseudo_version(go_sum_result_first[vul][fixing_sign][dependent]['fixing_version']):
                        count_2 += 1
                    else:
                        count_3 += 1
            if fixing_sign == '3':
                count_4 += len(go_sum_result_first[vul][fixing_sign].keys())
    print(count)
    print(count_1, count_2, count_3, count_4)
    print(count_2 + count_3)


def convert_utc_vul_tag_index(time_str):
    dt = datetime.fromisoformat(time_str)
    utc_dt = dt.astimezone(timezone.utc)
    return utc_dt


def req3_calculate_proportion_of_t_fix_index_dept():
    result = dict()
    result['before_fix'] = {}
    result['between_fix_index'] = {}
    result['within_index_one_month'] = {}
    result['after_index_one_month'] = {}
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    with open('./go_sum_result_first.json', encoding='utf-8') as a:
        go_sum_result_first = json.load(a)
    for key in result.keys():
        result[key]['remove'] = 0
        result[key]['update'] = 0
        result[key]['update_pseudo'] = 0
        result[key]['update_patch_version'] = 0
        result[key]['exist'] = 0
    for vul in go_sum_result_first.keys():
        vul_tag_interval = vul_tag_interval_table.find_one({'vul_id': int(vul)})
        # if vul_tag_interval['T_index'] == '':
        #     a += 1
        #     continue
        t_fix = convert_utc_vul_tag_index(vul_tag_interval['T_fix'])
        if vul_tag_interval['T_index'] == '':
            t_index = ''
            t_index_one_month = ''
        else:
            t_index = convert_utc_vul_tag_index(vul_tag_interval['T_index'])
            t_index_one_month = t_index + relativedelta(months=1)
        for fixing_sign in go_sum_result_first[vul].keys():
            for dependent in go_sum_result_first[vul][fixing_sign].keys():
                commit_date = convert_utc_vul_tag_index(
                    go_sum_result_first[vul][fixing_sign][dependent]['commit_pub_date'])
                if commit_date < t_fix:
                    sign = 'before_fix'
                else:
                    if t_index == '':
                        sign = 'between_fix_index'
                    else:
                        if commit_date < t_index:
                            sign = 'between_fix_index'
                        else:
                            if commit_date < t_index_one_month:
                                sign = 'within_index_one_month'
                            else:
                                sign = 'after_index_one_month'
                if fixing_sign == '1':
                    result[sign]['remove'] += 1
                if fixing_sign == '2':
                    result[sign]['update'] += 1
                    if is_pseudo_version(go_sum_result_first[vul][fixing_sign][dependent]['fixing_version']):
                        result[sign]['update_pseudo'] += 1
                    else:
                        if sign == 'before_fix':
                            print(vul_tag_interval['repo'], dependent, vul_tag_interval['T_index'],
                                  go_sum_result_first[vul][fixing_sign][dependent]['fixing_version'],
                                  go_sum_result_first[vul][fixing_sign][dependent]['commit_id'],
                                  go_sum_result_first[vul][fixing_sign][dependent]['commit_pub_date'])
                        result[sign]['update_patch_version'] += 1
                if fixing_sign == '3':
                    result[sign]['exist'] += 1
    f = open('./rq3_proportion_t_fix_index_dept.json', 'w')
    json.dump(result, f)
    f.close()


def update_no_t_index_fault():
    db = connect_mongodb()
    index_table = db['golang_index']
    vul_tag_interval_table = db['vul_tag_interval']
    fix_tag_index_table = db['fix_tag_index_info']
    for i in vul_tag_interval_table.find({'T_index': {'$ne': ''}, 'T_ver': {'$ne': ''}, 'Lag_ver': {'$ne': ''}}):
        t_ver = datetime.strptime(i['T_ver'].split('+00')[0], '%Y-%m-%d %H:%M:%S')
        lag_index = ''
        if i['T_index'] != '':
            t_index = datetime.strptime(i['T_index'].split('.')[0], '%Y-%m-%d %H:%M:%S')
            lag_index = (t_index - t_ver).total_seconds() / 60 / 60
        new_data = {"$set": {'Lag_index': lag_index}}
        query = {'_id': i['_id']}
        vul_tag_interval_table.update_one(query, new_data)


def median(lst):
    sorted_lst = sorted(lst)
    n = len(sorted_lst)
    if n % 2 == 1:
        # 列表长度为奇数
        return sorted_lst[n // 2]
    else:
        # 列表长度为偶数
        mid1 = sorted_lst[n // 2 - 1]
        mid2 = sorted_lst[n // 2]
        return (mid1 + mid2) / 2


def rq2_no_t_index_reason():
    with open('./popularity_of_Lag_index_result.json', encoding='utf-8') as a:
        popularity_of_Lag_index_result = json.load(a)
    a = 0
    b = 0
    c = 0
    result_total = []
    result_pseudo = []
    for repo in popularity_of_Lag_index_result.keys():
        if len(popularity_of_Lag_index_result[repo]['vuls'].keys()) > 0:
            b += 1
        for vul in popularity_of_Lag_index_result[repo]['vuls'].keys():
            c += 1
            result_total.append(popularity_of_Lag_index_result[repo]['vuls'][vul]['dependent_count'])
            if popularity_of_Lag_index_result[repo]['vuls'][vul]['pseudo_count'] > 0:
                a += 1
                result_pseudo.append(popularity_of_Lag_index_result[repo]['vuls'][vul]['pseudo_count'])
            print(repo, popularity_of_Lag_index_result[repo]['vuls'][vul]['pseudo_count'],
                  popularity_of_Lag_index_result[repo]['vuls'][vul]['dependent_count'])
    print(a, b, c, len(popularity_of_Lag_index_result.keys()))
    print(median(result_total))
    print(median(result_pseudo))


def generate_snapsho_at_bigquery():
    db = connect_mongodb()
    dependency_table = db['dependencies']
    result = dict()
    for i in dependency_table.find():
        if i['snapshot_at'] not in result.keys():
            result[i['snapshot_at']] = {}
        if i['module_name'] not in result[i['snapshot_at']].keys():
            result[i['snapshot_at']][i['module_name']] = set()
        result[i['snapshot_at']][i['module_name']].add(i['module_version'])
    for snapshot_at in result.keys():
        for module in result[snapshot_at].keys():
            result[snapshot_at][module] = list(result[snapshot_at][module])
    f = open('./snapshot_at_bigquery.json', 'w')
    json.dump(result, f)
    f.close()


def count_no_t_index_by_dependents():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    result = []
    query = {
        'Lag_ver': {
            '$ne': ''
        },
        'Lag_index': ''
        # 'cve': {
        #     '$eq': ''
        # }
    }
    with open('../processing/dependency.json', encoding='utf-8') as a:
        dependencies = json.load(a)
    for vul_tag in vul_tag_interval_table.find(query):
        vul_id = vul_tag['vul_id']
        repo = vul_tag['repo']
        vul_dependents = set()
        for module in dependencies[repo].keys():
            for version in dependencies[repo][module].keys():
                if 'vul_info' in dependencies[repo][module][version].keys():
                    if vul_id in dependencies[repo][module][version]['vul_info']:
                        if 'dependents' in dependencies[repo][module][version].keys():
                            vul_dependents = vul_dependents | set(
                                dependencies[repo][module][version]['dependents'].keys())
        vul_tag['dependents_count'] = len(vul_dependents)
        result.append(vul_tag)
    sorted_data = sorted(result, key=lambda x: x['dependents_count'], reverse=True)
    temp = dict()
    for i in sorted_data:
        if i['repo'] not in temp.keys():
            temp[i['repo']] = {}
            temp[i['repo']]['repo'] = i['repo']
            temp[i['repo']]['vuls'] = []
            temp[i['repo']]['dependents_count'] = 0

        if i['cve'] != '':
            temp[i['repo']]['vuls'].append(i['cve'])
        if i['cve'] == '':
            temp[i['repo']]['vuls'].append(i['cwe'])
        if i['dependents_count'] > temp[i['repo']]['dependents_count']:
            temp[i['repo']]['dependents_count'] = i['dependents_count']
    result = []
    for repo in temp.keys():
        result.append(temp[repo])
    sorted_data = sorted(result, key=lambda x: x['dependents_count'], reverse=True)
    print(len(sorted_data))
    a = 0
    for i in sorted_data:
        if i['dependents_count'] > 0:
            a += len(i['vuls'])
        print(i['repo'], ', '.join(i['vuls']), i['dependents_count'])
    print(a)


def generate_after_2019_vul_dependent_graph():
    db = connect_mongodb()
    vulnerability_table = db['vulnerabilities_info']
    with open('./golang_index.json', encoding='utf-8') as a:
        golang_index = json.load(a)
    with open('./rq1_dataset.json', encoding='utf-8') as a:
        rq1_dataset = json.load(a)
    result = dict()
    pattern_one = r"\d{4}"
    pattern_two = r"-\d{4}-"
    for vul in rq1_dataset.keys():
        vul_info = vulnerability_table.find_one({'_id': int(vul)})
        year = ''
        for package in vul_info['vul_packages'][0].keys():
            year = re.findall(pattern_one, vul_info['vul_packages'][0][package]['publish'])[0]
            break
        if year < '2020':
            result[vul] = {}
            result[vul]['safe'] = {}
            result[vul]['unsafe'] = {}
            for dependent in rq1_dataset[vul]['safe'].keys():
                result[vul]['safe'][dependent] = {}
                for version in rq1_dataset[vul]['safe'][dependent]:
                    result[vul]['safe'][dependent][version] = 'none'
                    if dependent in golang_index.keys():
                        if version in golang_index[dependent].keys():
                            result[vul]['safe'][dependent][version] = golang_index[dependent][version]
            for dependent in rq1_dataset[vul]['unsafe'].keys():
                result[vul]['unsafe'][dependent] = {}
                for version in rq1_dataset[vul]['unsafe'][dependent]:
                    result[vul]['unsafe'][dependent][version] = 'none'
                    if dependent in golang_index.keys():
                        if version in golang_index[dependent].keys():
                            result[vul]['unsafe'][dependent][version] = golang_index[dependent][version]
    del rq1_dataset
    with open('./addition_rq1_dataset.json', encoding='utf-8') as a:
        addition_rq1_dataset = json.load(a)
    for vul in addition_rq1_dataset.keys():
        temps = re.findall(pattern_two, vul)
        if len(temps) == 0:
            continue
        year = re.findall(pattern_two, vul)[0].replace('-', '')
        if year < '2019':
            result[vul] = {}
            result[vul]['safe'] = {}
            result[vul]['unsafe'] = {}
            for dependent in addition_rq1_dataset[vul]['safe'].keys():
                result[vul]['safe'][dependent] = {}
                for version in addition_rq1_dataset[vul]['safe'][dependent]:
                    result[vul]['safe'][dependent][version] = 'none'
                    if dependent in golang_index.keys():
                        if version in golang_index[dependent].keys():
                            result[vul]['safe'][dependent][version] = golang_index[dependent][version]
            for dependent in addition_rq1_dataset[vul]['unsafe'].keys():
                result[vul]['unsafe'][dependent] = {}
                for version in addition_rq1_dataset[vul]['unsafe'][dependent]:
                    result[vul]['unsafe'][dependent][version] = 'none'
                    if dependent in golang_index.keys():
                        if version in golang_index[dependent].keys():
                            result[vul]['unsafe'][dependent][version] = golang_index[dependent][version]
    del addition_rq1_dataset
    f = open('./before_2019_vuls_fig.json', 'w')
    json.dump(result, f)
    f.close()


def generate_before_2019_vuls_fig_dataset():
    with open('./before_2019_vuls_fig.json', encoding='utf-8') as a:
        before_2019_vuls_fig = json.load(a)
    result = dict()
    pattern = r"\d{4}-"
    for vul in before_2019_vuls_fig.keys():
        result[vul] = {}
        result[vul]['safe'] = {}
        result[vul]['unsafe'] = {}
        for dependent in before_2019_vuls_fig[vul]['safe'].keys():
            fix_time = 'none'
            for version in before_2019_vuls_fig[vul]['safe'][dependent].keys():
                if fix_time == 'none' or fix_time > before_2019_vuls_fig[vul]['safe'][dependent][version]:
                    fix_time = before_2019_vuls_fig[vul]['safe'][dependent][version]
            if fix_time != 'none':
                year = re.findall(pattern, fix_time)[0].replace('-', '')
                if year not in result[vul]['safe'].keys():
                    result[vul]['safe'][year] = set()
                result[vul]['safe'][year].add(dependent)
        for dependent in before_2019_vuls_fig[vul]['unsafe'].keys():
            fix_time = 'none'
            for version in before_2019_vuls_fig[vul]['unsafe'][dependent].keys():
                if fix_time == 'none' or fix_time > before_2019_vuls_fig[vul]['unsafe'][dependent][version]:
                    fix_time = before_2019_vuls_fig[vul]['unsafe'][dependent][version]
            if fix_time != 'none':
                year = re.findall(pattern, fix_time)[0].replace('-', '')
                if year not in result[vul]['unsafe'].keys():
                    result[vul]['unsafe'][year] = set()
                result[vul]['unsafe'][year].add(dependent)
    for vul in result.keys():
        for sign in result[vul].keys():
            for year in result[vul][sign].keys():
                result[vul][sign][year] = list(result[vul][sign][year])
    f = open('./before_2019_vuls_fig_dataset.json', 'w')
    json.dump(result, f)
    f.close()


def rq1_fig2():
    with open('./before_2019_vuls_fig_dataset.json', encoding='utf-8') as a:
        before_2019_vuls_fig_dataset = json.load(a)
    years = ['2019', '2020', '2021', '2022', '2023']
    for vul in before_2019_vuls_fig_dataset.keys():
        before_2019_vuls_fig_dataset[vul]['affect'] = set()
        before_2019_vuls_fig_dataset[vul]['retain_affect'] = set()
    clean_dependents = set()
    for year in years:
        retain_dependents = set()
        affect_dependents = set()
        safe_dependents = set()
        for vul in before_2019_vuls_fig_dataset.keys():
            if year in before_2019_vuls_fig_dataset[vul]['unsafe'].keys():
                before_2019_vuls_fig_dataset[vul]['affect'] = before_2019_vuls_fig_dataset[vul]['affect'] | set(
                    before_2019_vuls_fig_dataset[vul]['unsafe'][year])
                before_2019_vuls_fig_dataset[vul]['retain_affect'] = before_2019_vuls_fig_dataset[vul][
                                                                         'retain_affect'] | set(
                    before_2019_vuls_fig_dataset[vul]['unsafe'][year])
            if year in before_2019_vuls_fig_dataset[vul]['safe'].keys():
                before_2019_vuls_fig_dataset[vul]['retain_affect'] = before_2019_vuls_fig_dataset[vul][
                                                                         'retain_affect'] - set(
                    before_2019_vuls_fig_dataset[vul]['safe'][year])
                safe_dependents = safe_dependents | set(before_2019_vuls_fig_dataset[vul]['safe'][year])
            affect_dependents = affect_dependents | before_2019_vuls_fig_dataset[vul]['affect']
            retain_dependents = retain_dependents | before_2019_vuls_fig_dataset[vul]['retain_affect']
        for dependent in safe_dependents:
            if dependent not in retain_dependents:
                clean_dependents.add(dependent)
        print(year, len(retain_dependents), len(affect_dependents) - len(retain_dependents))
        print(year, len(retain_dependents), len(clean_dependents))


def rq4_patch_version_delay():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    query = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'fixing_commit_belong_tag_interval': {
            '$exists': True
        },
        'max_normal_interval': {
            '$exists': True
        },
        'cve': {
            '$ne': ''
        },
        'T_index': {
            '$ne': ''
        }
    }
    result = []
    for i in vul_tag_interval_table.find(query):
        if i['fixing_commit_belong_tag_interval'] <= i['max_normal_interval'] and i['Lag_ver'] > 720:
            print(str(i['vul_id']) + ',' + i['repo'] + ',' + i['cve'] + ', T_fix:' + i['T_fix'] + ', T_ver:' + i[
                'T_ver'] + ',' + str(i['Lag_ver']))
            result.append(i)
    repos = set()
    for i in result:
        repos.add(i['repo'])
    print(len(repos))


def dependent_info_by_repo_name(repo_name):
    print('github.com/' + repo_name)
    f = open('./test.txt', 'r')
    already = f.read().split('\n')
    for i in already:
        if '/' + repo_name.split('/')[-1] in i:
            print(i)
    db = connect_mongodb()
    vulnerability_table = db['vulnerabilities_info']
    fix_tag_index_table = db['fix_tag_index_info']
    with open('./go_sum_result_dependent_first.json', encoding='utf-8') as a:
        go_sum_result_dependent_first = json.load(a)
    if 'github.com/' + repo_name in go_sum_result_dependent_first.keys():
        if '3' in go_sum_result_dependent_first['github.com/' + repo_name].keys():
            for vul in go_sum_result_dependent_first['github.com/' + repo_name]['3'].keys():
                print(go_sum_result_dependent_first['github.com/' + repo_name]['3'][vul])
                info = vulnerability_table.find_one({'_id': int(vul)})
                fix_tag_index = fix_tag_index_table.find_one({'repo': info['repo']})
                print(fix_tag_index['vuls'][str(info['_id'])]['patch_tag']['tag'])
                print(info['_id'], info['repo'], info['cve'])
                for package in info['vul_packages']:
                    print(package)
                print('*******************')


def non_patch_version():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    query = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_ver': {
            '$eq': ''
        }
    }
    repos = set()
    for i in vul_tag_interval_table.find(query):
        repos.add(i['repo'])
    print(len(repos))


def non_patch_index():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    query = {
        'T_fix': {
            '$gte': '2019-04-10 00:00:00+00:00'
        },
        'T_index': {
            '$eq': ''
        }
    }
    repos = set()
    for i in vul_tag_interval_table.find(query):
        repos.add(i['repo'])
    print(len(repos))


def vul_repo_stars():
    db = connect_mongodb()
    golang_repo_table = db['golang_repo_info']
    repos = set()
    for i in golang_repo_table.find(sort=[('stars', -1)]):
        repos.add(i['repo'])
    print(len(repos))


def write(q, needs):
    for value in needs:
        q.put(value)


def read(q):
    if q.qsize() > 0:
        value = q.get(True)
        return value
    else:
        return None


def find_merge_commit():
    db = connect_mongodb()
    fix_tag_index_table = db['fix_tag_index_info']
    commits_table = db['commits_info_new']
    repo_table = db['repo_info']
    patches_table = db['patches_info']
    count = 0
    for fix_tag_index in fix_tag_index_table.find():
        repo_info = repo_table.find_one({'repo': fix_tag_index['repo']})
        query = {'repo_id': repo_info['_id']}
        temps = commits_table.find(query)
        commits = dict()
        for temp in temps:
            commits.update(temp['commits'])
        for vul in fix_tag_index['vuls'].keys():
            if 'merge_commit' in fix_tag_index['vuls'][vul].keys():
                print('*', fix_tag_index['_id'], vul)
                continue
            print(fix_tag_index['_id'], vul)
            patches_info = patches_table.find_one({'vul_id': int(vul)})
            if len(patches_info['final_fixing_commits']) == 0:
                continue
            earliest_commit = ''
            for fixing_commit in patches_info['final_fixing_commits']:
                if earliest_commit == '':
                    earliest_commit = fixing_commit['commit_id']
                else:
                    if commits[fixing_commit['commit_id']]['publish_time'] < commits[earliest_commit]['publish_time']:
                        earliest_commit = fixing_commit['commit_id']
            count = count + 1
            temp_commit = earliest_commit
            merge_commit = ''
            sign = 0
            while True:
                if len(commits[temp_commit]['fathers']) > 1:
                    if temp_commit == earliest_commit:
                        sign = 1
                    merge_commit = temp_commit
                    break
                if len(commits[temp_commit]['sons']) < 1 or len(commits[temp_commit]['sons']) > 1:
                    break
                temp_commit = commits[temp_commit]['sons'][0]
            if merge_commit == '':
                continue
            merge_count = -1
            tag_commit = ''
            tags_info = repo_info['tags']
            bifurcate = Queue()
            if sign == 1:
                bifurcate.put([merge_commit, -1])
            else:
                bifurcate.put([merge_commit, 0])
            temp = read(bifurcate)
            already = set()
            while temp:
                temp_commit = temp[0]
                temp_merge_count = temp[1]
                while True:
                    if temp_commit in already:
                        break
                    if len(commits[temp_commit]['fathers']) > 1:
                        temp_merge_count = temp_merge_count + 1
                        already.add(temp_commit)
                    if temp_commit in tags_info.keys():
                        if merge_count == -1 or merge_count > temp_merge_count:
                            merge_count = temp_merge_count
                            tag_commit = temp_commit
                        break
                    if len(commits[temp_commit]['sons']) < 1:
                        break
                    if len(commits[temp_commit]['sons']) > 1:
                        for son in commits[temp_commit]['sons']:
                            bifurcate.put([son, temp_merge_count])
                        break
                    temp_commit = commits[temp_commit]['sons'][0]
                temp = read(bifurcate)
            fix_tag_index['vuls'][vul]['merge_commit'] = dict()
            fix_tag_index['vuls'][vul]['merge_commit']['commit_id'] = merge_commit
            fix_tag_index['vuls'][vul]['merge_commit']['publish_time'] = str(
                convert_to_utc(commits[merge_commit]['publish_time']))
            fix_tag_index['vuls'][vul]['merge_commit']['tag_commit_id'] = tag_commit
            if tag_commit != '':
                fix_tag_index['vuls'][vul]['merge_commit']['tag'] = tags_info[tag_commit]['tag']
            else:
                fix_tag_index['vuls'][vul]['merge_commit']['tag'] = ''
            fix_tag_index['vuls'][vul]['merge_commit']['merge_count'] = merge_count
            query = {'_id': fix_tag_index['_id']}
            new_data = {
                "$set": {"vuls." + str(vul): fix_tag_index['vuls'][vul]}}
            fix_tag_index_table.update_one(query, new_data)
            print('*', fix_tag_index['_id'], vul)
    print(count)


def update_lag_ver():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    fix_tag_index_table = db['fix_tag_index_info']
    query = {'T_fix': {'$gte': '2019-04-10 00:00:00+00:00'}, 'T_ver': {'$ne': ''}}
    vuls = set()
    for vul_tag_interval in vul_tag_interval_table.find(query):
        vuls.add(str(vul_tag_interval['vul_id']))
    for fix_tag_index in fix_tag_index_table.find():
        for vul in fix_tag_index['vuls']:
            if 'merge_commit' in fix_tag_index['vuls'][vul].keys():
                if str(vul) in vuls:
                    query_vul_tag_interval = {'vul_id': int(vul)}
                    t_fix = datetime.strptime(
                        fix_tag_index['vuls'][vul]['merge_commit']['publish_time'].split('+00')[0], '%Y-%m-%d %H:%M:%S')
                    t_ver = datetime.strptime(fix_tag_index['vuls'][vul]['patch_tag']['earliest_time'].split('+00')[0],
                                              '%Y-%m-%d %H:%M:%S')
                    lag_ver = (t_ver - t_fix).total_seconds() / 60 / 60
                    if lag_ver < 0:
                        continue
                    else:
                        new_data = {"$set": {'Lag_ver_new': lag_ver,
                                             'merge_count': fix_tag_index['vuls'][vul]['merge_commit']['merge_count']}}
                        vul_tag_interval_table.update_one(query_vul_tag_interval, new_data)


def result_of_merge():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    fix_tag_index_table = db['fix_tag_index_info']
    query = {'T_fix': {'$gte': '2019-04-10 00:00:00+00:00'}, 'T_ver': {'$ne': ''}}
    vuls = set()
    zero = 0
    one = 0
    two = 0
    three = 0
    four = 0
    five = 0
    for vul_tag_interval in vul_tag_interval_table.find(query):
        vuls.add(str(vul_tag_interval['vul_id']))
    for fix_tag_index in fix_tag_index_table.find():
        for vul in fix_tag_index['vuls']:
            if 'merge_commit' in fix_tag_index['vuls'][vul].keys():
                if str(vul) in vuls:
                    if 0 <= fix_tag_index['vuls'][vul]['merge_commit']['merge_count'] <= 1 or \
                            fix_tag_index['vuls'][vul]['merge_commit']['merge_count'] == -1:
                        zero = zero + 1
                    if 1 < fix_tag_index['vuls'][vul]['merge_commit']['merge_count'] <= 5:
                        one = one + 1
                    if 5 < fix_tag_index['vuls'][vul]['merge_commit']['merge_count'] <= 10:
                        two = two + 1
                    if 10 < fix_tag_index['vuls'][vul]['merge_commit']['merge_count'] <= 15:
                        three = three + 1
                    if 15 < fix_tag_index['vuls'][vul]['merge_commit']['merge_count'] <= 20:
                        four = four + 1
                    if fix_tag_index['vuls'][vul]['merge_commit']['merge_count'] > 20:
                        five = five + 1
    print(zero, one, two, three, four, five)


def result_of_compare_abnormal_time():
    db = connect_mongodb()
    vul_tag_interval_table = db['vul_tag_interval']
    one = 0
    two = 0
    three = 0
    four = 0
    five = 0
    for vul_tag_interval in vul_tag_interval_table.find():
        if 'max_normal_interval' in vul_tag_interval.keys():
            max_normal_interval = vul_tag_interval['max_normal_interval']
            fixing_commit_belong_tag_interval = vul_tag_interval['fixing_commit_belong_tag_interval']
            if max_normal_interval < fixing_commit_belong_tag_interval <= 2 * max_normal_interval:
                one = one + 1
            if 2 * max_normal_interval < fixing_commit_belong_tag_interval <= 3 * max_normal_interval:
                two = two + 1
            if 3 * max_normal_interval < fixing_commit_belong_tag_interval <= 4 * max_normal_interval:
                three = three + 1
            if 4 * max_normal_interval < fixing_commit_belong_tag_interval <= 5 * max_normal_interval:
                four = four + 1
            if fixing_commit_belong_tag_interval > 5 * max_normal_interval:
                five = five + 1
    print(one, two, three, four, five)


if __name__ == '__main__':
    # prepare dataset and process them
    search_tag_index()
    get_vul_module_tag_intervals_by_branch()
    generate_vul_tag_normal_intervals()
    get_fixing_commits_intervals()
    generate_research_question_two_data()
    generate_vul_tag_interval()
    update_fix_tag_index()
    update_lags()
    update_vul_tag_interval_no_tag()
    update_addition_lags()
    process_go_sum_result()
    count_exist_go_sum()
    insert_no_patch_version_info_table()
    update_no_patch_version_info_table()
    # rq1
    dataset_of_rq1()
    rq1_figure_exist_vul()
    rq1_figure_exist_vul_base_vul()
    rq1_figure_exist_vul_total_vuls()
    generate_after_2019_vul_dependent_graph()
    generate_before_2019_vuls_fig_dataset()
    # rq2
    find_merge_commit()
    update_lag_ver()
    compute_lag_ver()
    compute_lag_index()
    # rq3
    rq3_calculate_portion_of_fixing_sign()
    req3_calculate_proportion_of_t_fix_index_dept()
    # rq4
    non_patch_version()
    non_patch_index()
    rq4_patch_version_delay()
    vul_repo_stars()
