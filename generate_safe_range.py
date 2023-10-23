# coding=gbk
import json
import os
import re
import subprocess
import sys
import pymysql
from multiprocessing import Queue, Process
from pymongo import MongoClient


def write(q, commit_list):
    for value in commit_list:
        q.put(value)


def read(q):
    if q.qsize() > 0:
        value = q.get(True)
        return value
    else:
        return None


def connect_mongodb():
    client = MongoClient('mongodb://localhost:27017/')
    mongodb = client['Golang_Vulnerabilities']
    return mongodb


def get_safe_range(q):
    db = connect_mongodb()
    commits_table = db['commits_info_new']
    patches_table = db['patches_info']
    lib_info = read(q)
    while lib_info is not None:
        print('begin: ' + str(lib_info['_id']))
        query = {'repo_id': lib_info['_id']}
        temps = commits_table.find(query)
        commits = dict()
        for temp in temps:
            commits.update(temp['commits'])
        patches = patches_table.find(query)
        for patch in patches:
            safe_commits = set()
            vul_commits = Queue()
            for fixing_commit in patch['final_fixing_commits']:
                if fixing_commit['commit_id'] in commits.keys():
                    safe_commits.add(fixing_commit['commit_id'])
                    for son in commits[fixing_commit['commit_id']]['sons']:
                        vul_commits.put(son)
            while vul_commits.qsize() > 0:
                temp = vul_commits.get()
                if temp in safe_commits:
                    continue
                safe_commits.add(temp)
                for son in commits[temp]['sons']:
                    vul_commits.put(son)
            exist_vul_commits = set(commits.keys()) - safe_commits
            for commit in exist_vul_commits:
                if 'vul' in commits[commit].keys():
                    commits[commit]['vul'].append(patch['_id'])
                else:
                    commits[commit]['vul'] = []
                    commits[commit]['vul'].append(patch['_id'])
            print(len(commits.keys()), len(exist_vul_commits), lib_info['_id'], lib_info['repo'])
        temps = commits_table.find(query)
        for temp in temps:
            temp_commits = temp['commits']
            for key in temp_commits.keys():
                if 'vul' in commits[key].keys():
                    temp_commits[key]['vul'] = commits[key]['vul']
                else:
                    temp_commits[key]['vul'] = []
            update_query = {'_id': temp['_id']}
            new_data = {"$set": {"commits": temp_commits}}
            commits_table.update_one(update_query, new_data)
        print('success: ' + str(lib_info['_id']))
        lib_info = read(q)


def generate_safe_range():
    db = connect_mongodb()
    repo_table = db['repo_info']
    repos = []
    for i in repo_table.find():
        repos.append(i)
    q = Queue()
    write(q, repos)
    for i in range(6):
        p = Process(target=get_safe_range, args=(q,))
        p.start()


def generate_safe_range_json():
    db = connect_mongodb()
    repo_table = db['repo_info']
    commits_table = db['commits_info']
    repo_info = dict()
    f = open('./safe_json.json', 'w')
    n = 1
    repos = []
    for repo in repo_table.find():
        repos.append(repo)
    for repo in repos:
        query = {'repo_id': repo['_id']}
        temps = commits_table.find(query)
        commits = dict()
        for temp in temps:
            commits.update(temp['commits'])
        repo_info[repo['repo']] = {}
        repo_info[repo['repo']]['safe_range'] = {}
        for commit in commits.keys():
            repo_info[repo['repo']]['safe_range'][commit] = list(set(commits[commit]['vul']))
        print(str(n) + '/' + str(len(repos)))
        n = n + 1
    json.dump(repo_info, f)
    f.close()


if __name__ == '__main__':
    generate_safe_range()
    generate_safe_range_json()
