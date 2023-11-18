# coding=gbk
import json
import time
from datetime import datetime
import requests
from pymongo import MongoClient


def connect_mongodb():
    client = MongoClient('mongodb://localhost:27017/')
    mongodb = client['Golang_Vulnerabilities']
    return mongodb


def get_new_libvers_from_host(time_stamp):
    proxies = {
        'http': 'http://127.0.0.1:7890',
        'https': 'http://127.0.0.1:7890'
    }
    url = 'https://index.golang.org/index?since='
    while True:
        try:
            with requests.Session() as session:
                res = session.get(url + str(time_stamp), proxies=proxies)
        except:
            time.sleep(1)
            continue
        try:
            res.raise_for_status()
            libs = json.loads('[' + res.text.replace('\n', ',').strip(',') + ']')
            break
        except Exception as e:
            print('Downloading failed, exception:', e)
            continue
    return libs


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


def index_crawl(time_stamp):
    db = connect_mongodb()
    if 'golang_index' not in db.list_collection_names():
        # 创建集合
        db.create_collection('golang_index')
    golang_index_table = db['golang_index']
    # first index date is 2019-4-10
    # time_stamp = str(datetime(2019, 4, 10)).replace(' ', 'T') + 'Z'
    current_batch = get_new_libvers_from_host(time_stamp)
    insert_mongo_many(golang_index_table, current_batch)
    print(0)
    print(current_batch[-1]["Timestamp"])
    n = 1
    while len(current_batch) == 2000:
        current_batch = get_new_libvers_from_host(current_batch[-1]["Timestamp"])
        insert_mongo_many(golang_index_table, current_batch[1:])
        print(n)
        n = n + 1
        print(current_batch[-1]["Timestamp"])


if __name__ == '__main__':
    db = connect_mongodb()
    if 'golang_index' not in db.list_collection_names():
        db.create_collection('golang_index')
    golang_index_table = db['golang_index']
    f = open('./index.txt', 'r')
    already = []
    content = f.read().split('\n')
    n = 0
    time_stamp = ''
    print(len(content))
    for i in set(content):
        if i == '':
            continue
        temps = i.split(',')
        already.append({'Path': temps[0], 'Version': temps[1], 'Timestamp': temps[2]})
        if temps[2] > time_stamp or time_stamp == '':
            time_stamp = temps[2]
        n = n + 1
        if n == 10000:
            insert_mongo_many(golang_index_table, already)
            n = 0
            already = []
    f.close()
    index_crawl(time_stamp)
