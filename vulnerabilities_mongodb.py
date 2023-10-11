# coding=gbk
import glob
import json
import os
import subprocess
import time
import re
import bs4 as soup
import pandas as pd
import requests
from pymongo import MongoClient
from requests.adapters import HTTPAdapter


def connect_mongodb():
    client = MongoClient('mongodb://localhost:27017/')
    mongodb = client['Golang_Vulnerabilities']
    return mongodb


class detail_info:
    def __init__(self, publish, vul, ranges, level, score, remediation, overview, cve, cwe, references):
        self.publish = publish
        self.vul = vul
        self.ranges = ranges
        self.level = level
        self.score = score
        self.remediation = remediation
        self.overview = overview
        self.cve = cve
        self.cwe = cwe
        self.references = references


def convert2json_list(details):
    results = []
    result = convert2json(details[0])
    results.append(result)
    if len(details) > 1:
        for i in range(len(details) - 1):
            results.append(convert2json(details[i + 1]))
    return results


def convert2json(detail):
    return {
        'publish': detail.publish,
        'vul': detail.vul,
        'ranges': detail.ranges,
        'level': detail.level,
        'score': detail.score,
        'remediation': detail.remediation,
        'overview': detail.overview,
        'cve': detail.cve,
        'cwe': detail.cwe,
        'references': detail.references
    }


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


def crawl_snyk_vuls_by_pages():
    db = connect_mongodb()
    local_vulnerability = db['snyk_vulnerabilities']
    o = requests.Session()
    o.mount('http://', HTTPAdapter(max_retries=3))
    for i in range(30):
        try:
            res = o.get(f'''https://security.snyk.io/vuln/golang/{i + 1}''', timeout=5)
            res.raise_for_status()
            html = res.content.decode()
            s = soup.BeautifulSoup(html, "html.parser")
            tbody = s.find_all(attrs={'class': 'vue--table__tbody'})
            vul_list = tbody[0].find_all(attrs={'class': 'vue--table__row'})
            for t in vul_list:
                try:
                    vul_name = t.find_all(attrs={'class': 'vue--anchor'})
                    url = 'https://security.snyk.io' + vul_name[1].attrs['href']
                    if local_vulnerability.find_one({'url': url}):
                        continue
                    name = vul_name[1].text.strip().split("\n")[0]
                    res = o.get(url, timeout=5)
                    res.raise_for_status()
                    package_page = res.content.decode()
                    page = soup.BeautifulSoup(package_page, "html.parser")
                    details = page.find_all(attrs={'class': 'vue--table__tbody'})
                    url_list = details[0].find_all(attrs={'class': 'vue--table__row'})
                    vul_details = []
                    for k in range(len(url_list)):
                        detail_temp = "https://security.snyk.io/" + url_list[k].find('a').attrs['href']
                        vul = url_list[k].find('a').text.strip()
                        res = o.get(detail_temp, timeout=5)
                        res.raise_for_status()
                        detail_page = res.content.decode()
                        detail = soup.BeautifulSoup(detail_page, "html.parser")
                        ranges = detail.find(attrs={'class': 'vue--heading title'}).find_all('strong')
                        range_temp = []
                        for i in ranges:
                            range_temp.append(i.text.strip())
                        vul_range = ','.join(range_temp)
                        temp = detail.find(attrs={'class': 'severity-widget__badge big'})
                        level = temp.text.strip().split("\n")[2].strip()
                        severity_widget_score = temp.find(
                            attrs={'class': 'severity-widget__score severity-' + level + ' big'}).attrs[
                            'data-snyk-test-score']
                        content = detail.find_all(attrs={'class': 'markdown-section'})
                        Remediation = ''
                        Overview = ''
                        for b in content:
                            temp = b.find(attrs={'class': 'vue--heading heading'}).text.strip()
                            if temp == 'How to fix?':
                                Remediation = b.find(
                                    attrs={'class': 'vue--markdown-to-html markdown-description'}).text.strip()
                                continue
                            if temp == 'Overview':
                                Overview = b.find(
                                    attrs={'class': 'vue--markdown-to-html markdown-description'}).text.strip()
                                continue
                        publish = detail.find(attrs={'class': 'vuln-info-block'}).find(
                            attrs={'class': 'vue--heading date'}).text.strip()
                        vul_info = detail.find(attrs={'class': 'vuln-info-block'}).find_all(
                            attrs={'class': 'vue--anchor'})
                        CVE = ''
                        CWE = ''
                        for b in vul_info:
                            temp = b.text.strip().split("\n")[0]
                            if temp.startswith('CWE'):
                                CWE = temp
                                continue
                            if temp.startswith('CVE'):
                                CVE = temp
                                continue
                        References_temp = detail.find_all(attrs={'class': 'markdown-section'})[-1]
                        References = []
                        if References_temp.find(attrs={'class': 'vue--heading heading'}).text.strip() == 'References':
                            for reference in References_temp.find_all('a'):
                                References.append(reference.attrs['href'])
                        vul_detail = detail_info(publish=publish, vul=vul, ranges=vul_range, level=level,
                                                 score=severity_widget_score, remediation=Remediation,
                                                 overview=Overview, cve=CVE, cwe=CWE, references=References)
                        vul_details.append(vul_detail)
                    details_json = convert2json_list(vul_details)
                    insert_content = {'package_path': name, "url": url, 'details': details_json}
                    insert_mongo(local_vulnerability, insert_content)
                    time.sleep(1)
                except Exception as e2:
                    print(e2, e2.__traceback__.tb_lineno)
        except Exception as e:
            print(e, e.__traceback__.tb_lineno)


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


def crawl_snyk_vuls_by_modules(vul_module):
    db = connect_mongodb()
    # db.create_collection('snyk_vulnerabilities')
    local_vulnerability = db['snyk_vulnerabilities']
    o = requests.Session()
    o.mount('http://', HTTPAdapter(max_retries=3))
    vul_list = []
    try:
        search_key = vul_module.replace('/', '%2F')
        page = 1
        while True:
            res = o.get(f'''https://security.snyk.io/vuln/golang/{str(page)}?search={search_key}''', timeout=5)
            res.raise_for_status()
            html = res.content.decode()
            s = soup.BeautifulSoup(html, "html.parser")
            tbody = s.find_all(attrs={'class': 'vue--table__tbody'})
            vul_temps = tbody[0].find_all(attrs={'class': 'vue--table__row'})
            for vul_temp in vul_temps:
                vul_list.append(vul_temp)
            if len(vul_temps) == 30:
                page = page + 1
            else:
                break
        for t in vul_list:
            try:
                vul_name = t.find_all(attrs={'class': 'vue--anchor'})
                url = 'https://security.snyk.io' + vul_name[1].attrs['href']
                if local_vulnerability.find_one({'url': url}):
                    continue
                name = vul_name[1].text.strip().split("\n")[0]
                res = o.get(url, timeout=5)
                res.raise_for_status()
                package_page = res.content.decode()
                page = soup.BeautifulSoup(package_page, "html.parser")
                details = page.find_all(attrs={'class': 'vue--table__tbody'})
                url_list = details[0].find_all(attrs={'class': 'vue--table__row'})
                vul_details = []
                for k in range(len(url_list)):
                    detail_temp = "https://security.snyk.io/" + url_list[k].find('a').attrs['href']
                    vul = url_list[k].find('a').text.strip()
                    res = o.get(detail_temp, timeout=5)
                    res.raise_for_status()
                    detail_page = res.content.decode()
                    detail = soup.BeautifulSoup(detail_page, "html.parser")
                    ranges = detail.find(attrs={'class': 'vue--heading title'}).find_all('strong')
                    range_temp = []
                    for i in ranges:
                        range_temp.append(i.text.strip())
                    vul_range = ','.join(range_temp)
                    temp = detail.find(attrs={'class': 'severity-widget__badge big'})
                    level = temp.text.strip().split("\n")[2].strip()
                    severity_widget_score = temp.find(
                        attrs={'class': 'severity-widget__score severity-' + level + ' big'}).attrs[
                        'data-snyk-test-score']
                    content = detail.find_all(attrs={'class': 'markdown-section'})
                    Remediation = ''
                    Overview = ''
                    for b in content:
                        temp = b.find(attrs={'class': 'vue--heading heading'}).text.strip()
                        if temp == 'How to fix?':
                            Remediation = b.find(
                                attrs={'class': 'vue--markdown-to-html markdown-description'}).text.strip()
                            continue
                        if temp == 'Overview':
                            Overview = b.find(
                                attrs={'class': 'vue--markdown-to-html markdown-description'}).text.strip()
                            continue
                    publish = detail.find(attrs={'class': 'vuln-info-block'}).find(
                        attrs={'class': 'vue--heading date'}).text.strip()
                    vul_info = detail.find(attrs={'class': 'vuln-info-block'}).find_all(
                        attrs={'class': 'vue--anchor'})
                    CVE = ''
                    CWE = ''
                    for b in vul_info:
                        temp = b.text.strip().split("\n")[0]
                        if temp.startswith('CWE'):
                            CWE = temp
                            continue
                        if temp.startswith('CVE'):
                            CVE = temp
                            continue
                    References_temp = detail.find_all(attrs={'class': 'markdown-section'})[-1]
                    References = []
                    if References_temp.find(attrs={'class': 'vue--heading heading'}).text.strip() == 'References':
                        for reference in References_temp.find_all('a'):
                            References.append(reference.attrs['href'])
                    vul_detail = detail_info(publish=publish, vul=vul, ranges=vul_range, level=level,
                                             score=severity_widget_score, remediation=Remediation,
                                             overview=Overview, cve=CVE, cwe=CWE, references=References)
                    vul_details.append(vul_detail)
                details_json = convert2json_list(vul_details)
                insert_content = {'package_path': name, "url": url, 'details': details_json}
                insert_mongo(local_vulnerability, insert_content)
                time.sleep(1)
            except Exception as e2:
                print(e2, e2.__traceback__.tb_lineno)
        f = open('./already_crawl.txt', 'a')
        f.write(vul_module + '\n')
        f.close()
    except Exception as e:
        print(e, e.__traceback__.tb_lineno)


def generate_vulnerabilities_by_local():
    origin = 'E:/vul_repos'
    need_modules = search_modules_name(origin)
    f = open('./already_crawl.txt', 'r')
    already_modules = f.read().split('\n')
    f.close()
    for sub_module in need_modules.keys():
        if sub_module in already_modules:
            continue
        crawl_snyk_vuls_by_modules(sub_module)


def count_matching_elements(str1, str2):
    # 将字符串按'/'分割为数组，并转换为小写形式
    arr1 = [s.lower() for s in str1.split('/')]
    arr2 = [s.lower() for s in str2.split('/')]

    count = 0  # 统计匹配成功的元素个数

    # 遍历两个数组，逐个比较元素
    for i in range(min(len(arr1), len(arr2))):
        if arr1[i] == arr2[i]:
            count += 1
        else:
            break  # 遇到不一致的元素，停止遍历

    return count


def update_mongodb_element():
    db = connect_mongodb()
    table = db['snyk_vulnerabilities']

    # 更新数据
    filter = {'package_path': 'github.com/AdguardTeam/AdGuardHome/home'}
    update = {'$set': {'package_path': 'github.com/AdguardTeam/AdGuardHome/home'.lower()}}
    table.update_one(filter, update)


def download_addition_repo():
    with open('./package_path.json', encoding='utf-8') as a:
        package_path = json.load(a)
    db = connect_mongodb()
    table = db['snyk_vulnerabilities']
    origin = 'E:/vul_repos/github.com/'
    for i in table.find():
        if i['package_path'] not in package_path.keys():
            path = i['package_path']
            if str(path).startswith('github.com'):
                owner = path.split('/')[1]
                repo = path.split('/')[2]
                if not os.path.exists(origin + owner):
                    os.mkdir(origin + owner)
                if not os.path.exists(origin + owner + '/' + repo):
                    try:
                        cmd = f"git clone https://foo:bar@{'github.com/' + owner + '/' + repo}.git"
                        print(cmd)
                        subprocess.check_output(cmd, shell=True, cwd=origin + owner)
                        print('success: ' + path)
                    except:
                        print('fault: ' + path)


def download_mongo_vuls_repo():
    db = connect_mongodb()
    table = db['snyk_vulnerabilities']
    origin = 'E:/vul_repos/github.com/'
    for i in table.find():
        references = []
        for detail in i['details']:
            for reference in detail['references']:
                if '/commit/' in reference:
                    references.append(reference)
        for reference in references:
            owner = reference.replace('https://', '').split('/')[1]
            repo = reference.replace('https://', '').split('/')[2]
            if not os.path.exists(origin + owner):
                os.mkdir(origin + owner)
            if not os.path.exists(origin + owner + '/' + repo):
                try:
                    cmd = f"git clone https://foo:bar@{'github.com/' + owner + '/' + repo}.git"
                    print(cmd)
                    subprocess.check_output(cmd, shell=True, cwd=origin + owner)
                    print('success')
                except:
                    print('fault')


def generate_package_json():
    db = connect_mongodb()
    table = db['snyk_vulnerabilities']
    module_info = dict()
    for i in os.listdir('E:/vul_repos/github.com'):
        for j in os.listdir('E:/vul_repos/github.com/' + i):
            path = 'E:/vul_repos/github.com/' + i + '/' + j
            repo = 'github.com/' + i + '/' + j
            modules = search_modules_name(path)
            module_info[repo] = modules
    result = dict()
    for i in table.find():
        for key in module_info.keys():
            for module in module_info[key].keys():
                if str(module).lower() in i['package_path']:
                    if i['package_path'] not in result.keys():
                        if count_matching_elements(module, i['package_path']) > 0:
                            result[i['package_path']] = {}
                            result[i['package_path']]['match_count'] = count_matching_elements(module,
                                                                                               i['package_path'])
                            result[i['package_path']]['repo'] = key
                            result[i['package_path']]['module'] = module
                            result[i['package_path']]['module_path'] = module_info[key][module]
                            f = open('./package_path.json', 'w')
                            json.dump(result, f)
                            f.close()
                    else:
                        current = count_matching_elements(module, i['package_path'])
                        if current > result[i['package_path']]['match_count']:
                            result[i['package_path']]['match_count'] = current
                            result[i['package_path']]['repo'] = key
                            result[i['package_path']]['module'] = module
                            result[i['package_path']]['module_path'] = module_info[key][module]
                            f = open('./package_path.json', 'w')
                            json.dump(result, f)
                            f.close()


def map_repo():
    db = connect_mongodb()
    table = db['snyk_vulnerabilities']
    with open('./package_path.json', encoding='utf-8') as a:
        result = json.load(a)
    if 'gopkg.in/yaml.v3' not in result.keys():
        result['gopkg.in/yaml.v3'] = {}
        result['gopkg.in/yaml.v3']['repo'] = 'github.com/go-yaml/yaml'
    if 'gopkg.in/yaml.v2' not in result.keys():
        result['gopkg.in/yaml.v2'] = {}
        result['gopkg.in/yaml.v2']['repo'] = 'github.com/go-yaml/yaml'
    if 'gopkg.in/macaron.v1' not in result.keys():
        result['gopkg.in/macaron.v1'] = {}
        result['gopkg.in/macaron.v1']['repo'] = 'github.com/go-macaron/macaron'
    if 'miniflux.app/ui' not in result.keys():
        result['miniflux.app/ui'] = {}
        result['miniflux.app/ui']['repo'] = 'github.com/miniflux/v2'
    if 'miniflux.app/http/request' not in result.keys():
        result['miniflux.app/http/request'] = {}
        result['miniflux.app/http/request']['repo'] = 'github.com/miniflux/v2'
    if 'miniflux.app/service/httpd' not in result.keys():
        result['miniflux.app/service/httpd'] = {}
        result['miniflux.app/service/httpd']['repo'] = 'github.com/miniflux/v2'
    if 'golang.org/x/net/http2/h2c' not in result.keys():
        result['golang.org/x/net/http2/h2c'] = {}
        result['golang.org/x/net/http2/h2c']['repo'] = 'github.com/golang/net'
    if 'teler.app/internal/event/www' not in result.keys():
        result['teler.app/internal/event/www'] = {}
        result['teler.app/internal/event/www']['repo'] = 'github.com/kitabisa/teler'
    if 'go.mongodb.org/mongo-driver/bson/bsonrw' not in result.keys():
        result['go.mongodb.org/mongo-driver/bson/bsonrw'] = {}
        result['go.mongodb.org/mongo-driver/bson/bsonrw']['repo'] = 'github.com/mongodb/mongo-go-driver'
    if 'go.pinniped.dev/internal/oidc' not in result.keys():
        result['go.pinniped.dev/internal/oidc'] = {}
        result['go.pinniped.dev/internal/oidc']['repo'] = 'github.com/vmware-tanzu/pinniped'
    if 'go.pinniped.dev/internal/upstreamldap' not in result.keys():
        result['go.pinniped.dev/internal/upstreamldap'] = {}
        result['go.pinniped.dev/internal/upstreamldap']['repo'] = 'github.com/vmware-tanzu/pinniped'
    if 'tailscale.com/ssh/tailssh' not in result.keys():
        result['tailscale.com/ssh/tailssh'] = {}
        result['tailscale.com/ssh/tailssh']['repo'] = 'github.com/tailscale/tailscale'
    if 'go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp' not in result.keys():
        result['go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp'] = {}
        result['go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp'][
            'repo'] = 'github.com/open-telemetry/opentelemetry-go-contrib'
    if 'github.com/containers/libpod/v2' not in result.keys():
        result['github.com/containers/libpod/v2'] = {}
        result['github.com/containers/libpod/v2']['repo'] = 'github.com/containers/podman'
    if 'git.arvados.org/arvados.git/lib/controller/localdb' not in result.keys():
        result['git.arvados.org/arvados.git/lib/controller/localdb'] = {}
        result['git.arvados.org/arvados.git/lib/controller/localdb']['repo'] = 'github.com/arvados/arvados'
    if 'github.com/stackrox/rox' not in result.keys():
        result['github.com/stackrox/rox'] = {}
        result['github.com/stackrox/rox']['repo'] = 'github.com/stackrox/stackrox'
    if 'github.com/ipfs/go-libipfs/bitswap/server' not in result.keys():
        result['github.com/ipfs/go-libipfs/bitswap/server'] = {}
        result['github.com/ipfs/go-libipfs/bitswap/server']['repo'] = 'github.com/ipfs/boxo'
    if 'github.com/containers/libpod' not in result.keys():
        result['github.com/containers/libpod'] = {}
        result['github.com/containers/libpod']['repo'] = 'github.com/containers/podman'
    f = open('./package_path.json', 'w')
    json.dump(result, f)
    f.close()
    for i in table.find():
        if i['package_path'] not in result.keys():
            paths = set()
            for j in i['details']:
                for reference in j['references']:
                    if str(reference).startswith('https://github.com'):
                        temps = str(reference).replace('https://', '')
                        temps = temps.split('/')
                        owner = temps[1]
                        repo = temps[2]
                        paths.add('github.com/' + owner + '/' + repo)
            for path in paths:
                if os.path.exists('E:/vul_repos/' + path):
                    if str(i['package_path']).startswith(path.lower()):
                        result[i['package_path']] = {}
                        result[i['package_path']]['repo'] = path
                        f = open('./package_path.json', 'w')
                        json.dump(result, f)
                        f.close()
                        break
                    else:
                        temps = i['package_path'].split('/')
                        if str(i['package_path']).startswith('golang.org'):
                            repo = temps[2]
                            if str(repo).lower() == str(path.split('/')[2]).lower():
                                result[i['package_path']] = {}
                                result[i['package_path']]['repo'] = path
                                f = open('./package_path.json', 'w')
                                json.dump(result, f)
                                f.close()
                                break
                        else:
                            try:
                                repo = temps[1]
                            except:
                                print(i['package_path'])
                            if str(repo).lower() == str(path.split('/')[-1]).lower():
                                result[i['package_path']] = {}
                                result[i['package_path']]['repo'] = path
                                f = open('./package_path.json', 'w')
                                json.dump(result, f)
                                f.close()
                                break
                            else:
                                try:
                                    repo = temps[2]
                                except:
                                    print(i['package_path'])
                                if str(repo).lower() == str(path.split('/')[-1]).lower():
                                    result[i['package_path']] = {}
                                    result[i['package_path']]['repo'] = path
                                    f = open('./package_path.json', 'w')
                                    json.dump(result, f)
                                    f.close()
                                    break


def generate_mongo_vuls_info():
    db = connect_mongodb()
    if 'vulnerabilities_info' not in db.list_collection_names():
        # 创建集合
        db.create_collection('vulnerabilities_info')
    vul_info_table = db['vulnerabilities_info']
    snky_vuls = db['snyk_vulnerabilities']
    with open('./package_path.json', encoding='utf-8') as a:
        package_path = json.load(a)
    for key in package_path.keys():
        repo = package_path[key]['repo']
        query = {"package_path": key}
        vul_info = snky_vuls.find_one(query)
        for vul in vul_info['details']:
            query = {"repo": repo}
            sign = 0
            vul_package = dict()
            vul_package[key] = {}
            vul_package[key]['publish'] = vul['publish']
            vul_package[key]['vul_name'] = vul['vul']
            vul_package[key]['vul_range'] = vul['ranges']
            vul_package[key]['level'] = vul['level']
            vul_package[key]['score'] = vul['score']
            vul_package[key]['remediation'] = vul['remediation']
            vul_package[key]['overview'] = vul['overview']
            for i in vul_info_table.find(query):
                if set(i['references']) == set(vul['references']) and i['cve'] == vul['cve'] and i['cwe'] == vul['cwe']:
                    filter = {"_id": i['_id']}
                    vul_packages = i['vul_packages']
                    vul_packages.append(vul_package)
                    new_data = {"$set": {"vul_packages": vul_packages}}
                    vul_info_table.update_one(filter, new_data)
                    sign = 1
                    break
            if sign == 0:
                vul_packages = list()
                vul_packages.append(vul_package)
                data = {"repo": repo, "references": vul['references'], "cve": vul['cve'], "cwe": vul['cwe'],
                        "vul_packages": vul_packages}
                insert_mongo(vul_info_table, data)


def generate_mongo_repo_init():
    db = connect_mongodb()
    if 'repo_info' not in db.list_collection_names():
        # 创建集合
        db.create_collection('repo_info')
    vul_info_table = db['vulnerabilities_info']
    repo_info_table = db['repo_info']
    for vul in vul_info_table.find():
        repo = vul['repo']
        query = {'repo': repo}
        repo_info = repo_info_table.find_one(query)
        if repo_info is None:
            data = {"repo": repo, "vuls": list([vul['_id']])}
            insert_mongo(repo_info_table, data)
        else:
            vuls = repo_info['vuls']
            vuls.append(vul['_id'])
            new_data = {"$set": {"vuls": vuls}}
            repo_info_table.update_one(query, new_data)


def split_dict_by_count(dictionary, chunk_size):
    result = {}
    current_chunk = 1
    count = 0

    for key, value in dictionary.items():
        if count == chunk_size:
            current_chunk += 1
            count = 0

        if current_chunk not in result:
            result[current_chunk] = {}

        result[current_chunk][key] = value
        count += 1

    return result


def generate_mongo_repo_commits():
    db = connect_mongodb()
    repo_info_table = db['repo_info']
    if 'commits_info_new' not in db.list_collection_names():
        # 创建集合
        db.create_collection('commits_info_new')
    commit_info_table = db['commits_info_new']
    for repo in repo_info_table.find():
        if 'commits_new' in repo.keys():
            continue
        print(repo['repo'])
        commits = dict()
        command = ['git', 'log', '--graph', '--pretty=format:----****%H----****%P----****%s----****%ci@@@@',
                   '--decorate', '--all', '--date=iso']
        process = subprocess.Popen(command, shell=True, cwd='E:/vul_repos/' + repo['repo'],
                                   stdout=subprocess.PIPE)
        output = process.communicate()[0].decode('utf-8')
        lines = output.splitlines()
        merge = ''
        sign = 0
        for line in lines:
            if not str(line).endswith('@@@@'):
                merge = merge + str(line)
                sign = 1
                continue
            if sign == 1:
                line = merge + str(line)
                sign = 0
                merge = ''
            output = str(line).replace('\\\\', '\\').replace('\'', '').replace('\"', '')[1:]
            if '----****' in output:
                temps = output.split('----****')
                son_commit_id = temps[1]
                son_commit_subject = temps[3]
                son_commit_publish_time = temps[4].replace('@@@@', '')
                if son_commit_id not in commits.keys():
                    commits[son_commit_id] = {}
                    commits[son_commit_id]['commits_subject'] = son_commit_subject
                    commits[son_commit_id]['publish_time'] = son_commit_publish_time
                    commits[son_commit_id]['fathers'] = []
                    commits[son_commit_id]['sons'] = []
                else:
                    if commits[son_commit_id]['commits_subject'] == '':
                        commits[son_commit_id]['commits_subject'] = son_commit_subject
                    if commits[son_commit_id]['publish_time'] == '':
                        commits[son_commit_id]['publish_time'] = son_commit_publish_time
                if len(temps[2]) != 0:
                    for father_commit_id in temps[2].split(' '):
                        commits[son_commit_id]['fathers'].append(father_commit_id)
                        if father_commit_id not in commits.keys():
                            commits[father_commit_id] = {}
                            commits[father_commit_id]['commits_subject'] = ''
                            commits[father_commit_id]['publish_time'] = ''
                            commits[father_commit_id]['fathers'] = []
                            commits[father_commit_id]['sons'] = [son_commit_id]
                        else:
                            commits[father_commit_id]['sons'].append(son_commit_id)

        query = {"_id": repo['_id']}
        new_data = {"$set": {"commits": []}}
        repo_info_table.update_one(query, new_data)
        commits = split_dict_by_count(commits, 10000)
        for key in commits.keys():
            data = {"repo": repo['repo'], "repo_id": repo['_id'], "commits": commits[key]}
            _id = insert_mongo(commit_info_table, data)
            query = {"_id": repo['_id']}
            new_data = {"$push": {"commits_new": _id}}
            repo_info_table.update_one(query, new_data)


def generate_vul_patches_init():
    db = connect_mongodb()
    repo_info_table = db['repo_info']
    vul_info_table = db['vulnerabilities_info']
    if 'patches_info' not in db.list_collection_names():
        # 创建集合
        db.create_collection('patches_info')
    patch_info_table = db['patches_info']
    for vul in vul_info_table.find():
        query = {'repo': vul['repo']}
        repo = repo_info_table.find_one(query)
        references = vul['references']
        commits_href = []
        issues_href = []
        pulls_href = []
        for reference in references:
            if 'github.com' in reference and vul['repo'] in reference:
                if 'commit' in reference.split('/'):
                    commits_href.append(reference)
                if 'issues' in reference.split('/'):
                    issues_href.append(reference)
                if 'pull' in reference.split('/'):
                    pulls_href.append(reference)
        data = {'vul_id': vul['_id'], 'repo_id': repo['_id'], 'origin_commits_href': commits_href,
                'origin_issues_href': issues_href, 'origin_pulls_href': pulls_href}
        insert_mongo(patch_info_table, data)


def search_all_fixing_commits():
    db = connect_mongodb()
    patch_info_table = db['patches_info']
    commit_info_table = db['commits_info']
    repo_info_table = db['repo_info']
    pipeline = [
        {
            '$group': {
                '_id': '$repo_id'
            }
        }
    ]
    result = patch_info_table.aggregate(pipeline)
    base_url = 'https://api.github.com'
    access_token = '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'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/vnd.github.v3+json'
    }

    params = {
        'state': 'closed'
    }
    for doc in result:
        repo_id = doc['_id']
        patch_query = {'repo_id': repo_id}
        commits_query = {'repo_id': repo_id}
        repo_query = {'_id': repo_id}
        repo_commits = commit_info_table.find(commits_query)
        commits = dict()
        for block in repo_commits:
            for commit in block['commits'].keys():
                commits[commit] = {}
                commits[commit]['commit_subject'] = block['commits'][commit]['commits_subject']
                commits[commit]['commits_info_id'] = block['_id']
        repo_info = repo_info_table.find_one(repo_query)
        owner = repo_info['repo'].split('/')[1]
        repo = repo_info['repo'].split('/')[2]
        for patch in patch_info_table.find(patch_query):
            print(patch['_id'])
            commit_subjects = set()
            fixing_commits = set()
            all_fixing_commits = []
            for commit in patch['origin_commits_href']:
                commit_id = commit.split('/')[-1]
                if commit_id in commits.keys():
                    fixing_commits.add(commit_id)
                    commit_subjects.add(commits[commit_id]['commit_subject'])
            pull_numbers = set()
            for pull in patch['origin_pulls_href']:
                pull_number = pull.split('/pull/')[1].split('/')[0]
                pull_numbers.add(pull_number)
            for pull_number in pull_numbers:
                url = f'{base_url}/repos/{owner}/{repo}/pulls/{pull_number}'
                response = requests.get(url, headers=headers, params=params)
                data = response.json()
                try:
                    merge_commit = data['merge_commit_sha']
                except:
                    print(url)
                merge_date = data['merged_at']
                if merge_date:
                    if merge_commit in commits.keys():
                        fixing_commits.add(merge_commit)
                        commit_subjects.add(commits[merge_commit]['commit_subject'])
            issue_numbers = set()
            for issue in patch['origin_issues_href']:
                issue_number = issue.split('/issues/')[1].split('/')[0]
                issue_numbers.add(issue_number)
            for issue_number in issue_numbers:
                url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}"
                response = requests.get(url, headers=headers)
                data = response.json()
                if "pull_request" in data:
                    pull_request_url = data["pull_request"]["url"]
                    response = requests.get(pull_request_url, headers=headers)
                    pull_request_data = response.json()
                    merge_commit = pull_request_data["merge_commit_sha"]
                    if merge_commit:
                        if merge_commit in commits.keys():
                            fixing_commits.add(merge_commit)
                            commit_subjects.add(commits[merge_commit]['commit_subject'])
            for commit_subject in commit_subjects:
                for commit in commits:
                    if commits[commit]['commit_subject'] == commit_subject:
                        temp = dict()
                        temp['commit_id'] = commit
                        temp['commits_info_id'] = commits[commit]['commits_info_id']
                        all_fixing_commits.append(temp)
            query = {"_id": patch['_id']}
            new_data = {
                "$set": {"origin_fixing_commits": list(fixing_commits), "final_fixing_commits": all_fixing_commits}}
            patch_info_table.update_one(query, new_data)


def split_list_by_count(lst, count):
    sublists = [lst[i:i + count] for i in range(0, len(lst), count)]
    return {i: sublist for i, sublist in enumerate(sublists)}


def search_mongo_pulls():
    db = connect_mongodb()
    if 'pulls_info' not in db.list_collection_names():
        # 创建集合
        db.create_collection('pulls_info')
    pulls_info_table = db['pulls_info']
    repo_info_table = db['repo_info']
    # hjc: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
    # zm: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
    access_token = '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'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/vnd.github.v3+json'
    }

    params = {
        'state': 'closed',
        "per_page": 100
    }
    query = {"pulls": {"$exists": False}}
    for repo_info in repo_info_table.find(query, no_cursor_timeout=True):
        owner = repo_info['repo'].split('/')[1]
        repo = repo_info['repo'].split('/')[2]
        if 'pulls' not in repo_info.keys():
            print('begin ' + str(repo_info['_id']))
            pulls = []
            next_url = f'https://api.github.com/repos/{owner}/{repo}/pulls'
            while next_url:
                response = requests.get(next_url, headers=headers, params=params)
                data = response.json()
                pulls.extend(data)
                if "Link" in response.headers:
                    links = response.headers["Link"].split(", ")
                    for link in links:
                        if "rel=\"next\"" in link:
                            next_url = link[link.index("<") + 1: link.index(">")]
                            break
                    else:
                        next_url = None
                else:
                    next_url = None
            query = {"_id": repo_info['_id']}
            new_data = {"$set": {"pulls": []}}
            repo_info_table.update_one(query, new_data)
            pulls_data = split_list_by_count(pulls, 100)
            for key in pulls_data.keys():
                data = {"repo": repo_info['repo'], "repo_id": repo_info['_id'], "pulls": pulls_data[key]}
                _id = insert_mongo(pulls_info_table, data)
                query = {"_id": repo_info['_id']}
                new_data = {"$push": {"pulls": _id}}
                repo_info_table.update_one(query, new_data)
            print('success ' + str(repo_info['_id']))


def search_mongo_issues():
    db = connect_mongodb()
    if 'issues_info' not in db.list_collection_names():
        # 创建集合
        db.create_collection('issues_info')
    issues_info_table = db['issues_info']
    repo_info_table = db['repo_info']
    # hjc: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
    # zm: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
    access_token = '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'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    params = {
        "state": "all",
        "per_page": 100
    }
    query = {"issues": {"$exists": False}}
    repos = []
    for repo_info in repo_info_table.find(query, no_cursor_timeout=True):
        repos.append(repo_info)
    for repo_info in repos:
        owner = repo_info['repo'].split('/')[1]
        repo = repo_info['repo'].split('/')[2]
        if 'issues' not in repo_info.keys():
            print('begin ' + str(repo_info['_id']))
            issues = []
            next_url = f'https://api.github.com/repos/{owner}/{repo}/issues'
            while next_url:
                response = requests.get(next_url, headers=headers, params=params)
                data = response.json()
                issues.extend(data)
                if "Link" in response.headers:
                    links = response.headers["Link"].split(", ")
                    for link in links:
                        if "rel=\"next\"" in link:
                            next_url = link[link.index("<") + 1: link.index(">")]
                            break
                    else:
                        next_url = None
                else:
                    next_url = None
            query = {"_id": repo_info['_id']}
            new_data = {"$set": {"issues": []}}
            repo_info_table.update_one(query, new_data)
            issues_data = split_list_by_count(issues, 100)
            for key in issues_data.keys():
                data = {"repo": repo_info['repo'], "repo_id": repo_info['_id'], "issues": issues_data[key]}
                _id = insert_mongo(issues_info_table, data)
                query = {"_id": repo_info['_id']}
                new_data = {"$push": {"issues": _id}}
                repo_info_table.update_one(query, new_data)
            print('success ' + str(repo_info['_id']))


def update_vul_tags():
    db = connect_mongodb()
    repo_info_table = db['repo_info']
    for repo in repo_info_table.find(no_cursor_timeout=True):
        if 'tags' in repo.keys():
            continue
        print('begin ' + str(repo['_id']))
        cmd = 'git tag'
        p = subprocess.check_output(cmd, shell=True, cwd='E:/vul_repos/' + repo['repo'])
        tags = {}
        for i in p.splitlines():
            try:
                tag = str(i)[1:].replace('\'', '')
                cmd = 'git show -s --pretty=format:%H,%cd ' + str(i)[1:].replace('\'', '')
                q = subprocess.check_output(cmd, shell=True, cwd='E:/vul_repos/' + repo['repo'])
                temps = str(q.splitlines()[-1])[1:].replace('\'', '').split(',')
                tags[temps[0]] = {}
                tags[temps[0]]['tag'] = tag
                tags[temps[0]]['tag_release_time'] = str(pd.Timestamp(temps[1]).tz_convert(tz='Asia/Shanghai'))
            except:
                print(repo['repo'], i, cmd)
        query = {"_id": repo['_id']}
        new_data = {"$set": {"tags": tags}}
        repo_info_table.update_one(query, new_data)
        print('success ' + str(repo['_id']))


def update_final_pulls_issues():
    db = connect_mongodb()
    repo_info_table = db['repo_info']
    pulls_table = db['pulls_info']
    issues_table = db['issues_info']
    patch_info_table = db['patches_info']
    commit_table = db['commits_info']
    pipeline = [
        {
            '$group': {
                '_id': '$repo_id'
            }
        }
    ]
    result = patch_info_table.aggregate(pipeline)
    for doc in result:
        repo_id = doc['_id']
        repo_query = {'_id': repo_id}
        repo = repo_info_table.find_one(repo_query)
        pulls = dict()
        # issues = dict()
        for pull in repo['pulls']:
            pull_query = {'_id': pull}
            pull_temps = pulls_table.find(pull_query)
            for pull_temp in pull_temps:
                for temp in pull_temp['pulls']:
                    try:
                        if 'merged_at' in temp.keys():
                            if temp['merged_at'] is not None:
                                pulls[temp['merge_commit_sha']] = {}
                                pulls[temp['merge_commit_sha']]['url'] = temp['url'].replace('api.', '').replace(
                                    '/repos/',
                                    '/')
                                pulls[temp['merge_commit_sha']]['merge_at'] = temp['merged_at']
                                if 'issue_url' in temp.keys():
                                    pulls[temp['merge_commit_sha']]['issue_url'] = temp['issue_url'].replace('api.',
                                                                                                             '').replace(
                                        '/repos/', '/')
                                else:
                                    pulls[temp['merge_commit_sha']]['issue_url'] = ''
                    except:
                        print(pull_temps)
                        print(pull_temp['pulls'])
                        print(pull_query)

        # for issue in repo['issues']:
        #     issue_query = {'_id': issue}
        #     issue_temps = issues_table.find(issue_query)
        #     for issue_temp in issue_temps:
        #         for temp in issue_temp['issues']:
        #             if 'pull_request' in temp.keys():
        #                 if temp['pull_request']['merged_at'] is not None:
        #                     issues[temp['url'].replace('api.', '').replace('/repos/', '/')] = {}
        #                     issues[temp['url'].replace('api.', '').replace('/repos/', '/')]['pull_url'] = \
        #                         temp['pull_request']['url'].replace('api.', '').replace('/repos/', '/')
        #                     issues[temp['url'].replace('api.', '').replace('/repos/', '/')]['merge_at'] = \
        #                         temp['pull_request']['merged_at']
        patch_query = {'repo_id': repo_id}
        patches = patch_info_table.find(patch_query)
        for patch in patches:
            if len(patch['final_fixing_commits']) == 0:
                continue
            print('begin ' + str(patch['_id']))
            patch_pulls = dict()
            # patch_issues = dict()
            final_fixing_commits = patch['final_fixing_commits']
            for fixing_commit in final_fixing_commits:
                if fixing_commit['commit_id'] in pulls.keys():
                    patch_pulls[fixing_commit['commit_id']] = {}
                    commit_temp_query = {'_id': fixing_commit['commits_info_id']}
                    commit_temp = commit_table.find_one(commit_temp_query)
                    patch_pulls[fixing_commit['commit_id']]['commit_at'] = \
                        commit_temp['commits'][fixing_commit['commit_id']]['publish_time']
                    patch_pulls[fixing_commit['commit_id']]['pull_url'] = pulls[fixing_commit['commit_id']]['url']
                    patch_pulls[fixing_commit['commit_id']]['issue_url'] = pulls[fixing_commit['commit_id']][
                        'issue_url']
                    patch_pulls[fixing_commit['commit_id']]['merge_at'] = pulls[fixing_commit['commit_id']]['merge_at']
            # for issue_url in issues.keys():
            #     for pull_commit in patch_pulls.keys():
            #         if issues[issue_url]['pull_url'] == patch_pulls[pull_commit]['url']:
            #             patch_issues[pull_commit] = {}
            #             patch_issues[pull_commit]['commit_at'] = patch_pulls[pull_commit]['commit_at']
            #             patch_issues[pull_commit]['issue_url'] = issue_url
            #             patch_issues[pull_commit]['pull_url'] = issues[issue_url]['pull_url']
            query = {"_id": patch['_id']}
            new_data = {"$set": {"final_pulls": patch_pulls}}
            patch_info_table.update_one(query, new_data)
            print('success ' + str(patch['_id']))


def generate_google_dependency_mongo():
    db = connect_mongodb()
    if 'dependencies' not in db.list_collection_names():
        # 创建集合
        db.create_collection('dependencies')
    dependencies_table = db['dependencies']
    origin_path = 'D:/go_dep'
    for dir_path in os.listdir(origin_path):
        for file_path in os.listdir(origin_path + '/' + dir_path):
            print('begin ' + str(file_path))
            f = open(origin_path + '/' + dir_path + '/' + file_path, 'r')
            content = f.read().split('\n')[1:]
            dependencies = []
            for i in content:
                if i == '':
                    continue
                temps = i.split(',')
                dependencies.append({'snapshot_at': temps[0], 'module_name': temps[1], 'module_version': temps[2],
                                     'dependency_name': temps[3], 'dependency_version': temps[4]})
            insert_mongo_many(dependencies_table, dependencies)
            print('success ' + str(file_path))


def nanyang_vuls():
    db = connect_mongodb()
    vul_table = db['vulnerabilities_info']
    f = open('./test.txt', 'r')
    content = f.read().split('\n')
    f.close()
    result = []
    for i in content:
        cve = i.split(',')[0]
        query = {'cve': cve}
        if not vul_table.find_one(query):
            result.append(cve)
    f = open('./need_add_vuls.txt', 'w')
    for i in result:
        f.write(i + '\n')
    f.close()


def addition_dependencies():
    f = open('./vul_affects.txt', 'r')
    content = f.read().split('\n')
    f.close()
    addition_vul_modules = dict()
    dependencies = set()
    for line in content:
        if line == '':
            continue
        temps = line.split(',')
        vul_name = temps[0]
        dependency_info = temps[1]
        dependency_name = dependency_info.split(':')[0]
        dependency_version = dependency_info.split(':')[1]
        dependencies.add(dependency_name)
        if vul_name not in addition_vul_modules.keys():
            addition_vul_modules[vul_name] = {}
        if dependency_name not in addition_vul_modules[vul_name].keys():
            addition_vul_modules[vul_name][dependency_name] = []
        if dependency_version not in addition_vul_modules[vul_name][dependency_name]:
            addition_vul_modules[vul_name][dependency_name].append(dependency_version)
    f = open('./addition_vul_modules.json', 'w')
    json.dump(addition_vul_modules, f)
    f.close()
    db = connect_mongodb()
    dependencies_table = db['dependencies']
    # 定义关键字列表
    keywords = list(dependencies)
    # 构建查询条件
    query = {
        "$or": [
            {"dependency_name": {"$in": keywords}},
            {"dependency_name": {"$regex": r"/v\[\d+\]$|\b(" + "|".join(keywords) + r")\b", "$options": "i"}}
        ]
    }

    # 执行查询
    results = dependencies_table.find(query)
    f = open('./addition_origin.txt', 'w')
    for i in results:
        f.write(i['module_name'] + ',' + i['module_version'] + ';' + i['dependency_name'] + ',' + i[
            'dependency_version'] + '\n')
    f.close()


def generate_addition_dependencies():
    result = dict()
    f = open('./addition_origin.txt', 'r')
    content = f.read().split('\n')
    f.close()
    for line in content:
        if line == '':
            continue
        temps = line.split(';')
        dependent_name = temps[0].split(',')[0]
        dependent_version = temps[0].split(',')[1]
        dependency_name = temps[1].split(',')[0]
        dependency_version = temps[1].split(',')[1]
        if dependency_name not in result.keys():
            result[dependency_name] = {}
        if dependency_version not in result[dependency_name].keys():
            result[dependency_name][dependency_version] = {}
        if dependent_name not in result[dependency_name][dependency_version].keys():
            result[dependency_name][dependency_version][dependent_name] = []
        if dependent_version not in result[dependency_name][dependency_version][dependent_name]:
            result[dependency_name][dependency_version][dependent_name].append(dependent_version)
    f = open('./addition_dependency.json', 'w')
    json.dump(result, f)
    f.close()


if __name__ == '__main__':
    generate_addition_dependencies()
