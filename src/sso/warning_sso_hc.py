#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import datetime
import sys
import os
import time
import json
import socket
import requests
import logging
import codecs
import smtplib
from pyquery import PyQuery
from kazoo.client import KazooClient
from gevent.pool import Pool
from gevent import monkey; monkey.patch_all();
from apscheduler.schedulers.blocking import BlockingScheduler
from elasticsearch import Elasticsearch

requests.packages.urllib3.disable_warnings()

reload(sys)

sys.setdefaultencoding('utf-8')

ad_username = ''
ad_password = ''
error_count = 0
result_list = []

es_cluster = [
    {'host': '', 'port': },
    {'host': '', 'port': },
    {'host': '', 'port': },
    {'host': '', 'port': },
    {'host': '', 'port': },
]

base_st = int(time.time())
ldap_result = []
sso_result = []


def alert_sender(text_result):
    d1 = {}
    d1['team'] = ''
    d1['channel'] = 'wechat,email'
    d1['callback_url'] = ''
    d1['msg'] = text_result

    s = requests.Session()
    postdata = json.dumps(d1)
    url = ''
    r = s.post(url = url, timeout = 5, data = postdata)


def takeTimestamp(elem):
    return elem['@timestamp']


def pull_es_sso():
    es = Elasticsearch(es_cluster)
    for i in xrange(1):
        query_body = {
            "size": 10000,
            "query": {
                "bool": {
                    "must": [
                        {
                            "query_string": {
                                "query": '',
                                "analyze_wildcard": True,
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": (base_st - i * 3600 - 300) * 1000,
                                    "lte": (base_st - i * 3600) * 1000 - 1,
                                    "format": "epoch_millis"
                                }
                            }
                        }
                    ],
                    "filter": [],
                    "should": [],
                    "must_not": []
                }
            }
        }

        res = es.search(index='log_healthcheck_sso-*', body=query_body, request_timeout=60)
        for hit in res['hits']['hits']:
            #        print(hit["_source"])
            d = {}
            s = hit["_source"]['@timestamp']
            l = list(s)
            l[10] = ' '
            s = ''.join(l)
            s = s.encode('utf8')
            t = datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f")
            t = t + datetime.timedelta(hours = 8)
            t = t.strftime("%Y-%m-%d %H:%M:%S.%f")

            d['@timestamp'] = t
            d['error_message'] = hit["_source"]['error']
            d['visitor_ip'] = hit["_source"]['visitor_ip']
            d['elapsed_total_seconds(s)'] = hit["_source"]['elapsed_total_time']
            d['time_1st'] = hit["_source"]['time_1st']
            d['time_login'] = hit["_source"]['time_login']
            d['time_logout'] = hit["_source"]['time_logout']

            sso_result.append(d)


def pull_es_ldap():
    es = Elasticsearch(es_cluster)
    for i in xrange(1):
        query_body = {
            "size": 10000,
            "query": {
                "bool": {
                    "must": [
                        {
                            "query_string": {
                                "query": '',
                                "analyze_wildcard": True,
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": (base_st - i * 3600 - 300) * 1000 * 1,
                                    "lte": (base_st - i * 3600) * 1000 - 1,
                                    "format": "epoch_millis"
                                }
                            }
                        }
                    ],
                    "filter": [],
                    "should": [],
                    "must_not": []
                }
            }
        }

        res = es.search(index='log_healthcheck_ldap-*', body=query_body, request_timeout=60)
        for hit in res['hits']['hits']:
            #        print(hit["_source"])
            d = {}
            s = hit["_source"]['@timestamp']
            l = list(s)
            l[10] = ' '
            s = ''.join(l)
            s = s.encode('utf8')
            t = datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f")
            t = t + datetime.timedelta(hours = 8)
            t = t.strftime("%Y-%m-%d %H:%M:%S.%f")

            d['@timestamp'] = t
            d['error_message'] = hit["_source"]['error_message']
            d['ldap_server'] = hit["_source"]['ldap_server']
            d['elapsed_total_seconds(ms)'] = hit["_source"]['elapsed_total_seconds']

            ldap_result.append(d)



def fetch_sso_ldap_status(error_count):
    text_return =u''
    try:
        pull_es_ldap()
    except Exception as e:
        text_return += u'Failed to pull ldap_data from es : %s\n\n' % e

    try:
        pull_es_sso()
    except Exception as e:
        text_return += u'Failed to pull sso_data from es : %s\n\n' % e

    ldap_result.sort(key=takeTimestamp)
    sso_result.sort(key=takeTimestamp)
    collector_ip = get_host_ip()
    collector_hostname = socket.gethostname()
    
    text_return += u'SSO节点连续 %d 次出现访问错误！\n近5分钟sso节点与ldap服务器访问情况如下。\n\n\n' % error_count

    for i in range(5):
        text_return += u'time: %s' % sso_result[3 * i]['@timestamp']
        text_return += u'\tcollector_ip : %s' % collector_ip
        text_return += u'\thostname : %s\n' % collector_hostname
        text_return += u'\tsso_nodes_status :\n'
        for k in range(3):
            if 3*i + k < len(sso_result) :
                if sso_result[3 * i + k]['error_message'] != 'ok':
                    text_return += u'\t\terror_message:  %s | ' % sso_result[3 * i + k]['error_message']
                    text_return += u'visitor_ip:  %s | ' % sso_result[3 * i + k]['visitor_ip']
                    text_return += u'elapsed_total_seconds(s):  %f\n' % sso_result[3 * i + k]['elapsed_total_seconds(s)']
        for j in range(8):
            if 8*i + j < len(ldap_result) :
                if ldap_result[8 * i + j]['elapsed_total_seconds(ms)'] < 0: 
                    text_return += u'\t\terror_message:  %s | ' % ldap_result[8 * i + j]['error_message']
                    text_return += u' %s \n' % ldap_result[8 * i + j]['ldap_server']
#                    f.write('elapsed_total_seconds(s):  %f\n' % ldap_result[8 * i + j]['elapsed_total_seconds(ms)'])
        text_return += u'\n'
    
    return text_return


def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
        return ip

def health_check(params):
    scheme, ip, port = params

    time_1st = time_login = time_logout = -1

    session = requests.session()
    try:
        resp = session.get('{scheme}://{ip}:{port}/'.format(scheme=scheme, ip=ip, port=port),
                           headers={
                               'Host': '',
                           },
                           verify=False,
                           timeout=5
                          )
        time_1st = resp.elapsed.total_seconds()
    except requests.exceptions.Timeout as e:
        result_list.append(((scheme, ip, port), False, '1st request timeout(5): %s' % e, (time_1st, time_login, time_logout, 101)))
        return
    except requests.exceptions.ConnectionError as e:
        result_list.append(((scheme, ip, port), False, '1st request connect error: %s' % e, (time_1st, time_login, time_logout, 102)))
        return
    except Exception as e:
        result_list.append(((scheme, ip, port), False, '1st error: %s' % e, (time_1st, time_login, time_logout, 103)))
        return

    if not resp or resp.status_code != requests.codes.ok:
        result_list.append(((scheme, ip, port), False, '1st request failed'), (time_1st, time_login, time_logout, 105))
        return
    
    post_data = {}
    html = PyQuery(resp.text)
    # execution_input_list = html('form')('input').filter(lambda i, item: item.name == 'execution')
    # execution = execution_input_list[0].value if len(execution_input_list) else ''
    input_list = html('form')('input')
    for item in input_list:
        if item.type == 'submit':
            continue
        post_data[item.name] = item.value
    post_data['username'] = ad_username
    post_data['password'] = ad_password
    # print post_data

    try:
        resp = session.post('{scheme}://{ip}:{port}/'.format(scheme=scheme, ip=ip, port=port),
                            headers={
                               'Host': '',
                           },
                           data=post_data,
                           verify=False,
                           timeout=10
                           )
        time_login = resp.elapsed.total_seconds()
    except requests.exceptions.Timeout as e:
        result_list.append(((scheme, ip, port), False, 'login request timeout(5): %s' % e, (time_1st, time_login, time_logout, 111)))
        return
    except requests.exceptions.ConnectionError as e:
        result_list.append(((scheme, ip, port), False, 'login request connect error: %s' % e, (time_1st, time_login, time_logout,112)))
        return
    except Exception as e:
        result_list.append(((scheme, ip, port), False, 'login request error: %s' % e, (time_1st, time_login, time_logout, 113)))
        return

    try:
        resp = session.get('{scheme}://{ip}:{port}/'.format(scheme=scheme, ip=ip, port=port),
                           headers={
                               'Host': '',
                           },
                           verify=False,
                           timeout=10
                          )
        time_logout = resp.elapsed.total_seconds()
    except Exception as e:
        print 'logout request error: %s' % e

    if not resp or (resp.status_code not in [requests.codes.ok, requests.codes.unauthorized]):
        result_list.append(((scheme, ip, port), False, 'login request failed'), (time_1st, time_login, time_logout, 121))
        return

    if resp.status_code == requests.codes.ok:
        result_list.append(((scheme, ip, port), True, 'ok', (time_1st, time_login, time_logout, resp.status_code)))
        return
    elif resp.status_code == requests.codes.unauthorized:
        result_list.append(((scheme, ip, port), False, 'unauthorized', (time_1st, time_login, time_logout, resp.status_code)))
        return
    else:
        result_list.append(((scheme, ip, port), False, 'status_code: %s' % resp.status_code, (time_1st, time_login, time_logout, resp.status_code)))
        return

def accessproxy_hc():
    print(time.ctime())
    zk = KazooClient(hosts='', read_only=True)
    logging.basicConfig()

    try:
        zk.start()
    except Exception :
        result_list.append((('https', '-1.-1.-1.-1', -1), False, 'did not get ip from Kazoo.Client', (-1, 104)))

    accessproxy_nodes, stat = zk.get('')
    accessproxy_nodes = json.loads(accessproxy_nodes)
    gevent_pool = Pool(10)
    gevent_pool.map(health_check, [('https', x['ip'], 443) for x in accessproxy_nodes])
    gevent_pool.join()
    zk.stop()

    es = Elasticsearch('')
    error_count_part = 0
    for result in result_list:
        (scheme, ip, port), is_running, error, (time_1st, time_login, time_logout, status_code) = result
        ip = ip.encode('utf8')
        if is_running != True:
            error_count_part += 1

        postdata = {}
        postdata['@timestamp'] = datetime.datetime.utcnow().isoformat()[:20]+'000000'
        postdata['visitor_ip'] = ip
        postdata['port'] = port
        postdata['time_1st'] = time_1st
        postdata['time_login'] = time_login
        postdata['time_logout'] = time_logout
        postdata['elapsed_total_time'] = time_1st + time_login + time_logout
        postdata['is_running'] = is_running
        postdata['error'] = error
        postdata['scheme'] = scheme
        postdata['collector_ip'] = get_host_ip()
        postdata['status_code'] = status_code
        print postdata
       
        es.index(index=('log_healthcheck_sso-' + time.strftime('%Y-%m-%d', time.localtime(time.time()))), doc_type='doc', body=postdata)

    global error_count
    if error_count_part != 0:
        error_count += 1
    else:
        error_count = 0

    print error_count, '\n'
    
    if error_count >=5 and error_count % 10 == 0:
        text = fetch_sso_ldap_status(error_count)
        alert_sender(text)
    del result_list[:]


if __name__ == '__main__':
    accessproxy_hc()
    scheduler = BlockingScheduler()
    scheduler.add_job(accessproxy_hc, 'interval',seconds = 60)

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()

