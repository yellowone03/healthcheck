#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import datetime
import socket
import sys
import os
import time
import ldap
from gevent import Timeout
from gevent.pool import Pool
from gevent import monkey; monkey.patch_all();
from apscheduler.schedulers.blocking import BlockingScheduler
from elasticsearch import Elasticsearch


reload(sys)

sys.setdefaultencoding('utf-8')

result_list=[]


def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
        return ip


def ldapsearch(ldap_server, base_dn, bind_dn, bind_credential, username):
    ldap_conn = ldap.initialize(ldap_server)
    ldap_conn.set_option(ldap.OPT_REFERRALS, 0)
    ldap_conn.set_option(ldap.OPT_NETWORK_TIMEOUT,3)
    ldap_conn.protocol_version = ldap.VERSION3
    try :
        ldap_conn.simple_bind_s(bind_dn, bind_credential)
    except ldap.LDAPError :
        ldap_conn.unbind()
        return 
        ldap_conn.abandon_ext()

    search_scope = ldap.SCOPE_SUBTREE
    search_filter = 'sAMAccountName={}'.format(username)

    results = ldap_conn.search(base_dn,search_scope,search_filter)
    result_type, result_data = ldap_conn.result(results, 0)

    if result_data == []:
        return None

    user_cn, user_info = result_data[0]

    user = {
            'cn': user_info.get('cn'),
            'employeeID': user_info.get('employeeID', []),
            'whenCreated': map(lambda x:datetime.datetime.strptime(x, '%Y%m%d%H%M%S.0Z').isoformat(), user_info.get('whenCreated', [])),
            'mail': user_info.get('mail'),
            'displayName': map(lambda x:x.decode('utf8'), user_info.get('displayName')),
            'distinguishedName': map(lambda x:x.decode('utf8'), user_info.get('distinguishedName')),
            'memberOf': map(lambda x:x.decode('utf8'), user_info.get('memberOf', [])),
            'sAMAccountName': user_info.get('sAMAccountName'),
            'name': user_info.get('name'),
        }

    return user


def ldap_health_check(params):
    ldap_server, base_dn, bind_dn, bind_credential, username = params
    print(ldap_server)
    # print(params)
    time_1st = -1

    try:
        starttime_1st = time.time()
        resp = ldapsearch(ldap_server, base_dn, bind_dn, bind_credential, username)
#        print (resp)
        endtime_1st = time.time()
        time_1st = endtime_1st - starttime_1st
        time_1st = round(time_1st,4)

    except Exception as e:
        print ('ldapserach_failed')
        result_list.append(((ldap_server, base_dn, bind_dn, bind_credential, username), False, 'error: %s' % e, (time_1st , -1 ) , {} ))
        return


    if not resp:
        print('nothing return ,maybe ldap bind failed')
        result_list.append(((ldap_server, base_dn, bind_dn, bind_credential, username), False, 'error:\'request failed, maybe timeout\'', (-1 , -1 ) , {} ))
        return
    else :
        print ('Success')
        result_list.append(((ldap_server, base_dn, bind_dn, bind_credential, username), True , 'no_error', (time_1st , 0) , resp ))
        return 



def hc_ldap():
    print(time.ctime())
    ldap_server_list = []
    base_dn = 'ou=,dc=,dc=com'
    bind_dn = ''
    bind_credential = '' 
    username = ''
    nodes_list = [(x,base_dn,bind_dn,bind_credential,username) for x in ldap_server_list]
    gevent_pool = Pool(10)
    gevent_pool.map(ldap_health_check,[x for x in nodes_list])
    gevent_pool.join()

#    params = (ldap_server_list[0], base_dn, bind_dn, bind_credential, username)
#    ldap_health_check(nodes_list[0])

    es = Elasticsearch('')

    ldap_result_list = []
    for result in result_list:
        (ldap_server, base_dn, bind_dn, bind_credential, username) , is_running, error, (times , status_code) , rec_data  = result
        user_data = {}
        user_data['@timestamp'] = datetime.datetime.utcnow().isoformat()
        user_data['is_running'] = is_running
        if times == -1:
            user_data['elapsed_total_seconds'] = times
        else :
            user_data['elapsed_total_seconds'] = times * 1000
        user_data['ldap_server'] = ldap_server
        user_data['base_dn'] = base_dn
        user_data['bind_dn'] = bind_dn
        user_data['bind_credential'] = bind_credential
        user_data['status_code'] = status_code
        user_data['error_message'] = error
        post_data = rec_data.copy()
        post_data.update(user_data)
          
        if is_running == True:
            print('normal_nodes:',post_data)
            print('\n')
            es.index(index=('log_healthcheck_ldap-' + time.strftime('%Y-%m-%d', time.localtime(time.time()))), doc_type='nodes', body=post_data)
            print('sent')
        else :
            print('error_nodes:',post_data)
            print('\n')
            es.index(index=('log_healthcheck_ldap-' + time.strftime('%Y-%m-%d', time.localtime(time.time()))), doc_type='nodes', body=post_data)
            print('sent')
        
        
        if not is_running:
            ldap_result_list.append(result)
          


    content = u'检测节点：%s\n' % os.uname()[1]
    if len(ldap_result_list) > 0:
        content = content + u'通过ldap访问发现故障节点：\n'
        for result in ldap_result_list:
            (ldap_server, base_dn, bind_dn, bind_credential, username) , is_running, error, (times , status_code) , rec_data  = result
            content = content + u'\tLDAP: %s, ERROR:%s, TIMES:%s\n' % ((ldap_server, base_dn, bind_dn, bind_credential, username), error, times)


    del result_list[:]
    print(content)
    content = ''
    print(content)
    return

if __name__ == '__main__':
    hc_ldap()
    scheduler = BlockingScheduler()
    scheduler.add_job(hc_ldap, 'interval', seconds = 60)
    
    try:
        scheduler.start()
    except (KeyboardInterrupt,SystemExit):
        scheduler.shutdown()
