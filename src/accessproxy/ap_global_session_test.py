#! /usr/bin/env python
# -*- coding: utf-8 -*-

import time
import json
import logging
import traceback
import codecs
import urlparse
import MySQLdb
import requests
import cchardet
from pyquery import PyQuery
from gevent.pool import Pool
from gevent import monkey; monkey.patch_all();
from kazoo.client import KazooClient
import config
from requests.cookies import RequestsCookieJar

POOL_SIZE = 30

requests.packages.urllib3.disable_warnings()

redirect2apsso_cnt = redirect2sso_cnt = 0
error_5xx_domain = []
error_4xx_domain = []

ad_username = ''
ad_password = ''
results = []


def url_resolve(url):
    newquery = ''
    position = url.find('jsessionid')
    if position != - 1:
        url = url[:position]
    parsed_tuple = urlparse.urlparse(url)
    q = urlparse.parse_qs(parsed_tuple.query)
    if 'service' in q:
        s = ''.join(q['service'])
        s = url_resolve(s)
        q['service'] = s

    filter_list = ['redirect_url', 'ticket', 'request_id', 'code', 'state']
    for i in filter_list:
        if i in q:
            q.pop(i)

    for k, v in q.items():
        s = ''.join(q[k])
        s.encode('utf-8')
        q[k] = s

    sorted(q.items(), key=lambda q: q[0])
    flag = 0
    for k, v in q.items():
        v1 = str(v)
        if flag == 0:
            newquery = newquery + k + '=' + v1
            flag = 1
        else:
            newquery = newquery + '&' + k + '=' + v1

    oldtuple = parsed_tuple[:]
    l = []
    for i in oldtuple:
        l.append(i)

    l[4] = newquery
    newtuple = tuple(l)

    return urlparse.urlunparse(newtuple)


def test_domain(all_domain):
    domain, cookie = all_domain
    
    global redirect2apsso_cnt
    global redirect2sso_cnt
    post_data = {}
    result = u''
    session = requests.Session()
    apflag = 0
    ssoflag = 0
    ssourl = u''
    try:
        url = '%s://%s/' % ('https' if domain['always_use_https'] == 1 else 'http', domain['domain'])
        resp = session.get(url=url, verify=True, timeout=5, cookies = cookie)
        resp.encoding = cchardet.detect(resp.content)['encoding']
        global t
        t = resp.url
        for history in resp.history:
            if history.status_code == 302 and history.url.startswith(''):
                apflag = 1
                result += u'\t\tRedirect to APSSO...\n'
                redirect2apsso_cnt = redirect2apsso_cnt + 1

            if history.status_code == 302 and history.headers.get('Location', '').startswith(''):
                ssoflag = 1
                if 1 == apflag:
                    result += u'\t\t'
                result += u'\t\tRedirect to SSO...\n'
                redirect2sso_cnt = redirect2sso_cnt + 1
                ssourl = history.headers['Location']
                ssourl = ssourl.encode('utf-8')
#                break

            if apflag == 1:
                result += u'\t\t'
            if ssoflag == 1:
                result += u'\t\t\t' 
            history.url = url_resolve(history.url)   
            result += u'\t{status_code} {url}\n'.format(
                status_code=history.status_code,
                url=history.url,
            )

        else:
            try:
                title = PyQuery(resp.text)('title').text()
            except Exception as e:
                title = u'CAN\'T GET TITLE!\n'

            resp.url = url_resolve(resp.url)
            result += u'\t{status_code} {url} {title}\n'.format(
                status_code='%s' % resp.status_code if 400 <= resp.status_code <= 599 else resp.status_code,
                url=resp.url,
                title=title
            )
            if 500 <= resp.status_code <= 599:
                error_5xx_domain.append(domain['domain'])
            elif 400 <= resp.status_code <= 499:
                error_4xx_domain.append(domain['domain'])
    except requests.exceptions.Timeout as e:
        result += u'\t504x {e}\n'.format(e=e)
        error_5xx_domain.append(domain['domain'])
    except requests.exceptions.ConnectionError as e:
        result += u'\t502x {e}\n'.format(e=e)
    except requests.exceptions.SSLError as e:
        result += u'\tSSLError {e}\n'.format(e=e)
    except Exception as e:
        result += u'ERROR {e}\n'.format(e=e)


    if apflag == 1 and ssoflag == 1:
        domain['domain'] += u'\t\tvia AP and SSO'
    elif ssoflag == 1:
        domain['domain'] += u'\t\tvia SSO only'
    elif apflag == 1:
        domain['domain'] += u'\t\tvia AP only'
    else:
        domain['domain'] += u'\t\tvia neither AP nor SSO'

    results.append({'domain': domain['domain'], 'result': result})


def main():
    print('Start time: %s' % time.ctime())
    try:
        mysql_conn = MySQLdb.connect(
            host=config.mysql_host,
            port=config.mysql_port,
            user=config.mysql_user,
            passwd=config.mysql_passwd,
            db=config.mysql_db,
            charset=config.mysql_charset
        )
        mysql_conn.autocommit(True)
        mysql_cursor = mysql_conn.cursor(MySQLdb.cursors.DictCursor)
    except Exception as e:
        error_msg = 'Failed to connect to MySQL: {error_msg}'.format(error_msg=traceback.format_exc())
        logging.error(error_msg)

    first_visit_status = login_status = logout_status = 0

    session = requests.Session()
    try:
        resp = session.get(url = '', verify=True, timeout=5)
        first_visit_status = 1
    except Exception as e:
        print('First visit failed : %s' % e)

    post_data = {}
    html = PyQuery(resp.text)
    input_list = html('')('')
    for item in input_list:
        if item.type == '':
            continue
        post_data[item.name] = item.value
        post_data['username'] = ad_username
        post_data['password'] = ad_password
    
    try:
        resp = session.post(url = '', verify=False, timeout=5, data = post_data)
        if resp.status_code == 302 or resp.status_code == 307 or resp.status_code == 200 :
            login_status = 1
        else :
            print('Login failed ')
    except Exception as e:
        print('Login failed : %s' % e)

    
    if first_visit_status == 1 and login_status == 1:
        cookie_jar = RequestsCookieJar()
        cookie_jar.update(resp.cookies)

        mysql_cursor.execute('SELECT * FROM domain WHERE status=1')
        domains = mysql_cursor.fetchall()
        mysql_conn.close()
        gevent_pool = Pool(POOL_SIZE)
        gevent_pool.map(test_domain, [(d, cookie_jar)for d in domains])
        gevent_pool.join()
                

        logouturl = ''
        try:
            resp = session.get(url=logouturl, verify=True, timeout=5)
            if resp.status_code == 302 or resp.status_code == 307 or resp.status_code == 200 :
                logout_status = 1
            else :
                print('Logout failed ')
        except Exception as e:
            result += u'\tLogout ERROR {e}\n'.format(e=e)
     
    if logout_status == 1:
        results.sort(key=lambda x: (x['domain']))
        for result in results:
            print('%s' % result['domain'])
            print(result['result'].rstrip('\n'))
            print('')

        print('%s domain redirect to APSSO' % redirect2apsso_cnt)
        print('%s domain redirect to SSO' % redirect2sso_cnt)
        print('%s domain return 5xx' % len(error_5xx_domain))
        print(json.dumps(error_5xx_domain))
        print('%s domain return 4xx' % len(error_4xx_domain))
        print(json.dumps(error_4xx_domain))

        print('Finish time: %s' % time.ctime())
        print('-' * 20)
        print(' ')

if __name__ == '__main__':
    main()

