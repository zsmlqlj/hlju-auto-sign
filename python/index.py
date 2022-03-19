# -*- coding: utf-8 -*-
import sys
import json
import uuid
import oss2
from requests.api import request
import yaml
import os
import base64
import requests
import threading
import hashlib  # at 2021.11.13
from Crypto.Cipher import AES # at 2021.11.13
import urllib # at 2021.11.13
from pyDes import des, CBC, PAD_PKCS5
from datetime import datetime, timedelta, timezone
from threading import Thread
from urllib.parse import urlparse
from urllib3.exceptions import InsecureRequestWarning

# debug模式
debug = True
if debug:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# 读取yml配置
def getYmlConfig(yaml_file='config.yml'):
    file = open(yaml_file, 'r', encoding="utf-8")
    file_data = file.read()
    file.close()
    config = yaml.load(file_data, Loader=yaml.FullLoader)
    return dict(config)


# 全局配置
config = getYmlConfig(yaml_file='config.yml')


# 获取当前utc时间，并格式化为北京时间
def getTimeStr():
    utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
    bj_dt = utc_dt.astimezone(timezone(timedelta(hours=8)))
    return bj_dt.strftime("%Y-%m-%d %H:%M:%S")


# 输出调试信息，并及时刷新缓冲区
def log(content):
    print(getTimeStr() + ' ' + str(content))
    sys.stdout.flush()

# 获取代理
def getProxy():
    proxyAvailableCount = 10
    while(proxyAvailableCount > 0):
        try:
            res = requests.get("http://127.0.0.1:5010/get/").json() 
            if (True == res.get("https")):
                return res.get("proxy")
        except:
            proxyAvailableCount = proxyAvailableCount - 1

# 获取今日校园api
def getCpdailyApis(user):
    apis = {}
    schools = requests.get(url='https://mobile.campushoy.com/v6/config/guest/tenant/list', verify=not debug).json()['data']
    flag = True
    for one in schools:
        if one['name'] == '黑龙江大学':
            if one['joinType'] == 'NONE':
                log(user['school'] + ' 未加入今日校园')
                exit(-1)
            flag = False
            params = {
                'ids': one['id']
            }
            res = requests.get(url='https://mobile.campushoy.com/v6/config/guest/tenant/info', params=params,
                               verify=not debug)
            data = res.json()['data'][0]
            joinType = data['joinType']
            idsUrl = data['idsUrl']
            ampUrl = data['ampUrl']
            if 'campusphere' in ampUrl or 'cpdaily' in ampUrl:
                parse = urlparse(ampUrl)
                host = parse.netloc
                res = requests.get(parse.scheme + '://' + host)
                parse = urlparse(res.url)
                apis[
                    'login-url'] = idsUrl + '/login?service=' + parse.scheme + r"%3A%2F%2F" + host + r'%2Fportal%2Flogin'
                apis['host'] = host

            ampUrl2 = data['ampUrl2']
            if 'campusphere' in ampUrl2 or 'cpdaily' in ampUrl2:
                parse = urlparse(ampUrl2)
                host = parse.netloc
                res = requests.get(parse.scheme + '://' + host)
                parse = urlparse(res.url)
                apis[
                    'login-url'] = idsUrl + '/login?service=' + parse.scheme + r"%3A%2F%2F" + host + r'%2Fportal%2Flogin'
                apis['host'] = host
            break
    if flag:
        log(user['school'] + ' 未找到该院校信息，请检查是否是学校全称错误')
        exit(-1)
    log(apis)
    return apis


# 登陆并获取session
def getSession(user, apis):
    user = user['user']
    params = {
        # 'login_url': 'http://authserverxg.swu.edu.cn/authserver/login?service=https://swu.cpdaily.com/wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay',
        'login_url': apis['login-url'],
        'needcaptcha_url': '',
        'captcha_url': '',
        'username': user['username'],
        'password': user['password']
    }

    cookies = {}
    # 借助上一个项目开放出来的登陆API，模拟登陆
    res = ''
    try:
        res = requests.post(url=config['login']['api'], data=params, verify=not debug)
    except Exception as e:
        res = requests.post(url='http://127.0.0.1:8080/wisedu-unified-login-api-v1.0/api/login', data=params, verify=not debug)
    
    # cookieStr可以使用手动抓包获取到的cookie，有效期暂时未知，请自己测试
    # cookieStr = str(res.json()['cookies'])
    cookieStr = str(res.json()['cookies'])
    log('开始' + user['username'] + '的签到')
    #log(cookieStr) 
    if cookieStr == 'None':
        log(res.json())
        return 'signFail'
    # log(cookieStr)

    # 解析cookie
    for line in cookieStr.split(';'):
        name, value = line.strip().split('=', 1)
        cookies[name] = value
    session = requests.session()
    session.cookies = requests.utils.cookiejar_from_dict(cookies, cookiejar=None, overwrite=True)
    #log(session.cookies)
    return session


# 获取最新未签到任务并全部签到
def getUnSignedTasksAndSign(session, apis, user, proxyIp):
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
        'content-type': 'application/json',
        'Accept-Encoding': 'gzip,deflate',
        'Accept-Language': 'zh-CN,en-US;q=0.8',
        'Content-Type': 'application/json;charset=UTF-8'
    }
    # 第一次请求每日签到任务接口，主要是为了获取MOD_AUTH_CAS
    res = session.post(
        url='https://{host}/wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay'.format(host=apis['host']),
        headers=headers, data=json.dumps({}), verify = not debug, proxies={"http": "http://{}".format(proxyIp), "https": "http://{}".format(proxyIp)})
    #log(res)    
    # 第二次请求每日签到任务接口，拿到具体的签到任务
    res = session.post(
        url='https://{host}/wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay'.format(host=apis['host']),
        headers=headers, data=json.dumps({}), verify=not debug, proxies={"http": "http://{}".format(proxyIp), "https": "http://{}".format(proxyIp)})
    #log(res)    
    if len(res.json()['datas']['unSignedTasks']) < 1:
        log('当前没有未签到任务')
        #exit(-1)
        return
    # log(res.json())
    for i in range(0, len(res.json()['datas']['unSignedTasks'])):
        if '2021年秋季学期疫情防控信息登记'== res.json()['datas']['unSignedTasks'][i]['taskName']:
            latestTask = res.json()['datas']['unSignedTasks'][i]
            params = {
            'signInstanceWid': latestTask['signInstanceWid'],
            'signWid': latestTask['signWid']
            }
            task = getDetailTask(session, params, apis, proxyIp)
            form = fillForm(task, session, user, apis)
            #log(task)
            submitForm(session, user, form, apis, proxyIp)  

# 获取签到任务详情
def getDetailTask(session, params, apis, proxyIp):
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
        'content-type': 'application/json',
        'Accept-Encoding': 'gzip,deflate',
        'Accept-Language': 'zh-CN,en-US;q=0.8',
        'Content-Type': 'application/json;charset=UTF-8'
    }
    res = session.post(
        url='https://{host}/wec-counselor-sign-apps/stu/sign/detailSignInstance'.format(host=apis['host']),
        headers=headers, data=json.dumps(params), verify=not debug, proxies={"http": "http://{}".format(proxyIp), "https": "http://{}".format(proxyIp)})
    data = res.json()['datas']
    return data


# 填充表单
def fillForm(task, session, user, apis):
    user = user['user']
    form = {}
    if task['isPhoto'] == 1:
        fileName = uploadPicture(session, user['photo'], apis)
        form['signPhotoUrl'] = getPictureUrl(session, fileName, apis)
    else:
        form['signPhotoUrl'] = ''
    if task['isNeedExtra'] == 1:
        form['isNeedExtra'] = 1
        extraFields = task['extraField']
        defaults = config['cpdaily']['defaults']
        extraFieldItemValues = []
        for i in range(0, len(extraFields)):
            default = defaults[i]['default']
            extraField = extraFields[i]
            if config['cpdaily']['check'] and default['title'] != extraField['title']:
                log('第%d个默认配置项错误，请检查' % (i + 1))
                exit(-1)
            extraFieldItems = extraField['extraFieldItems']
            for extraFieldItem in extraFieldItems:
                if extraFieldItem['content'] == default['value']:
                    extraFieldItemValue = {'extraFieldItemValue': default['value'],
                                           'extraFieldItemWid': extraFieldItem['wid']}
                    # 其他，额外文本
                    if extraFieldItem['isOtherItems'] == 1:
                        extraFieldItemValue = {'extraFieldItemValue': default['other'],
                                               'extraFieldItemWid': extraFieldItem['wid']}
                    extraFieldItemValues.append(extraFieldItemValue)
        # log(extraFieldItemValues)
        # 处理带附加选项的签到 
        form['extraFieldItems'] = extraFieldItemValues
    # form['signInstanceWid'] = params['signInstanceWid']
    form['signInstanceWid'] = task['signInstanceWid']
    form['longitude'] = user['lon']
    form['latitude'] = user['lat']
    form['isMalposition'] = task['isMalposition']
    form['abnormalReason'] = user['abnormalReason']
    form['position'] = user['address']
    form['uaIsCpadaily'] = True
    return form


# 上传图片到阿里云oss
def uploadPicture(session, image, apis):
    url = 'https://{host}/wec-counselor-sign-apps/stu/sign/getStsAccess'.format(host=apis['host'])
    res = session.post(url=url, headers={'content-type': 'application/json'}, data=json.dumps({}), verify=not debug)
    datas = res.json().get('datas')
    fileName = datas.get('fileName')
    accessKeyId = datas.get('accessKeyId')
    accessSecret = datas.get('accessKeySecret')
    securityToken = datas.get('securityToken')
    endPoint = datas.get('endPoint')
    bucket = datas.get('bucket')
    bucket = oss2.Bucket(oss2.Auth(access_key_id=accessKeyId, access_key_secret=accessSecret), endPoint, bucket)
    with open(image, "rb") as f:
        data = f.read()
    bucket.put_object(key=fileName, headers={'x-oss-security-token': securityToken}, data=data)
    res = bucket.sign_url('PUT', fileName, 60)
    # log(res)
    return fileName


# 获取图片上传位置
def getPictureUrl(session, fileName, apis):
    url = 'https://{host}/wec-counselor-sign-apps/stu/sign/previewAttachment'.format(host=apis['host'])
    data = {
        'ossKey': fileName
    }
    res = session.post(url=url, headers={'content-type': 'application/json'}, data=json.dumps(data), verify=not debug)
    photoUrl = res.json().get('datas')
    return photoUrl


# DES加密
def DESEncrypt(s, key='b3L26XNL'):
    key = key
    iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    k = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    encrypt_str = k.encrypt(s)
    return base64.b64encode(encrypt_str).decode()

# AES加密      at 2021.11.13
def myEncryptAES(data, key):
    ivStr = '\x01\x02\x03\x04\x05\x06\x07\x08\t\x01\x02\x03\x04\x05\x06\x07'
    aes = AES.new(bytes(key, encoding='utf-8'), AES.MODE_CBC,
                    bytes(ivStr, encoding="utf8"))
    text_length = len(data)
    amount_to_pad = AES.block_size - (text_length % AES.block_size)
    if amount_to_pad == 0:
        amount_to_pad = AES.block_size
    pad = chr(amount_to_pad)
    data = data + pad * amount_to_pad
    text = aes.encrypt(bytes(data, encoding='utf-8'))
    text = base64.encodebytes(text)
    text = text.decode('utf-8').strip()
    return text

# md5         at 2021.11.13
def md5(str):
    md5 = hashlib.md5()
    md5.update(str.encode("utf8"))
    return md5.hexdigest()

# 提交签到任务
def submitForm(session, user, form, apis, proxyIp):
    try:
        user = user['user']
        # Cpdaily-Extension
        extension = {
            "lon": user['lon'],
            "model": "OPPO R11 Plus",
            "appVersion": "9.0.12",
            "systemVersion": "8.0",
            "userId": user['username'],
            "systemName": "android",
            "lat": user['lat'],
            "deviceId": str(uuid.uuid1())
        }
        headers = {
            # 'tenantId': '1019318364515869',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 4.4.4; OPPO R11 Plus Build/KTU84P) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Safari/537.36 okhttp/3.12.4',
            'CpdailyStandAlone': '0',
            'extension': '1',
            'Cpdaily-Extension': DESEncrypt(json.dumps(extension)),
            'Content-Type': 'application/json; charset=utf-8',
            'Accept-Encoding': 'gzip',
            # 'Host': 'swu.cpdaily.com',
            'Connection': 'Keep-Alive'
        }
        formData = {
            'version':'first_v2',
            'calVersion':'firstv',
            'bodyString':
            myEncryptAES(json.dumps(form), 'ytUQ7l2ZZu8mLvJZ'),
            'sign':
            md5(
                urllib.parse.urlencode(form) + "&ytUQ7l2ZZu8mLvJZ")
        }
        formData.update(extension)
        res = session.post(url='https://{host}/wec-counselor-sign-apps/stu/sign/submitSign'.format(host=apis['host']),
                        headers=headers, data=json.dumps(formData), verify=not debug, proxies={"http": "http://{}".format(proxyIp), "https": "http://{}".format(proxyIp)})
        message = res.json()['message']
        if message == 'SUCCESS':
            log('自动签到成功')
        else:
            log('自动签到失败，原因是：' + message)
    except:
        raise Exception('自动签到失败，原因是代理可能出现问题')


# 主函数
def main():
    # 判断时间
    log(datetime.now().hour)
    if(False):
        threads = []
        length = 0
        # 签到线程
        for user in config['users']:
            length = length+1
            t = Thread(target = runUser, args = (user,))
            threads.append(t)

        for i in range(length):
            threads[i].start()

        for i in range(length):
            threads[i].join()   
    else:
        # 结束其他脚本
        os.system('ps aux|grep index.py|grep -v grep|cut -c 9-15|xargs kill -9') 



# 异步函数
def runUser(user):
    apis = getCpdailyApis(user)
    # 只要代理无法登录就重复尝试，直到成功签到当前 user 为止
    while(True):
        try:
            session = getSession(user, apis)
            proxyIp = getProxy()
            if str(session) != 'signFail':
                log('登陆成功')
                getUnSignedTasksAndSign(session, apis, user, proxyIp)
                log('搞定' + user['user']['username'] + '的签到')
                log('剩余线程--------{num} （共18个）'.format(num=threading.active_count()))
                break
        except Exception as e:
            log(e)
            continue    
    

# 提供给腾讯云函数调用的启动函数
def main_handler(event, context):
    try:
        main()
    except Exception as e:
        raise e
    else:
        return 'success'


if __name__ == '__main__':
    # print(extension)
    print(main_handler({}, {}))
