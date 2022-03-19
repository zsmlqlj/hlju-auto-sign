# -*- coding: utf-8 -*-
import sys
import json
import uuid
import asyncio
from aiocqhttp import message
from nonebot.command import Command
import oss2
import yaml
import base64
import requests
import re
import time
from pyDes import des, CBC, PAD_PKCS5
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlparse
from urllib3.exceptions import InsecureRequestWarning


#------------------nonebot--------------------

import nonebot
from nonebot import on_command, CommandSession
import pytz
from aiocqhttp.exceptions import Error as CQHttpError


# 早签到定时器
@nonebot.scheduler.scheduled_job('cron', hour = '8-9', minute = '*/20')
async def signNonebotScheduler():
    bot = nonebot.get_bot()
    try:
        await bot.send_group_msg(group_id = 949929123, message = signMessageStart())
    except CQHttpError:
        pass

# 晚签到定时器
@nonebot.scheduler.scheduled_job('cron', hour = '21-23', minute = '*/30')
async def signNonebotScheduler():
    bot = nonebot.get_bot()
    try:
        await bot.send_group_msg(group_id = 949929123, message = signMessageStart())
    except CQHttpError:
        pass

# @nonebot.scheduler.scheduled_job('cron', minute = '*')
# async def signNonebotScheduler():
#     bot = nonebot.get_bot()
#     try:
#         await bot.send_group_msg(group_id = 140414086, message = 'test')
#     except CQHttpError:
#         pass



#手动命令
@on_command('sign', aliases=('qd', '1', '签到'))
async def signCommand(session: CommandSession):
     clazz = session.get('clazz', prompt = '大佬想查询哪个班级的签到信息呢？俺签到酱帮你康康')
     clazzSignList = await getSignListByClazz(clazz)
     await session.send(clazzSignList)


@signCommand.args_parser
async def _(session: CommandSession):
    strippedArg = session.current_arg_text.strip()
    if session.is_first_run:
        if strippedArg:
            session.state['clazz'] = strippedArg
        return
    if not strippedArg:
        session.pause('大佬，班级不能为空，重来！')

    session.state[session.current_key] = strippedArg   


async def getSignListByClazz(clazz: str) -> str:
    for user in config['users']:
        apis = getCpdailyApis(user)
        session = getSession(user, apis)
        res = getUnSignedTasksByClazz(session, apis, user, clazz)
        log(res)
    return f'签到酱v1.1\n' + res     


#---------------------sign---------------------



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


# 获取今日校园api
def getCpdailyApis(user):
    apis = {}
    user = user['user']
    schools = requests.get(url='https://mobile.campushoy.com/v6/config/guest/tenant/list', verify=not debug).json()['data']
    flag = True
    for one in schools:
        if one['name'] == user['school']:
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
        exit(-1)
    # log(cookieStr)

    # 解析cookie
    for line in cookieStr.split(';'):
        name, value = line.strip().split('=', 1)
        cookies[name] = value
    session = requests.session()
    session.cookies = requests.utils.cookiejar_from_dict(cookies, cookiejar=None, overwrite=True)
    #log(session.cookies)
    return session


 















# 获取全部签到任务并返回未签到人信息
def getUnSignedTasks(session, apis, user):
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
        'content-type': 'application/json',
        'Accept-Encoding': 'gzip,deflate',
        'Accept-Language': 'zh-CN,en-US;q=0.8',
        'Content-Type': 'application/json;charset=UTF-8'
    }
    # 请求辅导猫-学生助理-我关注的-签到任务， 拿到所有签到任务名单
    res = session.post(
        url='https://{host}/wec-counselor-apps/counselor/homepage/getFollowsInProgress'.format(host=apis['host']),
        headers=headers, data=json.dumps({'moduleCode':'6'}), verify=not debug) # moduleCode = 6 为我关注的-签到
    unSignStudentList = ""    
    #log(res.json()) 
    for i in range(0, res.json()['datas']['totalSize']):
        result = res.json()
        # 判断签到任务是否处于启动状态
        if ifStart(result['datas']['rows'][i]['currentTime'], result['datas']['rows'][i]['beginTime'], result['datas']['rows'][i]['endTime']):
            # 拿到任务的 signWid, taskInstanceWid
            wid = re.search(r'\d+', res.json()['datas']['rows'][i]['pcUrl']).group()
            instanceWidParams = {
                "pageSize": 1,
                "pageNumber": 1,
                "taskWid": wid
            }
            instanceWidRes = session.post(
                url = 'https://{host}/wec-counselor-sign-apps/sign/counselor/querySignTaskDayStatistic'.format(host = apis['host']),
                headers = headers, data=json.dumps(instanceWidParams), verify = not debug)
            instanceWid = instanceWidRes.json()['datas']['rows'][0]['signInstanceWid']    
            content = result['datas']['rows'][i]['content']
            unSignStudentList = unSignStudentList + getUnSignStudentList(session, apis, wid, instanceWid, content)
    if unSignStudentList == "":
        return "恭喜！当前没有开启的签到任务或全员均完成签到"
    else:
        return unSignStudentList  


# 获取全部签到任务并返回未签到人信息--班级筛选
def getUnSignedTasksByClazz(session, apis, user, clazz):
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
        'content-type': 'application/json',
        'Accept-Encoding': 'gzip,deflate',
        'Accept-Language': 'zh-CN,en-US;q=0.8',
        'Content-Type': 'application/json;charset=UTF-8'
    }
    # 请求辅导猫-学生助理-我关注的-签到任务， 拿到所有签到任务名单
    res = session.post(
        url='https://{host}/wec-counselor-apps/counselor/homepage/getFollowsInProgress'.format(host=apis['host']),
        headers=headers, data=json.dumps({'moduleCode':'6'}), verify=not debug) # moduleCode = 6 为我关注的-签到
    unSignStudentList = ""    
    #log(res.json()) 
    # 判断当前是否有未全部签到任务
    for i in range(0, res.json()['datas']['totalSize']):
        result = res.json()
        # 判断签到任务是否处于启动状态
        if ifStart(result['datas']['rows'][i]['currentTime'], result['datas']['rows'][i]['beginTime'], result['datas']['rows'][i]['endTime']):
            # 拿到任务的 signWid, taskInstanceWid
            wid = re.search(r'\d+', res.json()['datas']['rows'][i]['pcUrl']).group()
            instanceWidParams = {
                "pageSize": 1,
                "pageNumber": 1,
                "taskWid": wid
            }
            instanceWidRes = session.post(
                url = 'https://{host}/wec-counselor-sign-apps/sign/counselor/querySignTaskDayStatistic'.format(host = apis['host']),
                headers = headers, data=json.dumps(instanceWidParams), verify = not debug)
            instanceWid = instanceWidRes.json()['datas']['rows'][0]['signInstanceWid']    
            content = result['datas']['rows'][i]['content']
            unSignStudentList = unSignStudentList + getUnSignStudentListByClazz(session, apis, wid, instanceWid, clazz,content)
    if unSignStudentList == "":
        return "恭喜！当前没有开启的签到任务或全员均完成签到"
    else:
        return unSignStudentList        
              

                 













# 抽取未签到人名            
def getUnSignStudentList(session, apis, wid, instanceWid, content):
    clazzDict = {
        '1' : '19电工集成1班',
        '2' : '19电工集成2班',
        '3' : '19电工集成3班',
        '4' : '19电工集成4班',
        '5' : '19电工自动化1班',
        '6' : '19电工自动化2班',
        '7' : '19电工自动化3班',
        '8' : '19电工自动化4班',
    } 
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
        'content-type': 'application/json',
        'Accept-Encoding': 'gzip,deflate',
        'Accept-Language': 'zh-CN,en-US;q=0.8',
        'Content-Type': 'application/json;charset=UTF-8'
    }
    # 请求未签到列表 
    detailParams = {
        "pageNumber": 1,
        "pageSize": 300,
        "signStatus": 2,
        "sortColumn": "userId asc",
        "taskWid": wid,
        "taskInstanceWid": instanceWid
    }
    res = session.post(
        url='https://{host}/wec-counselor-sign-apps/sign/counselor/querySingleSignList'.format(host=apis['host']),
        headers=headers, data=json.dumps(detailParams), verify=not debug)
    #log(res.json())
    nameList = '\n\n\n' + content + '\n' + '未签到名单\n\n' 
    for clazzNumber in range(1,9):
        clazzToCls = clazzDict.get(str(clazzNumber))
        nameList = nameList + '\n' 
        for i in range(0, len(res.json()['datas']['rows'])):
            if clazzToCls == res.json()['datas']['rows'][i]['cls']:
                nameList = nameList + res.json()['datas']['rows'][i]['name'] + '  ' + res.json()['datas']['rows'][i]['cls'] + '\n'      
    return nameList


# 抽取未签到人名--班级筛选            
# 1-8 19电工集成1班-19电工自动化4班
def getUnSignStudentListByClazz(session, apis, wid, instanceWid, clazz, content):
    clazzDict = {
        '1' : '19电工集成1班',
        '2' : '19电工集成2班',
        '3' : '19电工集成3班',
        '4' : '19电工集成4班',
        '5' : '19电工自动化1班',
        '6' : '19电工自动化2班',
        '7' : '19电工自动化3班',
        '8' : '19电工自动化4班',
    }
    clazzToCls = clazzDict.get(clazz)
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
        'content-type': 'application/json',
        'Accept-Encoding': 'gzip,deflate',
        'Accept-Language': 'zh-CN,en-US;q=0.8',
        'Content-Type': 'application/json;charset=UTF-8'
    }
    # 请求未签到列表 
    detailParams = {
        "pageNumber": 1,
        "pageSize": 300,
        "signStatus": 2,
        "sortColumn": "userId asc",
        "taskWid": wid,
        "taskInstanceWid": instanceWid
    }
    res = session.post(
        url='https://{host}/wec-counselor-sign-apps/sign/counselor/querySingleSignList'.format(host=apis['host']),
        headers=headers, data=json.dumps(detailParams), verify=not debug)
    
    nameList = '\n\n\n' + clazzToCls + content + '未签到名单\n\n'
    for i in range(0, len(res.json()['datas']['rows'])):
        if clazzToCls == res.json()['datas']['rows'][i]['cls']:
           nameList = nameList + res.json()['datas']['rows'][i]['name'] + '  ' + res.json()['datas']['rows'][i]['cls'] + '\n'     
    return nameList













# 判断处于开启状态的签到任务
def ifStart(currentTime, startTime, endTime):
    currentTimeDate = datetime.strptime(currentTime, "%Y-%m-%d %H:%M:%S")
    startTimeDate = datetime.strptime(startTime, "%Y-%m-%d %H:%M")
    endTimeDate = datetime.strptime(endTime, "%Y-%m-%d %H:%M:%S")
    if currentTimeDate > startTimeDate and currentTimeDate < endTimeDate:
        return True
    else: 
        return False   



































# 定时启动
def signMessageStart():
    for user in config['users']:
        apis = getCpdailyApis(user)
        session = getSession(user, apis)
        res = getUnSignedTasks(session, apis, user)
        log(res)
    return '签到酱v1.1\n' + res   









# 手动调起异步调试
# if __name__ == '__main__':
#     loop = asyncio.get_event_loop()
#     res = loop.run_until_complete(getSignListByClazz('3'))
#     loop.close



# # 调试
# def main_handler(event, context):
#     try:
#         signMessageStart()
#     except Exception as e:
#         raise e
#     else:
#         return '成功返回未签到人员名单'


# if __name__ == '__main__':
#     # print(extension)
#     print(main_handler({}, {}))







 
