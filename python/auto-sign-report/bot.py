import nonebot 
from os import path

if __name__ == '__main__':
    nonebot.init()
    nonebot.load_plugins(
        path.join(path.dirname(__file__), 'sign', 'plugins'), 'sign.plugins'
    )
    nonebot.run(host = '127.0.0.1', port = '8089')