import argparse
import sys
import nmap
import datetime
import threading
import requests
import re
import json
import os
from queue import Queue

import urllib3

final_domains = []
ports = []


class PortScan(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self._queue = queue

    def run(self):
        while not self._queue.empty():
            scan_ip = self._queue.get()
            try:
                portscan(scan_ip)
                Scan(scan_ip)
            except Exception as e:
                print(e)
                pass


def portscan(scan_ip):
    """
    调用masscan程序进行端口扫描
    """
    temp_ports = []  # 设定一个临时端口列表
    os.system('masscan/bin/masscan ' + scan_ip + ' -p 1-65535 -oJ masscan.json --rate 2000')
    # 提取json文件中的端口
    with open('masscan.json', 'r') as f:
        for line in f:
            if line.startswith('{ '):
                temp = json.loads(json.dumps(line[:-2] + "}"))
                temp1 = eval(temp)["ports"][0]
                temp_ports.append(str(temp1["port"]))

    if len(temp_ports) > 50:
        temp_ports.clear()  # 如果端口数量大于50，说明可能存在防火墙，属于误报，清空列表
    else:
        ports.extend(temp_ports)  # 小于50则放到总端口列表里


def Title(scan_url_port,service_name):
    """
    获取网站的web应用程序名和网站标题信息
    """
    try:
        r = requests.get(scan_url_port, timeout=3, verify=False, )
        response = re.findall(u'<title>(.*?)</title>', r.content.decode("utf-8"), re.S)
        if response == []:
            final_domains.append((scan_url_port + '\t' + service_name).encode())
        else:
            # 若网站的响应头中无server字段，直接写入无server，若有就写
            banner = "无server"
            try:
                banner = r.headers['server']
            except Exception as e:
                pass
            finally:
                final_domains.append(scan_url_port + b'\t' + banner.encode("utf-8") + b'\t' + str(response[0]).encode("utf-8"))
    except Exception as e:
        print(e)
        pass


def Scan(scan_ip):
    """
    调用nmap识别服务
    """
    nm = nmap.PortScanner()
    try:
        for port in ports:
            ret = nm.scan(scan_ip, port, arguments='-Pn,-sS')
            service_name = ret['scan'][scan_ip]['tcp'][int(port)]['name']
            print('[*]主机 ' + scan_ip + ' 的 ' + str(port) + ' 端口服务为：' + service_name)
            if 'http' in service_name or service_name == 'sun-answerbook':
                if service_name == 'https' or service_name == 'https-alt':
                    scan_url_port = ('https://' + scan_ip + ':' + str(port)).encode()
                    Title(scan_url_port, service_name)
                else:
                    scan_url_port = ('http://' + scan_ip + ':' + str(port)).encode()
                    Title(scan_url_port, service_name)
            else:
                final_domains.append((scan_ip + ':' + str(port) + '\t' + service_name).encode())
    except Exception as e:
        print(e)


def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 ' + sys.argv[0] + " -i 192.168.1.1")
    parser.add_argument("-i", "--ip", help="The scan ip")
    parser.add_argument("-f", "--file", help="The scan ip list file")
    parser.add_argument("-o", "--output", help="Output file name")
    parser.add_argument("-t", "--thread", help="Number of Threads", default=100)
    return parser.parse_args()


def main(ip_list_file):
    """
    启用多线程扫描
    """
    queue = Queue()

    try:
        # 单个ip扫描
        if args.ip:
            final_ip = args.ip
            queue.put(final_ip)
            threads = []
            for i in range(int(args.thread)):
                threads.append(PortScan(queue))
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        else:
            # 批量ip扫描
            f = open(ip_list_file, 'rb')
            for line in f.readlines():
                final_ip = line.decode().strip('\n')
                queue.put(final_ip)
            threads = []
            for i in range(int(args.thread)):
                threads.append(PortScan(queue))
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            f.close()
    except Exception as e:
        print(e)
        pass


if __name__ == '__main__':
    start_time = datetime.datetime.now()
    urllib3.disable_warnings()
    args = parse_args()
    # 判断是否指定ip列表文件
    if args.file == None:
        main("ip.txt")
    else:
        main(args.file)
    tmp_domians = []
    for tmp_domain in final_domains:
        if tmp_domain not in tmp_domians:
            tmp_domians.append(tmp_domain)
    # 判断是否指定文件输出
    if args.output is True:
        for url in tmp_domians:
            with open(str(args.output), 'ab+') as ff:
                ff.write(url + '\n'.encode())
    else:
        for url in tmp_domians:
            with open(r'scan_url_port.txt', 'ab+') as ff:
                ff.write(url + '\n'.encode())
    spend_time = (datetime.datetime.now() - start_time).seconds
    print('程序共运行了： ' + str(spend_time) + '秒')
