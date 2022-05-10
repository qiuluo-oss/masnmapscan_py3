# masnmapscan_py3

本项目在[masnmapscan-V1.0](https://github.com/hellogoldsnakeman/masnmapscan-V1.0)的基础上进行修复调整，解决masscan与nmap无法联动的问题，是基于python3开发的。已经集成masscan，无需做任何操作，开箱即用。可以单个IP扫描，也可以批量扫描。

### 安装

1、cd masnmapscan_py3

2、pip3 install -r requirements.txt

3、编译masscan

cd masscan/

make

### 使用

optional arguments:

-h, --help  show this help message and exit

-i --ip IP  The scan ip

-f --file FILE  The scan ip list file

-o --output OUTPUT  Output file name

-t --thread THREAD   Number of Threads

Example: python3 masnmapcan_py3.py -i 192.168.1.1


### module 'nmap' has no attribute 'PortScanner'问题解决方法

1、pip3 uninstall nmap

2、pip3 uninstall python-nmap

3、pip3 install python-nmap

### 引用原作者的话

整合了masscan和nmap两款扫描器，masscan扫描端口，nmap扫描端口对应服务，二者结合起来实现了又快又好地扫描。并且加入了针对目标资产有防火墙的应对措施

首先pip install -r requirements.txt安装所需插件，然后将ip地址每行一个保存到txt文本里，与本程序放在同一目录下，masscan安装完成后也与本程序放在同一目录下，运行程序即可。最终会在当前目录下生成一个scan_url_port.txt的扫描结果

本程序仅供于学习交流，请使用者遵守《中华人民共和国网络安全法》，勿将此工具用于非授权的测试，程序开发者不负任何连带法律责任。
