#### 一 值得关注的枚举细节点：
1 某插件：Linenum一建枚举
2 几个细节：（1）OS version （2）Kernelversion （3）running services 
ps：列出当前进程：
```
ps aux | grep root

```
列出root进程反倒对提升权限本身至关重要的 
3 Installed packages and version：
检查是否存在过时 的入团简报重要  
4 logged in Users  是 了解其他用户到晋城以及如何了解他们在所什么 

列出当前进程  ps au

5 User home dir  ：能否访问其他路径的信息提示点 

## 二 首页目录：
ls/home查看主页重大任何内容  
ls -la 查看当前用户目录内 六一ssh  如果 不差的话至少也该检查ARP缓存机制
ls -l ~/.ssh 这是检查用户的 bash 记录也重要 例如是否操纵git仓库等行为 
history

sudo -l 查看 速冻pirivleeges  能否以其他用户身份运行这个命令，利用sudo -l 查看可能具有的信息 ，往往会蕴含着一些提示信息 

config file中即配置文件中也可能包含大量的信息内容，。conf 跟.v扩展名结尾的文件 
他们通常以.conf .config结尾命名 

shadow file：尝试利用用户查看shadow看卡能否透露出密码信息
具体细节查看：https://www.cyberciti.biz/faq/understanding-etcshadow-file/

/etc/passwd中直接获取信息内容

cronjob 是cron 里诶死鱼window的计划任务 主要存在于 ：
ls -la /etc/vron.daily中 

查看文件系统与附加驱动器观察是否有额外的挂在驱动器 ，可能会发现文件包含的额密码信息 等内容  命令：lsblk 

setgid 跟setgid 二进制文件允许用户以root的身份运行这命令然后无需授予root权限即可执行 

请帮我查看可写目录，这有助于观察corn以及观察可写目录是否可以利用
```
find / -path /proc -prune -o -type d -perm -o+w 2>dev/null
```
分析命令功能:
find / 告诉系统从根目录开始，向下搜索整个文件系统 

-path /proc -prune 
这个是 ：-path 或者/proc这个是对应路径为/proc的对象.且/proc是个虚拟的文件系统，信息上存储的是内存中的进程 
-prune:管阿金的时候是剪切 ，当find遇到合适-path /proc的目录的时候会跳过目录不进入子目录进行搜索 
为啥要修复/proc 就是在搜索查询，几千了里面到底哪个符合关键 

-o 关键信息 逻辑或  如果proc 则剪切 别往下在深度搜索了浪费，或者执行后面赛选  

type -d 只搜索目录，关心可写的目录内容 

-perm -o+w 
-perm这个是匹配权限，-o+w o表示other +w表示写权限，-表示是找包含浙西额权限，即使还有r跟x权限也包含其他人可写想，安全的意义是 如果系统中纯在人恶化一个低权限的 都可以在这里面2 >dev/null 将错误重定向 输出丶结果保持干净的问题 
找到那些具有可写的目录

Writeable Files ：是否存在全局可写的脚本或者文件信息，目的是可以添加一行命令在违规的信息内容进而造成可能的群贤提升 ：
```
find / -path /proc -prune -o -type f -perm -o+w 2>dev/null
```

### 第一章 如何枚举：
脚本自动枚举法：
1 https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS
2 https://github.com/rebootuser/LinEnum

### 一：如何获取态势感知 
假设我们通过一些手段取得基本的shell后，我们应该收集一些关于目标脚本的信息 

思路：1 面对和操作系统？ 需要查询基本操作手册，此内容假设以ubuntu为目标介绍策略技巧 

请注意对于命令本身的深度理解能力
（1）whoami 何种身份谁运行的
（2）id 我们用户属于那些用户组
（3）hostname服务器名称是啥，能否从规则中知晓信息呢
（4）ip -a 进入了哪个子网段呢，现在处于何种网段区间内
（5）sudo -l 能否以root用户身份使用sudo 执行操作无需多密码 

第一步：
查询操作系统版本内容 细节 ：
命令：`cat /etc/os-release`
![[Pasted image 20260215103055.png]]
那么为啥要这么查信息呢？因为细节更多，那么有了这些细节有啥用呢？
我们能看到操作系统详细版本，在ubuntu 此网站中可以知晓发布信息 我们需要去诶多功能是否已经过时或者已在维护中，这个信息能反映出是否存在已经有人挖到的0day可以供我们使用 
https://ubuntu.com/about/release-cycle
第二步：检查当前用户的$PATH
```
echo $PATH
```
得到的结果如下：
![[Pasted image 20260215103350.png]]
为啥查他呢?因为linux 系统每次执行命令都会在path中查找我们匹配命令中的可执行文件，从哪里找呢 ，就从他环境变量设计的路径中招，这就引入一个问题，如果环境变量匹配错误，以及匹配的路径具有写权限的画，我们就可以在环境变量引入的路径中插入自己想要的bash进而达到提升权限的目的，执行我们想执行的命令

第三步：查看用户设置所有环境变量:有些用户用密码懒得自己写直接附加到环境变量中了：
![[Pasted image 20260215103658.png]]
第四步：查看内核版本 
```
uname -a  或者是 cat /proc/version查看可能具有的内核已知提权漏洞 
```
![[Pasted image 20260215103822.png]]
第五步收集其他信息 
1 cpu类型 ：lscpu
![[Pasted image 20260215103924.png]]
2 服务器有哪些登录shell？
`cat /etc/shells`
![[Pasted image 20260215104022.png]]
记录登录shell指的是通过控制台或者是webshell进入的时候我们需要知道其权限问题，并且我们了解系统支持那些解释器，并且通过tty等进行交互升级以及绕过限制 
通过python的等进行shell逃逸以获取到更多的权限信息

3 了解有啥保护措施以及放手措施 
（1）例如exec shield 是位置无关可执行文件，PIE linux内核地址空间随机化补丁等等 为了防止将内存数据标记为不可写的问题 https://en.wikipedia.org/wiki/Exec_Shield
（2）https://linux.die.net/man/8/iptables
用于防火墙检查ip过滤包的内容 
（3）https://apparmor.net/
（4）https://www.redhat.com/en/topics/linux/what-is-selinux

![[Pasted image 20260215111452.png]]（5）https://github.com/fail2ban/fail2ban
![[Pasted image 20260215111647.png]]
fail2ban ：这个是封禁导致多次身份验证错误的主机
 （6）https://www.snort.org/faq/what-is-snort
 （7）https://wiki.ubuntu.com/UncomplicatedFirewall
### 第六步 了解系统上的驱动器跟共享文件夹观察 有哪些共享文件挂载的可能性 :

lsblk:系统块儿设备 U盘等，lpstat是了解挂载的打印机信息，观察能否利用一种打印机漏洞的东西来窃取相关信息

第七步 检查已经挂载没挂载的驱动器，能否挂载一个新的搜集敏感数据：
`fstab 这个可以看到已经挂在跟味瓜子啊的驱动器`
在/etc/fstab当中是个关键的linux系统配置文件，列出了在启动的时候的自动挂载的磁盘分区，等等，具体信息如下 ：

第八步：在域环境中考虑/etc/resolv.conf主机是否配置为内部DNS 
第九步检查arp  
```
arp -a 
```
检查目标主机还与哪些主机通信过

第十步：查看/etc/passwd信息
可根据/etc/passwd的信息点查看加密哈希值

在/etc/passwd内不同的hash值代表了不同的哈希加密方式
第11步：检查哪些用户拥有登录shell 
`grep "sh$" /etc/passwd`
第十二步：查看相关组信息以了解权限多少：
```
cat /etc/group
```
这个是查看行管大的组信息用户组分配文件夹信息
![[Pasted image 20260217165447.png]]
第十三步：getent 命令功能列出任何感兴趣组成员 ：
```
getent group sudo

```
![[Pasted image 20260217165543.png]]
第十四步：检查哪些用户有/home文件夹  
第十五步：检查.bash.history文件是否可读包含任何的可疑命令信息
第十六步：查找配置文件 拿到访问AD的信息内容，
第十七部：检查可能的ssh秘钥信息，检查ARP缓存
注意密码的重复使用问题！
### 第十八步：已挂载的文件系统
`df -h`
利用提升权限后，可以访问到本该卸载的文件系统的共享信息内容已获取敏感信息点
![[Pasted image 20260217170229.png]]
挂载的文件系统的信息内容，查看已经卸载的文件系统 
访问卸载文件系统  排除掉哪些注释信息# 将其表格形式输出出去即可
第十九部：查找所有隐藏的文件信息：
具体命令：
```
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null 
```
其中分析如下 ：find / 全盘搜索  
-type 指定文件搜索类型为 file -name是指定名字为.* 的 其中他们为通配符  
-exec是 exec 的执行的名词 告诉find只找到一个匹配的文件 就立即执行  
{}站位付 ，嗲表find刚才找到文件的路径，\;执行命令的孩子归姐夫  
并且将标准的输出错误 直接扔到空件重去
第二十个：指定的隐藏目录 ：
```
find / -type d -name ".*" -ls 2>/dev/null 
```
指定的隐藏目录信息：具体内容看上面没啥好说的 

第二十一个 ：几个地方存放临时文件 且所有的用户都可以看：
`/var/tmp ` /tmp 都用于存放临时文件 但是这俩的区别在于数据在这些文件系统中的存储时间。/var/tmp存放时间比、tmp唱的多 
、tmp系统重启后的画 临时分挖金胡别删除  


注意 有时候version的版本不是最终版本 

### Linux 服务与内部枚举：
一 内部 ：
内部枚举指的是内部的枚举跟配置方式等，首要考虑目标的系统可以通过那些接口与内部通信 ：
`ip a `
2 `/etc/hosts`查看之前的dns解析
3查看每个用户最后的登录时间 目的是了解用户啥时候登录系统以及登录频率。了解系统的使用范围 （已登录用户
）
`lastlog
![[Pasted image 20260218145328.png]]
输入who 这个米宁的画 可以知晓那些已登录的用户信息 之前有几个用户跟咱在一起用的那种 
命令的历史记录： `history`
可以查看这台机器登录前的输入的bash的及时记录 有助于及时排查
查找可能的历史脚本文件：
```
find / -type f \(-name *_hist -o -name *_history \) -exec ls -l {} \;2>/dev/null
```
分析命令 ：
1 find / 从根目录查找 -type 类型 f file类型  
2 `\(...\)` 用于将多个测试条件组合在一起，形成逻辑整体，且因为 ()在shell中有特殊含义 所以这里用反斜杠
3 -name 查询名字为 通配符 任意 _hist  -O 是逻辑or 满足左边或者右边 选择命令字为  xxx history 或者xxx hist的 
4 -exec \;_    这一组揭示了对每个搜索到的文件执行后续指令  {}占位符 代表当前找到的文件名  
5 将错误信息放到 /dev/null中 查看不了

访问 
`ls -la /etc/cron.daily/`这个是定时任务系统 系统可能会通过此任务提升权限 
重点关注proc系统 这个是关系同进程硬件 等系统信息内容 访问进程信息主要途径，且proc虚拟的 且有内核动态进程的  
查看他们 
如果枚举/proc 的话 可通过 /envrion去拿到环境变量与命令行的点 
/proc/cmdline是查看进程启动的完整命令公函参数地点  
![[Pasted image 20260218152905.png]]
这里的每一个信息都比较关键 

第三 过程：
`find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " " \n`
这个tr 是 将 `" 这里的命令" 转换为“ \n`
这里的\n换行符命令 
第四 服务系统可能的安装枚举， 如果是较旧的系统可能在内部有包含就服务的枚举
```
apt list --installed | tr "/" " " | cut -d" " -f1,3 |sed 's/[0-9]://g' |tee -a installed_pkgs.list
```
拆解命令 ：
1 apt list --installed  排序系统中所有通过apt安装的包  输出如下 ：
![[Pasted image 20260218154028.png]]
进行输出拆解：
2 `tr "/" " "`将所有/换成空格输出 方便辨析 
他是这样的：![[Pasted image 20260218154153.png]]
为啥要这么做？因为为了后面裁剪做准备  
3 现场取出 ：
`cut -d" " -f1,3`
以空格为分隔符 包含第一列包名跟第三列版本号  
![[Pasted image 20260218154438.png]]
-d相当于告诉cut 每个空格就多切一刀  -f 1，3  值得是 -f 取列 第一列跟第三列 只要包的名字跟版本号 其他的不需要  
第四步 清理版本号 做 epoch清理 
`sed 's/[0-9]://g'`
使用流便器其sed 删除形如 1： 2：版本号远端 lilnux 成为epoch这种逻辑  
正则解析 s 表示替换  0-9匹配后跟个冒号 g 代表全局替换为空  
就是把冒号的形式 删除掉 留下百衲本号的东西 


检查一下sudo 版本 ：
`sudo -V `
查询一下 ls -l 的/bin的版本号遗留 例如 /bin /usr/bin  /usr/sbin 可能跟 -v显示的不一样 

注意 ：
将现有的文件与gtfobin进行比较 然后来观察到底那些可以用于gtfobin
脚本文件学习：
```
#!/bin/bash 
dpkg -l | awk '{print $2}'>installed_pkgs.list 2>/dev/null 

for i in $(curl -s http://gtfobins.github.io/) | html2text |cut -d" " -f1|sed '/^[[:space:]]*$/d'); do 
  if grep -q "$i" installed_pkgs.list;then
      echo "Check GTFO for : $i "
  fi 
done

#清理临时文件
rm -f installed_pkgs.list

```
六：是strace 写入文件后稍后分析 利用strace 工具来跟踪分析操作系统跟信号处理
七：ps aux| root 的服务内容 
## 枚举系统记录凭据

一、凭据可能存在于配置文件中(.conf .bashrc .config.xml等等中)
备份.bak文件，数据库文件文本文件中等内容 
有几个重点需要关注一下：
1 `/var`包含主机上的运行的任何web服务网站的根目录，网站根目录可能包含数据库凭据或者其他类i小姑娘凭据  
wordpress 默认凭据的存储地点:
wp-config.php : 具体命令如下：
`grep 'DB_USER\|DB_PASSWORD' wp-config.php`
2 如果是遍历查找所有的配置文件的话统一的 脚本命令行 ：
```
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
```
这里分析细节：
从根目录开始搜索后：
1`! -path "*/proc/*"`排除掉/proc的目录 ：porc是虚拟文件系统白搜索而且还占据大量的问题卡死 
2 `-iname "*config*"`
找到包含config的文件  inme的含义是 不管大小写 只要包含config就行   




### 基于环境的权限提升

如何基于PATH进行环境变量提升 ：
账户的PATH包含一组绝对路径 允许用户在不指定绝对路径下直接输入命令，可以通过看 echo $PATH 查看内容

![[Pasted image 20260219145501.png]]
也就意味着我在 PATH的涉及到的路径上面歘杆件任何的脚本跟程序 都可以在此系统中任何目录中还行 

利用这一点，如果我们可以人为的添加任何路径文件到这个PATH上，这样就可以执行我们想执行的文件 
其操作如下：
```
1 echo $PATH 
```
先查看path究竟有没有我们新添加的。没有 
现在的我们的目的是把 . 这个目录添加到path文件中 
于是乎我们进行添加 ： 
`2 PATH=.:${PATH}` 中间来
这时候.是新变量 需要添加到 系统的PATH中 进行加载 
`3 export PATH`
加载完毕后：

echo $PATH 看看添加进来了没 ![[Pasted image 20260219151422.png]]
成功添加进来了后呢能干嘛呢 系统优先级先去.这个目录找 那么我们 在我这个文件里面输入一个叫做 ls 的命令  文件，让这个文件干嘛的 打印 文字 
这样子本来![[Pasted image 20260219151835.png]]
这个shabi 不应该作为任意脚本执行的但是由于修改了环境变量所以他可以 得到了劫持的作用

### 利用通配符可以进行正则表达化匹配同时可以提权 
通配符执行前可以被shell解析 ，通配符包含 ：
```
*  ：匹配文件名任意数量字符       ？匹配单个字符 【】 用于括起字符匹配指定位置大哥字符    ~  波浪展开用户主目录名称  - 连字符表示一系列字符
  
```
例子一：利用tar 来进行权限提升 
首先我们来看tar 是干嘛的：
`man tar `
![[Pasted image 20260219152610.png]]
关注到了这两个 其中含义为 
--checkpoint-action 选项云溪 EXEC到检查点时候执行操作 ，在tar命令执行完毕后运行任何操作系统的命令 ，通过创建这些名称文件  --checkpoint =1 并且指定通配符
tar 的规则是 在处理通配符的时候 如*的时候会取出当前目录下所有的文件名直接填写到目命令中 
此时如果把其中一个文件名干脆设置为命令的画  他就会原封不动无法识别出来，然后附加到后面买
例如 
目录下如果有个文件名为`checkpoint=1`那么就想当于是将其附加到 tar * 后面*
为啥要注意这俩 呢 ，因为这里拉可以干到 危险参数 ：1  --checkpoint =1  告诉tar 处理一个文件就出发一个检查点 
--checkpoint-action=exec=sh root.sh这个是告诉tar 一旦叨叨检查点的画执行sh.root.sh



## 逃离受限制的shell 
如何逃离：在受限制的shell中 只能执行一组特定的名玲玲  其中有如下
· rbash ：linux标准命令行解释器限制住了一些功能跟能力
https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html
2 具体shell具体处理

### 基于权限的权限提升
SUID版本：
执行的时候设置setuid位的时候 ，允许用户以其他的方式提升自己的权限suid位

一 基于SUID的权限提升：
搜索命令：
```
find  / -user root -perm -4000 -exec ls -ldb {} \;2>/dev/null
```
重点在于 为啥用-perm -4000 这个 原因在于：用于linnux中查找设置呃suid位的文件 且-4000的模式专门检查suid位 忽略其他的权限，的问题 

https://linuxconfig.org/how-to-use-special-permissions-the-setuid-setgid-and-sticky-bits
关于上述区分总结
如何识别呢  suid 中的setuid位：
用了一个可执行的x为的s s表示可执行为已经设置即为：

关于sed 在linux提权的位置：
sed 强大文本处理工具，处理文本文件，-n是sed 的选项不自动打印模式，sed默认打印每一行。用-n后他只会告诉你他打印的行 
`'1e exec bash 1？&0` le告诉sed 在处理大第一行后执行e迷宫。e让sed 执行打哦后面的明林 并且重新启动一个bashshell 问题 
这样子 结合sed 就好
