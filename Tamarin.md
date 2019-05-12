---
author:
	- name: kyh
	  github: kyh
	- name: leon
	  leon
---



# Installation

###### 环境

Linux Ubuntu 18.04LTS



###### 首先安装brew

先安装brew依赖工具：

```bash
sudo apt install build-essential curl file git
```

安装brew

```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/Linuxbrew/install/master/install.sh)
```



###### 加入环境变量

```bash
test -d ~/.linuxbrew && eval $(~/.linuxbrew/bin/brew shellenv)
test -d /home/linuxbrew/.linuxbrew && eval $(/home/linuxbrew/.linuxbrew/bin/brew shellenv)
test -r ~/.bash_profile && echo "eval \$($(brew --prefix)/bin/brew shellenv)" >>~/.bash_profile
echo "eval \$($(brew --prefix)/bin/brew shellenv)" >>~/.profile
```



###### 然后安装Tamarin-prover

```bash
brew install tamarin-prover/tap/tamarin-prover
```



###### Syntax Highlight (Optional)

可以用 Sublime Text 配合插件实现代码高亮。首先在Sublime里安装packagecontrol, 然后在里面安装 [**Tamarin**Prover](https://packagecontrol.io/packages/TamarinProver) (可能在墙外)



# Tamarin Walk Through

首先Tamarin作为一个Prover， 能指定几个状态之间的转化，以及安全守则，Tamarin 会自动分析在状态转换之间是否遵守了安全守则。

### Rule

在Tamarin中状态转换用 `rule` 表示。基本语法 demo (语法不是完整的)：

```c++
rule GeneratePrivKey:  // rule 的名字必须unique
	[]                 // 这是初始状态
-->
	[PrivateKey('A'), PrivateKey('B')]     // 结束状态
	
rule Client: 
	let
		PublicKey = 'g'^V   // 宏定义
	in
	[ PrivateKey(V) ]  // 状态声明必须和之前的保持一致，包括所包含的随机变量
--> 
    [ ClientHello(PublicKey, clientid) ] // 每一个状态名要大写 

```



### Fact

Tamarin 中的状态是用被称为`Fact`, Tamarin的执行过程如下：

1. 首先是一个完全空的状态
2. 根据`rule` 转换到下一个状态，比如demo中根据`rule GeneratePrivKey` 转入 `PrivateKey()` 状态
3. 找到可以匹配的状态，重复2， 比如demo 中`rule Client` 被执行2两次



#### Fact Attribute

实际上协议更复杂的，比如永久密钥 (Long Term Key, aka. Ltk) 是在理论上每一个状态都应该有，而有些变量比如随机数是临时的，Tamarin通过记号标记这些状态包含的变量的属性

| Syntax      | Explain                                |
| ----------- | -------------------------------------- |
| `~`         | fresh: 新建一个变量, 如`~temp`         |
| `$`         | pub: 公开的变量，比如公钥, 如`$pubkey` |
| `#`         | temporal: 时间变量, 如 `#timepoint`    |
| `PublicKey` | `PublicKey` 是一条消息, 如 `msg`       |
| `'ident`'   | 是一个公开的常量                       |



#### Persistent Fact

为了表示永久密钥这个Fact一直存在，引入标记：

| Syntax | Explain                                                      |
| ------ | ------------------------------------------------------------ |
| `!`    | 表示这个状态始终存在，如`Ltk($serverid, ~ltk)`, 这里使用`~` fresh是因为对于每一个Server的永久密钥是不同的 |

> In contrast, some facts in our models will never be removed from the state once they are introduced. Modeling this using linear facts would require that every rule that has such a fact in the left-hand-side, also has an exact copy of this fact in the right-hand side. While there is no fundamental problem with this modeling in theory, it is inconvenient for the user and it also might lead Tamarin to explore rule instantiations that are irrelevant for tracing such facts in practice, which may even lead to non-termination.
>
> For the above two reasons, we now introduce 'persistent facts', which are never removed from the state. We denote these facts by prefixing them with a bang (`!`).



同时 Tamarin也提供了内建的Fact：

| Syntax  | Explain                                      |
| ------- | -------------------------------------------- |
| `Fr()`  | 生成一个随机数                               |
| `Out()` | 输出信息将被攻击者看到，比如`Out(publickey)` |
| `In()`  | 输入信息可以被嗅探到，可能是伪造的，篡改的   |
|         |                                              |



`builtins` 在Tamarin里是内建函数，包含了

| builtin          | Explain                  | Example                  |
| ---------------- | ------------------------ | ------------------------ |
| `diffie-hellman` | 求指数，一般用于计算公钥 | `pubkey = 'g' ^ privkey` |





`functions` 是用户自己定义的函数，没有特殊说明的则是单向的函数，定义方法如下：

```javascript
functions: h1/2 // 定义了h1, 接受1个参数
functions: f1/2 // 定义了f1, 接受2个参数
```





oracle



### Init Rules

- generate private keys for different parties



### Key Leakage



### Misc

increase sqn

```c++
[User(sqn), In(m)] --> [User(sqn+m)]
```



Toggle = `SyncSuccess`,  `MacSuccess` ...

Party = (priv, priv) [toggle1, toggle2, ...] 

Communiate = PartyA[`on`, `off`, ...] --> PartyB[`off`]  ==> DoSomething