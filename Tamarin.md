---
acknowledgement: kyh (kyhn7@github.com) is co-author of this doc
---

# 0. Installation

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



# 1. Tamarin Walk Through

首先Tamarin作为一个Prover， 能指定几个状态之间的转化，以及安全守则，Tamarin 会自动分析在状态转换之间是否遵守了安全守则。

## 1.1 Rule

在Tamarin中**状态转换**用 `rule` 表示。基本语法 demo (语法不是完整的)：

```c++
rule GeneratePrivKey:  // rule 的名字必须unique
	[]                 // 这是前提状态
-->
	[PrivateKey('A'), PrivateKey('B')]     // 结果状态
	
rule Client: 
	let
		PublicKey = 'g'^V   // 宏定义
	in
	[ PrivateKey(V) ]  // 状态声明必须和之前的保持一致，包括所包含的随机变量
--> 
    [ ClientHello(PublicKey, clientid) ] // 每一个状态名要大写 

```

一个 `rule` 由两个状态组成，一个**前提状态**(<dfn> premise </dfn>) 和一个 **结果状态** (<dfn>conculsion</dfn>)。只有满足前提状态就能激活`rule` 进入结果状态。`rule` 还可以在中间插入**活动** (<dfn>action</dfn>)。

`let...in` 表示一个**宏定义**(<dfn>local macros</dfn>)。它所作的是想C语言那样把表达式所以有的 `RHS` 替换成 `LHS`。

宏定义也可以串联：

```c++
rule Whatever:
	let
		a = 'g' ^ q
		b = a ^ q
	in
	[] --> []
```

`b` 的右手边含有的`a` 也会被替换成 `'g' ^ q`。



## 1.2 Fact

Tamarin 中的**状态** 是由多个**事实** (<dfn>fact</dfn>) 组成的, Tamarin的执行过程如下：

1. 首先是一个完全空的状态集合 (<dfn>system state</dfn>)
2. 根据`rule` 转换到下一个状态  (<dfn>rewrite</dfn>), 即从状态集里删除等号左边，加上等号右边的状态， 其中状态集合的变量用于初始化等式左边 (instantiated with the matched values)。注意如果一个前提有多个Fact, 他们被认为同时初始化。比如demo中根据`rule GeneratePrivKey` 转入 `PrivateKey()` 状态
3. 找到可以匹配的状态，重复2。 比如demo 中`rule Client` 被执行2两次



### 1.2.1 Linear Facts

实际上协议更复杂的，比如有些Fact比如随机数是临时的，Tamarin通过记号标记这些状态包含的变量的属性

| Syntax      | Explain                                        |
| ----------- | ---------------------------------------------- |
| `~`         | fresh: 新建一个变量, 如`~temp`                 |
| `$`         | pub: 公开的变量，比如公钥, 如`$pubkey`         |
| `#`         | temporal: 时间变量, 如 `#timepoint`            |
| `PublicKey` | `PublicKey` 是一条消息, 如 `msg`               |
| `'ident'`   | 是一个公开的常量，比如`pubkey = 'g' ^ privkey` |



#### 1.2.1.1 Special Facts

同时 Tamarin也提供了内建的Fact：

| Syntax  | Explain                                      |
| ------- | -------------------------------------------- |
| `Fr()`  | 生成一个随机数                               |
| `Out()` | 输出信息将被攻击者看到，比如`Out(publickey)` |
| `In()`  | 输入信息可以被嗅探到，可能是伪造的，篡改的   |

`In` 和 `Out` 是符合`Dolev-Yao` 的攻击者模型的。

#### 1.2.1.2 Linear Facts

以上Facts 统称 **线性事实** (<dfn>Linear facts</dfn>), 线性事实 由 `rule` 生成，也可以被`rule` 作为初始状态使用 (produced & consumed by rules)。

### 1.2.2 Persistent Fact

一些状态永久密钥(Long Term Key, aka. Ltk)在理论上每一个状态转换都应该有, 这意味着我们需要在所有的`rule` 的初始状态和结束状态写一遍这个事实。

Tamarin 引入**永久事实** (<dfn>Persistent Fact</dfn>) 表明一直存在，只需要声明一遍就能表示它会在所有`rule` 的输入输出中包含，引入标记：

| Syntax | Explain                                                      |
| ------ | ------------------------------------------------------------ |
| `!`    | 表示这个状态始终存在，如`!Ltk($serverid, ~ltk)`, 这里使用`~` fresh是因为对于每一个Server的永久密钥是不同的 |



### 1.2.3 Persistent v.s. Linear

//TODO: <https://tamarin-prover.github.io/manual/book/005_protocol-specification.html>

### 1.2.4 Action Facts

首先我们展示一下加入Action Fact后的 `rule`

```javascript
rule Client: 
	[ PrivateKey(V) ]  // 前提
--[SessionKey(V)]->  // Action Fact
    [ ClientHello('g'^V, clientid) ] // 结果
```

我们可以理解为这条规则被 `SessionKey(V)` 标记 (<dfn>labeled</dfn>)。我们会在 [1.4 Security Properties](1.4 Security Properties) 中介绍它的作用。



## 1.3 Equations & Functions

用户可以自己定义**函数**， 在Tamarin中函数在没有特殊说明的情况下是单向的函数。定义方法如下

```javascript
functions: h1/1 // 定义了h1, 接受1个参数
functions: f1/2 // 定义了f1, 接受2个参数
```



**方程**则是用于阐明函数的属性的，比如非对称加密能加解密信息：

```javascript
functions: aenc/2, adec/2
equations: adec(aenc(m, pk(sk)), sk) = m
```

注意方程要满足一些条件

- 等式右边出现的变量必须在左边出现



`builtins` 在Tamarin里是内建函数，一般用于加密，包含了

| builtin                 | Explain                  | Example                  | equations                                                    |
| ----------------------- | ------------------------ | ------------------------ | ------------------------------------------------------------ |
| `diffie-hellman`        | 求指数，一般用于计算公钥 | `pubkey = 'g' ^ privkey` | `(x^y)^z = x^(y*z), x^1 = x, x*y = y*x, (x*y)*z = x*(y*z), x*1 = x, x*inv(x) = 1` |
| `hashing`               |                          |                          |                                                              |
| `asymmetric-encryption` |                          | `aenc(<x,y>, pkB)`       | `dec(aenc(m, pk(sk)), sk) = m`                               |
| `signing`               |                          |                          | `verify(sign(m,sk),m,pk(sk)) = true`                         |
| `revealing-signing`     |                          |                          | `revealVerify(revealSign(m,sk),m,pk(sk)) = true` , `getMessage(revealSign(m,sk)) = m` |
| `symmetric-encryption`  |                          |                          | `sdec(senc(m,k),k) = m`                                      |
| `bilinear-pairing`      |                          |                          |                                                              |
| `multiset`              |                          |                          |                                                              |
|                         |                          |                          |                                                              |

//TODO: Table above not finished



## 1.4 Security Properties

首先一个rule 能被多个 `Action Fact` 标记，而利用这些标记我们可以实现定义安全规范，首先我们需要了解一下新的记号(github 不能正确显示LATEX)：

| Syntax    | Explain                                |
| --------- | -------------------------------------- |
| `All`     | 相当与 $\forall$                       |
| `Ex`      | $\exists$                              |
| ==>       | 蕴含                                   |
| &         |                                        |
| \|        |                                        |
| `not`     |                                        |
| `#`       | 时间点， 和1.2.1定义相同               |
| `f @ i`   | f 发生在时间点 `i`, 这里的`#` 可以省略 |
| `#i = #j` | 同时                                   |
| `x = y`   | x, y 两条信息相等                      |
| `K(msg)`  | `msg` 被攻击者知道了                   |
| `.`       | so that                                |

优先级(由高到低)

- `not`
- `&`
- `|`
- `==>`

比如这样一个规则：

```javascript
rule fictitious:
   [ Pre(x), Fr(~n) ]
 --[ Act1(~n), Act2(x) ]-->
   [ Out(<x,~n>) ]
```



定义安全规则使用 lemma 关键字:

```javascript
lemma distinct_nonces: 
	all-traces // 可省略
    "All n #i #j. Act1(n)@i & Act1(n)@j ==> #i=#j"
```

这里`all-traces` 指的是对于所有的状态转换执行路径(<dfn>traces</dfn>) `lemma`都要成立，默认是开启的，当然也可以替换成 `exists-trace `， 只要符合一条路径就能成立。

### 1.4.1 Secrecy

通常测试密钥是否被泄露会有固定的方法，首先定义密钥泄露的规则：

```javascript
// Compromising an agent's long-term key
rule Reveal_ltk:
  [ !Ltk($X, ltkX) ] --[ Reveal($X) ]-> [ Out(ltkX) ]
```

接下来定义安全规则：

```javascript
lemma:
	"
	All n #i. Secret(n) @i & Role('A') ==> (
    	not (Ex #j. K(n)@j) |
        (Ex B #j. Reveal(B)@j & Honest(B)@i)
    )
	"
```



### 1.4.2 Authentication

首先我们定义两个角色，他们负责接受和发送消息

```javascript
rule Send:
[Fr(~nsend), !Ltk($S, ltkS)]
--[Send($S, <$S, ~nsend>)]->
        [
        	Sent($S, ltkS, ~nsend),
   			Out(aenc(<$S, ~nsend>, ltkA))
        ]
rule Recv:
	[!Pk($S, pk(skS)),
    In(aenc(<$S, ~nsend>, skS))]
--[Recv($R, <$S, nsend>),
   Authentic($S,<$S, nsend>), 
   Honest($S), Honest($R)
   ]->
             [Sent($R, pk(skA), $S, <$S, nsend>)]
  
```



接下来我们就能定义验证：

```javascript
lemma message_authentication: 
    "All b m #i. Authentic(b,m) @i
     ==> (Ex #j. Send(b,m) @j & j<i)"
```



### 1.4.3 Observational Equivalence

观察等价要证明两个状态（比如执行协议的两个不同实体）无法让攻击者观察到不同，比如一个投票系统，尽管攻击者无法知道谁在投票，但是可以利用差分信息统计投给不同人的票数。

因此我们引入差分操作符：

| operator    | explain          |
| ----------- | ---------------- |
| `diff( , )` | 证明两个状态系统 |

比如下面发送者生成两个临时值，然后选取`~a` 或者 `~b` 加密并发送

```javascript
// Generate a public key and output it
// Choose two fresh values and reveal one of it
// Encrypt either the first or the second fresh value
rule Example:
    [ Fr(~ltk)
    , Fr(~a)
    , Fr(~b) ]
  --[ Secret( ~b ) ]->
    [ Out( pk(~ltk) )
    , Out( ~a )
    , Out( aenc( diff(~a,~b), pk(~ltk) ) )
    ]
```

在这个例子里攻击者无法计算出`~b`

```javascript
lemma B_is_secret:
  " /* The intruder cannot know ~b: */
    All B #i. (
      /* ~b is claimed secret implies */
      Secret(B) @ #i ==>
      /* the adversary does not know '~b' */
      not( Ex #j. K(B) @ #j )
    )
```

但是由于攻击者知道`~a` 所以可以计算出`aenc(~a)`, 因此知道第二条信息是否是a 或者 b



## 1.5 Oracle

//TODO



# 2. Model Protocol

## 2.0

本章会介绍一下5G AKA 的model 的一部分，首先是一些Prerequisites

| Entity           | Contain                                                      |
| ---------------- | ------------------------------------------------------------ |
| Subscriber       | UE/ USIM(Universal Subscriber Identity Module)/ SUPI/ K(Long-term Key shared with Serving Network)/ SQN(Sequence Number used to prevent replay attack) |
| Home Networks    | HNID(Home Network ID)/ pkHN(Publickey)/ K(Long-term Key shared with Subscriber)/ SQN(Sequence Number used to prevent replay attack) |
| Serving Networks | SNID(Serving Network ID)                                     |

## 2.1 Define Secure Channels

5G的信道如下：

| Channels                         | Descriptions                                                 |
| -------------------------------- | ------------------------------------------------------------ |
| Subscriber <-> Serving Network   | Not Secure(can be modeled using Facts In() and Out())        |
| Serving Network <-> Home Network | Secure(In this version, however, the channel can be compromised) |

定义不同的通信通道，比如下面第1、2个定义了在 Serving Network <-> Home Network(HSS) 的两个安全信道，第3、4定义了当信道不安全的情况：

```javascript
/************************************/
/*    Channel: SEAF .<->. HSS       */
/************************************/
// This is a standard, secure channel abstraction, as previously used in work 
// by Basin, Radomirovic and Schmid: Modeling Human Errors in Security Protocols
// (CSF 2016)
// This version does provide replay protection but is not order-preserving.

rule send_secure:
	[SndS(A,B,m)]
	-->
	[Sec(A,B,m)]

rule receive_secure:
	[Sec(A,B,m)]
	-->
	[RcvS(A,B,m)]

rule secureChannel_compromised_in:
	[In(<A,B,x>)]
	--[
		Rev(A,'secureChannel'),
		Injected(x)
	]->
	[Sec(A,B,x)]

rule secureChannel_compromised_out:
	[Sec(A,B,m)]
	--[Rev(B,'secureChannel')]->
	[Out(m)]
```

## 2.2 Model the entities

定义初始化规则，比如下面定义了初始化一个归属地网络的规则：

```javascript
rule init_homeNet:
	[Fr(~sk_HN),
	  Fr(~idHN)]
	--[ HomeNet(~idHN) ]->
	[!HSS(~idHN, ~sk_HN),
	 !Pk(~idHN, pk(~sk_HN)),
	 Out(<~idHN, pk(~sk_HN)>)]
```



## 2.3 Compromised Keys

接下来我们通过rule来定义当我们泄露密钥的情况, 比如下面的对称密钥被泄露

```javascript
// Compromised subscriptions (symmetric key k)
rule reveal_Ltk_Sym:
	[!Ltk_Sym(~supi, ~idHN, ~k, ~sqn_root)]
	--[
		// Security properties
		Rev(~supi, <'k', ~k>),
		Rev(~idHN, <'k', ~k>)
	]->
	[Out(~k)]
```



## 2.4 Define Protocol Rules

根据协议的验证模型定义规则。首先是AKA的验证流程

![](img\5gaka-process1.png)

![](img\5g-aka-process2.jpg)

Because the whole process is complicated, we only take a part of the process(Figure 2) as example



```C
/************************************/
/*       Protocol Rules             */
/************************************/

// Attach Request
rule ue_send_attachReq:
	let
		suci = < aenc{<~supi, ~R>}pk_HN, ~idHN>
		msg = suci
	in
	[!Ltk_Sym(~supi, ~idHN, ~k, ~sqn_root),
	 !Pk(~idHN, pk_HN),
	 Fr(~R),
	 Fr(~tid)]
	--[
		// Executability
		Start_UE_Session(~supi)
	]->
	[St_1_UE(~tid, ~supi, ~idHN, ~k, ~sqn_root),
	 Out(msg)]

// Attach Request + Authentication Initiation Request (AIR)
// NOTE: The AIR message is in fact the initial authentication request of the service "Nausf_UEAuthentication_Authenticate" (see TS 33.501 9.6.2).
rule seaf_receive_attachReq_send_air:
	let
		suci = <conc_supi,  idHN>
		msg = <suci, SNID >

	in
	[!SEAF(~idSN, SNID),
	 Fr(~tid),
	 In(suci)]
	--[
		// Executability
		Start_SEAF_Session(~idSN)
	]->
	[St_1_SEAF(~tid, ~idSN, SNID, conc_supi, idHN),
	 SndS(~idSN, idHN, <'air', msg>)]

// Authentication Initiation Request (AIR) + 5G Authentication Initiation Answer (5G-AIA)
// For key derivarion, see [5G] clause 6.1.3.2 and annex A6
// NOTE: The AIR message is in fact the initial authentication request to the service "Nausf_UEAuthentication_Authenticate" (see TS 33.501 9.6.2).
// NOTE: The 5G-AIA is the corresponding Nausf_UEAuthentication_Authenticate Response.
rule hss_receive_air_send_aia:
	let
	        // 1. Receive
		conc_supi = aenc{<~supi, ~R>}pk(~sk_HN)
		suci = <conc_supi, ~idHN>
		SNID = <'5G', idSN> // HSS checks that the received SNID matches the authenticated channel with idSN
		msgIn = <suci, SNID >
		SqnNext = SqnHSS + '1'
		
		// 2. Send
                //     a. ARPF part
		MAC = f1(~k, <SqnNext, ~RAND, SNID>)
	 	XRES = f2(~k, ~RAND)
		CK = f3(~k, ~RAND)
		IK = f4(~k, ~RAND)
		AK = f5(~k, ~RAND)
		AUTN = <SqnNext XOR AK, MAC>
		K_seaf = KDF(KDF(<CK, IK>, <SNID, SqnNext XOR AK>), SNID)
		XRES_star = KDF(<CK, IK>, <SNID, XRES, ~RAND>)

		//     b. AUSF part
                HXRES_star = SHA256(XRES_star, ~RAND)
		5G_AV = < ~RAND, HXRES_star, K_seaf, AUTN >

		msgOut = 5G_AV
        in
	[!HSS(~idHN, ~sk_HN),
	 RcvS(idSN, ~idHN, <'air', msgIn>),
	 !Ltk_Sym(~supi, ~idHN, ~k, ~sqn_root),
	 Sqn_HSS(~supi, ~idHN, SqnHSS, ~sqn_root, count),
	 Fr(~RAND),
	 Fr(~tid),
	 In(count)]
	--[
		// Open chains
		Sqn_HSS_Invariance(~idHN, ~supi, SqnNext, ~sqn_root, count+'1'),
		Src(~RAND, AUTN),

		// Executability
		Start_HSS_Session(~idHN),
		HSS_Send_Aia(),

		// Security properties
		Running(~idHN, idSN,<'SEAF','HSS',<'K_seaf', K_seaf>>),
		Running(~idHN, idSN,<'SEAF','HSS',<'supi', ~supi>>),
		Running(~idHN, idSN,<'SEAF','HSS',<'RES_star', XRES_star>>),
		Running(~idHN, ~supi,<'UE','HSS', <'K_seaf', K_seaf>>),
		Running(~idHN, ~supi,<'UE','HSS', <'snname', idSN>>),
		Running(~idHN, ~supi,<'UE','HSS',<'supi', ~supi>>),
		Running(~idHN, ~supi,<'UE','HSS',<'AUTN', AUTN>>),
		Honest(~supi),
		Honest(~idHN),
		Honest(idSN)
	]->
	[St_1_HSS(~tid, ~idHN, ~supi, suci, idSN, SNID, ~k, SqnNext, XRES_star, ~RAND, ~sqn_root, ~sk_HN),
         Sqn_HSS(~supi, ~idHN, SqnNext, ~sqn_root, count+'1'),
         SndS(~idHN, idSN, <'aia', msgOut>)]
```

## 2.5 Lemmas

There are a lot of properties which need to be checked. We only take several of them as example.

### 2.5.1  Restrictions

Restrictions restrict the set of traces to be considered in the protocol analysis. 

The first restriction means that the action Subscribe(supi, HN1) must be unique. If it appears on the trace twice, it actually is only once, as the two time points are identified.

The second restriction means that for all the instances of action Greater_Or_Equal_Than(x,y) on the trances, y >=x.

```C
/************************************/
/*     Restrictions / Axioms        */
/************************************/

restriction subscribe_once:
	" All HN1 HN2 supi #i #j. Subscribe(supi, HN1)@i & Subscribe(supi, HN2)@j ==> (#i = #j & HN1 = HN2)"

restriction greater_or_equal_than:
  	" All x y #i. Greater_Or_Equal_Than(x,y)@i ==> not (Ex z. x + z = y) "
```



### 2.5.2 Lemmas with [reuse]

A lemma marked `reuse` will be used in the proofs of all lemmas syntactically following it (except `sources`lemmas as above). This includes other `reuse` lemmas that can transitively depend on each other.



```C
//lemmas with [reuse]
/************************************/
/*          Helper lemmas           */
/************************************/

// proof (automatic) (~1 sec)
// If you know that a lemma will require induction, you just annotate it with use_induction
lemma sqn_ue_src [use_induction, reuse]:
	" All supi HN Sqn sqn_root count #i.
		Sqn_UE_Invariance(supi, HN, Sqn, sqn_root, count)@i
			==> (Ex #j. Sqn_Create(supi, HN, sqn_root)@j & j < i) "

// proof (automatic) (~1 sec)
lemma sqn_hss_src [reuse]:
	" All HN supi Sqn sqn_root count #i.
		Sqn_HSS_Invariance(HN, supi, Sqn, sqn_root, count)@i
			==> (Ex #j. Sqn_Create(supi, HN, sqn_root)@j & j < i) "

// proof (automatic) (~2 min)
lemma sqn_ue_nodecrease [use_induction, reuse]:
	" (All supi HN Sqni Sqnj #i #j.
		(Sqn_UE_Change(supi, HN, Sqnj)@j &
		 Sqn_UE_Change(supi, HN, Sqni)@i &
		 i < j)	==> (Ex dif. Sqnj = Sqni + dif)) &
	  (All supi HN Sqni Sqnj #i #j.
		(Sqn_UE_Change(supi, HN, Sqnj)@j &
		 Sqn_UE_Nochange(supi, HN, Sqni)@i &
		 i < j)	==> (Ex dif. Sqnj = Sqni + dif)) &
	  (All supi HN Sqni Sqnj #i #j.
		(Sqn_UE_Nochange(supi, HN, Sqnj)@j &
		 Sqn_UE_Change(supi, HN, Sqni)@i &
		 i < j)	==> ((Sqnj = Sqni) | (Ex dif. Sqnj = Sqni + dif))) &
	  (All supi HN Sqni Sqnj #i #j.
		(Sqn_UE_Nochange(supi, HN, Sqnj)@j &
		 Sqn_UE_Nochange(supi, HN, Sqni)@i &
		 i < j)	==> ((Sqnj = Sqni) | (Ex dif. Sqnj = Sqni + dif))) "

// proof (automatic) (~1 sec)
lemma sqn_ue_unique [reuse, hide_lemma=sqn_ue_src, hide_lemma=sqn_hss_src]:
	" All supi HN Sqn #i #j.
		Sqn_UE_Use(supi, HN, Sqn)@i & Sqn_UE_Use(supi, HN, Sqn)@j
			==> #i = #j "

```

### 2.3 Secrecy (SEAF)

```C
/********************************/
/*           Secrecy SEAF       */
/********************************/

// proof (automatic) (~1 sec)
lemma secrecy_seaf_kseaf_noChanRev_noKeyRev [hide_lemma=sqn_ue_nodecrease, hide_lemma=sqn_ue_src, hide_lemma=sqn_hss_src]:
	" All idSN t #i. Secret(<'SEAF', idSN>, 'key', t)@i
		==> not (Ex #j. K(t)@j)
        	    | (Ex X #r. Rev(X, 'secureChannel')@r & Honest(X)@i) 
		    | (Ex X key #r. Rev(X, <'k',key>)@r & Honest(X)@i) "

// attack (stored)
lemma secrecy_seaf_kseaf_noChanRev_noSupiRev_noSqnRev_noAsyKeyRev [hide_lemma=sqn_ue_nodecrease, hide_lemma=sqn_ue_src, hide_lemma=sqn_hss_src]:
	" All idSN t #i. Secret(<'SEAF', idSN>, 'key', t)@i
		==> not (Ex #j. K(t)@j)
        	    | (Ex X #r. Rev(X, 'secureChannel')@r & Honest(X)@i) 
		    | (Ex X k #r. Rev(X, <'skHN',k>)@r & Honest(X)@i)
		    | (Ex X s #r. Rev(X, <'sqn',s>)@r & Honest(X)@i)
           	    | (Ex X s #r. Rev(X, <'supi',s>)@r & Honest(X)@i) "

// attack (stored)
lemma secrecy_seaf_kseaf_noKeyRev_noSupiRev_noSqnRev_noAsyKeyRev [hide_lemma=sqn_ue_nodecrease, hide_lemma=sqn_ue_src, hide_lemma=sqn_hss_src]:
	" All idSN t #i. Secret(<'SEAF', idSN>, 'key', t)@i
		==> not (Ex #j. K(t)@j)
        	    | (Ex X key #r. Rev(X, <'k',key>)@r & Honest(X)@i) 
		    | (Ex X k #r. Rev(X, <'skHN',k>)@r & Honest(X)@i)
		    | (Ex X s #r. Rev(X, <'sqn',s>)@r & Honest(X)@i)
           	    | (Ex X s #r. Rev(X, <'supi',s>)@r & Honest(X)@i) "
```



### 2.7.4 Agreement (UE->SEAF)

```C
/********************************************/
/*     Agreement UE -> SEAF (before KC)     */
/********************************************/

// attack (stored)
lemma weakagreement_ue_seaf_noRev [hide_lemma=sqn_ue_nodecrease, hide_lemma=sqn_ue_src, hide_lemma=sqn_hss_src]:
	" All a b t #i. Commit(a,b,<'UE','SEAF',t>)@i
			==> (Ex t2 #j. Running(b, a, t2)@j)
			    | (Ex X data #r. Rev(X,data)@r & Honest(X)@i) "

/********************************************/
/*     Agreement UE -> SEAF (after KC)      */
/********************************************/

// attack (stored)
lemma weakagreement_ue_seaf_keyConf_noRev [hide_lemma=sqn_ue_nodecrease, hide_lemma=sqn_ue_src, hide_lemma=sqn_hss_src]:
	" All a b t #i. CommitConf(a,b,<'UE','SEAF',t>)@i
			==> (Ex t2 #j. Running(b, a, t2)@j)
			    | (Ex X data #r. Rev(X,data)@r & Honest(X)@i) "
```

## 2.7 Tricks

计数器的攻击模型可以通过输入和加法实现，这样就能实现攻击者可以任意增加计数器的值

```javascript
rule counter_inc:
[In(m), Msg(counter, userid)]
--[Counter_Inc(userid, counter + m)]->
[Msg(counter + m, userid)]
```









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

```bash
git remote add upstream https://github.com/linwe2012/IoT.git
git remote -v
origin git@github.com:kyhn7/IoT.git (fetch)
origin git@github.com:kyhn7/IoT.git (push)
upstream https://github.com/linwe2012/IoT.git (fetch)
upstream https://github.com/linwe2012/IoT.git (push)
# update from original repo
git pull upstream master
# git fetch upstream
# git merge upstream/master
```
