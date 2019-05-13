# 5G-AKA Modelling

**1. Rules (model the protocol):**

**1.1 Three main entities:**

| Entity           | Contain                                                      |
| ---------------- | ------------------------------------------------------------ |
| Subscriber       | UE/ USIM(Universal Subscriber Identity Module)/ SUPI/ K(Long-term Key shared with Serving Network)/ SQN(Sequence Number used to prevent replay attack) |
| Home Networks    | HNID(Home Network ID)/ pkHN(Publickey)/ K(Long-term Key shared with Subscriber)/ SQN(Sequence Number used to prevent replay attack) |
| Serving Networks | SNID(Serving Network ID)                                     |

**Model the entities(Not Compromised):**

```c++
/************************************/
/*     Initialization               */
/************************************/
// Initialize a serving network
rule init_servNet:
	let 
		SNID = <'5G', ~idSN>
	in
	[ Fr(~idSN) ] // idSN denotes VPLMNID
	--[ ServNet(~idSN) ]->
	[!SEAF(~idSN, SNID)
	, Out(SNID)]

// Initialize a home network
rule init_homeNet:
	[Fr(~sk_HN),
	  Fr(~idHN)]
	--[ HomeNet(~idHN) ]->
	[!HSS(~idHN, ~sk_HN),
	 !Pk(~idHN, pk(~sk_HN)),
	 Out(<~idHN, pk(~sk_HN)>)]

// Initialize the subscription
rule add_subscription:
	[Fr(~supi),
	 Fr(~k),
	 Fr(~sqn_root),
	 !HSS(~idHN, ~sk_HN)]
	--[
		// Restriction
		Subscribe(~supi, ~idHN),

		// Helper lemmas
		Sqn_Create(~supi, ~idHN, ~sqn_root)
	]->
	[!Ltk_Sym(~supi, ~idHN, ~k, ~sqn_root), //These terms are persistent and shared by UE and HN 
	 Sqn_UE(~supi, ~idHN, ~sqn_root+'1', ~sqn_root, '1'),
	 Sqn_HSS(~supi, ~idHN, ~sqn_root+'1', ~sqn_root, '1')]
```

**Model the entities(Compromised):**

```C
// Compromised subscriptions (symmetric key k)
rule reveal_Ltk_Sym:
	[!Ltk_Sym(~supi, ~idHN, ~k, ~sqn_root)]
	--[
		// Security properties
		Rev(~supi, <'k', ~k>),
		Rev(~idHN, <'k', ~k>)
	]->
	[Out(~k)]

// Compromised subscriptions ("initial" counter sqn_root)
rule reveal_Ltk_Sqn:
	[!Ltk_Sym(~supi, ~idHN, ~k, ~sqn_root)]
	--[
		// Security properties
		Rev(~supi, <'sqn', ~sqn_root>),
		Rev(~idHN, <'sqn', ~sqn_root>)
	]->
	[Out(~sqn_root)]

// Compromised subscriptions (identifier supi)
rule reveal_Ltk_supi:
	[!Ltk_Sym(~supi, ~idHN, ~k, ~sqn_root)]
	--[
		// Security properties
		Rev(~supi, <'supi', ~supi>),
		Rev(~idHN, <'supi', ~supi>)
	]->
	[Out(~supi)]

// Compromised home network (private asymmetric key sqn_HN)
rule reveal_sk_HN:
	[!HSS(~idHN, ~sk_HN)]
	--[
		// Security properties
		Rev(~idHN, <'skHN', ~sk_HN>)
	]->
	[Out(~sk_HN)]

```



**1.2 Channels between entities:**

| Channels                         | Descriptions                                                 |
| -------------------------------- | ------------------------------------------------------------ |
| Subscriber <-> Serving Network   | Not Secure(can be modeled using Facts In() and Out())        |
| Serving Network <-> Home Network | Secure(In this version, however, the channel can be compromised) |

**Model the Channels**

* Serving Network <-> Home Network(HSS)

```c
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

**1.3 AKA Process**

The whole process will be shown below:

![](C:\Users\asus\Desktop\IoT\IoT\img\5gaka-process1.png)

![](C:\Users\asus\Desktop\IoT\IoT\img\5g-aka-process2.jpg)

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

**2. Lemmas (Model Secure Properties)** 

There are a lot of properties which need to be checked. We only take several of them as example.

**2.1 Restrictions**

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

**2.2 Lemmas with [reuse]**

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

**2.3 Secrecy (SEAF)**

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

**2.4 Agreement (UE->SEAF)**

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

