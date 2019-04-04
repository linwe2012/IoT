# Where the wild warnings are: root causes of chrome https certificate errors [^www.chrome]

[^www.chrome]: https://acmccs.github.io/papers/p1407-acerA.pdf

goal: resolve benign https errors from bad ones

#### HTTPS error warnings

alert users and protect them from nwk attack

- server side
  - date error
    - 时间过快导致证书过期
  - name mismatch
    - `*.aa.com` 不能代表`a.b.aa.com`, 所以证书里的网址无效
    - `www.aaa.com` 和 `aaa.com` 不一样
  - Authority Invalid
    - 证书链没有根证书，
    - 通常是政府网站喜欢用自己签发没有获得广泛认可的证书
  - Insufficient intermediates:
    - 通过根证书认证的证书也可以签发新证书，浏览器需要追溯到根证书
      - 缺乏部分证书链，但是有这部分证书链的缓存可以帮助追溯
      - 没有缓存 -- ERROR
  - attacker intercepts a connection causing invalid certificate chain -- malicious

  

- client side

  - incorrect client clock

    - 原因: 用户手动改时间来在游戏里作弊或者CMOS老化

  - Anti-Virus Errors

    - AV 通常会检查HTTPS，然后用自己的密钥重新签名

    

- Network

  - Captive portal
    - 联网是要重新定位到登录页，参见ZJUWlan
  - Missing TLS proxy roots
    - 代理网络的证书没有被安装





# Neural Network-based Graph Embedding for Cross-Platform Binary Code Similarity Detection
- cross platform binary code comparison
- learn feature from CFG

Drawbacks

- minor changes in CFG maybe a fix to bug, but undetected
- graph matchings are slow





# AuthScope: Towards Automatic Discovery of Vulnerable Authorizations in Online Services


## Ideas

这篇论文没有详细介绍怎么分类，基本上是个结果展示，但是他最后提到根据不同的错误给出提示有助于用户理解问题，在检查一个协议安全性的时候，也需要从用户角度出发，确保用户能正确理解安全信息做出恰当的举动



# TODO

可能有关的论文

### CCS2017 

#### Security

- **Herding Vulnerable Cats: A Statistical Approach to Disentangle Joint Responsibility for Web Security in Shared Hosting** [^ccs171]
- **Hiding in Plain Sight: A Longitudinal Study of Combosquatting Abuse** [^ccs172]
- **Verifying Security Policies in Multi-agent Workflows with Loops** [[PDF\]](https://acmccs.github.io/papers/p633-finkbeinerA.pdf) [[Paper\]](http://arxiv.org/abs/1708.09013)
  - We consider the automatic verification of information flow security policies of web-based workflows, such as conference submission systems like EasyChair. 
- **AUTHSCOPE: Towards Automatic Discovery of Vulnerable Access Control in Online Services** [[PDF\]](https://acmccs.github.io/papers/p799-zuoA.pdf)

- **Unleashing the Walking Dead: Understanding Cross-App Remote Infections on Mobile WebViews** [[PDF\]](https://acmccs.github.io/papers/p829-liA.pdf)
- **Stacco: Differentially Analyzing Side-Channel Traces for Detecting SSL/TLS Vulnerabilities in Secure Enclaves** [[PDF\]](https://acmccs.github.io/papers/p859-xiaoA.pdf)
- **Watch Me, but Don’t Touch Me! Contactless Control Flow Monitoring via Electromagnetic Emanations** [[PDF\]](https://acmccs.github.io/papers/p1095-hanA.pdf)
- **A Large-Scale Empirical Study of Security Patches** [[PDF\]](https://acmccs.github.io/papers/p2201-liA.pdf) 





#### Deep Learning

- **Machine Learning Models that Remember Too Much** [[PDF\]](https://acmccs.github.io/papers/p587-songA.pdf)https://acmccs.github.io/papers/p603-hitajA.pdf)
  -  abstract: It is important that ML models trained on sensitive inputs (e.g., personal images or documents) not leak too much information about the training data.
- **Deep Models Under the GAN: Information Leakage from Collaborative Deep Learning** [[PDF\]](https://acmccs.github.io/papers/p603-hitajA.pdf)
  - Models are typically trained in a centralized manner with all the data being processed by the same training algorithm. If the data is a collection of users' private data, including habits, personal pictures, geographical positions, interests, and more, the centralized server will have access to sensitive information that could potentially be mishandled. To tackle this problem, collaborative deep learning models have recently been proposed where parties locally train their deep learning structures and only share a subset of the parameters in the attempt to keep their respective training sets private. Parameters can also be obfuscated via differential privacy (DP) to make information extraction even more challenging, as proposed by Shokri and Shmatikov at CCS'15. 
- **Practical Secure Aggregation for Privacy-Preserving Machine Learning** [[PDF\]](https://acmccs.github.io/papers/p1175-bonawitzA.pdf)
- **A Comprehensive Symbolic Analysis of TLS 1.3** [[PDF\]](https://acmccs.github.io/papers/p1773-cremersA.pdf) [[Paper\]](http://tls13tamarin.github.io/TLS13Tamarin/) 
- **Nonmalleable Information Flow Control** [[PDF\]](https://acmccs.github.io/papers/p1875-cecchettiA.pdf) [[Paper\]](https://www.cs.cornell.edu/~ethan/papers/nmifc.pdf)
- **Cryptographically Secure Information Flow Control on Key-Value Stores** [[PDF\]](https://acmccs.github.io/papers/p1893-wayeACC.pdf)[[Paper\]](https://arxiv.org/abs/1708.08895)
- *Object Flow Integrity* [[PDF\]](https://acmccs.github.io/papers/p1909-wangA.pdf)
- 


[^ccs171]: https://acmccs.github.io/papers/p553-tajalizadehkhoobAemb.pdf
[^ccs172]: https://acmccs.github.io/papers/p569-kintisA.pdf





#### NLP

[100 Must-Read NLP Papers - GitHub](https://github.com/mhagiwara/100-nlp-papers)

#### Just Interested

- *How Unique is Your .onion? An Analysis of the Fingerprintability of Tor Onion Services* [[PDF\]](https://acmccs.github.io/papers/p2021-overdorfA.pdf) [[Paper\]](https://arxiv.org/abs/1708.08475) 

- *HexType: Efficient Detection of Type Confusion Errors for C++* [[PDF\]](https://acmccs.github.io/papers/p2373-jeonA.pdf) [[VID\]](https://www.youtube.com/watch?v=3hJjtlhKnr8)



