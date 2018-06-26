# Proxy-Re-Encryption

## Overview
プロキシ再暗号化(代理人再暗号化)を実装してみたい  
とりあえずECDH鍵共有からやっている途中  
  
## 使用ライブラリ
 - OpenSSL (OpenSSL 1.0.2k-fips  26 Jan 2017)
 - GMP (The GNU Multiple Precision Arithmetic Library)
 - TEPLA (University of Tsukuba Elliptic Curve and Pairing Library)
 
 
 ## 実装内容
 ### ECDH鍵交換
 ![画像](https://github.com/jpfaw/Proxy-Re-Encryption/blob/README_files/Images/ECDH.png?raw=true)
