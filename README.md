# NtlmSocks
一个网络层的PTH工具
## 使用
ntlm_socks.exe -b 要替换的错误密码 -h NT哈希 -p 要监听的端口
工具会在你设置的端口上开启一个socks代理，然后使用其他工具配置成使用此代理，工具会自动识别出NTLMSSP数据包并替换掉错误的HASH和会话KEY。
