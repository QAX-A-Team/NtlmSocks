# NtlmSocks
一个工作在网络层的跨平台哈希传递工具
## 原理
开启一个socks代理，在流量中匹配NTLMSSP数据包，替换其中错误的NT哈希和会话密钥
## 使用
ntlm_socks -b 要替换的错误密码 -h NT哈希 -p socks代理要监听的端口  
在Mac，Windows，Linux上均适用。
## 已知的缺陷
在Windows7上对Windows7进行认证时，NTLMSSP数据包中会多一个签名，使用工具修改数据包后会导致签名校验失败。Windows向下兼容，这个签名可有可无，所以在低版本Windows或者Linux上使用此工具即可避免。
## 可能存在的缺陷
替换Net-NTLM哈希的同时工具还会替换NTLM会话密钥，如果协商结果并没有交换会话密钥，那么后面加密或者签名使用的密钥不一致，操作会失败。
