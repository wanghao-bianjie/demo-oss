package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	osscrypto "github.com/aliyun/aliyun-oss-go-sdk/oss/crypto"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

var client *oss.Client

var pubkey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsy8hPyUa/QoRTVhBukJH
jZYc73MIR51irleLzxcbRaRAfsRL+qZklX4UXRz9eoUD/VZi7mOg1zZu7TvVtscu
DapKh9Ug5PPYCM22jqKI2Sp4CxmiZdk4WGAmC2jmAN8M/bfEjmr6o6/Mn8mMKY2u
xtPaJftdnS93OILnPbyewnWq2uYRo3fDKKmDRALeNOIGLOrUwYCpZc93+9ozlAj9
lMziohr5IxZwXYQEcgeSEqv6dW5GhtzzobtcZF3WoUzf2j6kbLswjcTbRyGiIlLJ
EfrZ7YWcFNoMrANX33Df7nYUYqbTNxSMt1qZsJtceEftzk6fJA6ax7xHsW05DD4U
+QIDAQAB
-----END PUBLIC KEY-----`

var prikey = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAsy8hPyUa/QoRTVhBukJHjZYc73MIR51irleLzxcbRaRAfsRL
+qZklX4UXRz9eoUD/VZi7mOg1zZu7TvVtscuDapKh9Ug5PPYCM22jqKI2Sp4Cxmi
Zdk4WGAmC2jmAN8M/bfEjmr6o6/Mn8mMKY2uxtPaJftdnS93OILnPbyewnWq2uYR
o3fDKKmDRALeNOIGLOrUwYCpZc93+9ozlAj9lMziohr5IxZwXYQEcgeSEqv6dW5G
htzzobtcZF3WoUzf2j6kbLswjcTbRyGiIlLJEfrZ7YWcFNoMrANX33Df7nYUYqbT
NxSMt1qZsJtceEftzk6fJA6ax7xHsW05DD4U+QIDAQABAoIBAHgW5y5d3PeoDq6K
rwp5L2F6MQxeSTdOCPwVmpMBxnpnOf576vwjFpiGdnltW4kIqwLYKdfhl8OFLNT8
XCBy36+y6N6efbxUnP5ReL+huRvq9adi189wxO2eCwFsnXIKC7fjuO1GT5Ly2K5i
sviKh4+kHrmD/VrCnCGYwghDaRekC1stJ3UBsNANWXX4+lwZA2iQ35UkEMeYROQ+
84eD3wN65garZIh5RzwRsqz4IxvPLsvkDFaWrwlYgnvZckbakHevL0+08Be+TEz8
UOT6b+sSvP6qBM8yapER0rqfDEG40kMH6U8dfQ6v+nFy9WKkWll6D6T2M0WG+SCP
IM+p3R0CgYEA5JktA3bkgupGkaCIvvgWaCZE9zISLNssd0EC7WbYxlgqEsoJKuve
njSiFJfIe4wEpDIiJ5pPhtsQbhnjR80EuyJWJOga6lW98bST/Qw7So9B7agQ9al4
aVnSN7cKUYRBvzKPo1pMKmG8U7Kcze86zdh18hCRatZd/xia0tOC0D8CgYEAyKmd
20AoXwNihXHIHZB1qcdHtQSaAeoU/1D+Gqc89xZv8dTy7PMUXN4I7icPTPagd7Sp
B5nY+vuIpLkXFY5se0S2Vs61jI7ARC3IZsd4hpL6znroXS9BJuZXXGi2V3vUOQye
N4hNMcb07dRfHdWS2G94fVXx86NfGIJ8bDVkzMcCgYBRQwZWYfBPfXqCkB+sS0Kj
2V7QxPLjETKYXfrta48JyxOBxGJH6LslYC5xxZcWHCsWN2Ae1eMJXFxV10wNHRte
bpFS41OWE87G2lt1K+Dz20MjeYg12/2a7bwl5CJ94dcBYbbf6dyDgGTTF/5X0oAD
5rvexfb7lKKraRK4eUnaPwKBgHBn063GOtc+pinqmxc0nTUGFP0qHruDzU9Yp392
v4gKYZsulwZ1BKshFg+SgdezMCDeavF/FTVDQkBEDtJcfhhvXVUzZi/ep4WJwAET
LEj2fNi9sPzCQ9Tuo3F4luxayX9LujWRfOytbvbrSH0F7sSfbPeI9YhttA+eyOQ0
5MpxAoGAPVvwdekpOMynlCUy1n+5MwTwRTbPP4zesXSb1JbJhpIiStzjJ/VhSE+Y
uZOW1zgbT9VcUZPZJmUDxaUFMeyeH72607QBbSJZqHGHPldEf9/oMEuZWE30W1iT
Bqg/1FX/GpM/BrHRot4mLmc+0xowMzHELd4/o6CfIyO/q81wxx4=
-----END RSA PRIVATE KEY-----`

func TestMain(m *testing.M) {
	var err error
	client, err = oss.New("https://oss-cn-hangzhou.aliyuncs.com", "***", "***")
	if err != nil {
		panic(err)
	}
	m.Run()
}

//文本上传下载
func TestText(t *testing.T) {
	buckerName := "wanghao-demo"
	//buckerName := "wanghao-demo-server-aes"
	bucket, err := client.Bucket(buckerName)
	if err != nil {
		t.Fatal(err)
	}
	objectKey := "1.txt"
	err = bucket.PutObject(objectKey, strings.NewReader("15651859999"))
	if err != nil {
		t.Fatal(err)
	}
	object, err := bucket.GetObject(objectKey)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := ioutil.ReadAll(object)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(bytes))
}

//文件上传下载
func TestFile(t *testing.T) {
	buckerName := "wanghao-demo"
	//buckerName := "wanghao-demo-server-aes" //服务端aes签名
	bucket, err := client.Bucket(buckerName)
	if err != nil {
		t.Fatal(err)
	}
	objectKey := "1.png"
	err = bucket.PutObjectFromFile(objectKey, "./1.png")
	if err != nil {
		t.Fatal(err)
	}
	err = bucket.GetObjectToFile(objectKey, "./1-download.png")
	if err != nil {
		t.Fatal(err)
	}
}

//客户端加密文本
func TestClientEncryptText(t *testing.T) {

	// 创建一个主密钥的描述信息，创建后不允许修改。主密钥描述信息和主密钥一一对应。
	// 如果所有的Object都使用相同的主密钥，主密钥描述信息可以为空，但后续不支持更换主密钥。
	// 如果主密钥描述信息为空，解密时无法判断使用的是哪个主密钥。
	// 强烈建议为每个主密钥都配置主密钥描述信息(json字符串), 由客户端保存主密钥和描述信息之间的对应关系（服务端不保存两者之间的对应关系）。

	// 由主密钥描述信息(json字符串)转换的map。
	materialDesc := make(map[string]string)
	//materialDesc["desc"] = "<your master encrypt key material describe information>"

	// 根据主密钥描述信息创建一个主密钥对象。
	masterRsaCipher, err := osscrypto.CreateMasterRsa(materialDesc, pubkey, prikey)
	if err != nil {
		t.Fatal(err)
	}

	// 根据主密钥对象创建一个用于加密的接口, 使用aes ctr模式加密。
	contentProvider := osscrypto.CreateAesCtrCipher(masterRsaCipher)

	// 获取一个用于客户端加密的已创建bucket。
	// 客户端加密bucket和普通bucket具有相似的用法。

	buckerName := "wanghao-demo"
	cryptoBucket, err := osscrypto.GetCryptoBucket(client, buckerName, contentProvider)
	if err != nil {
		t.Fatal(err)
	}

	// put object时自动加密。
	objectKey := "2.txt"
	err = cryptoBucket.PutObject(objectKey, bytes.NewReader([]byte("15651859999")))
	if err != nil {
		t.Fatal(err)
	}

	// get object时自动解密。
	body, err := cryptoBucket.GetObject(objectKey)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()

	data, err := ioutil.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("data:", string(data))
}

//客户端加密文件
func TestClientEncryptFile(t *testing.T) {
	masterRsaCipher, err := osscrypto.CreateMasterRsa(nil, pubkey, prikey)
	if err != nil {
		t.Fatal(err)
	}

	contentProvider := osscrypto.CreateAesCtrCipher(masterRsaCipher)

	buckerName := "wanghao-demo"
	cryptoBucket, err := osscrypto.GetCryptoBucket(client, buckerName, contentProvider)
	if err != nil {
		t.Fatal(err)
	}

	// put object时自动加密。
	objectKey := "2.png"
	err = cryptoBucket.PutObjectFromFile(objectKey, "./1.png")
	if err != nil {
		t.Fatal(err)
	}

	// get object时自动解密。
	err = cryptoBucket.GetObjectToFile(objectKey, "./2-download.png")
	if err != nil {
		t.Fatal(err)
	}
}

func TestClientDecrypt(t *testing.T) {
	buckerName := "wanghao-demo"
	bucket, err := client.Bucket(buckerName)
	if err != nil {
		t.Fatal(err)
	}
	objectKey := "2.txt"
	signURL, err := bucket.SignURL(objectKey, oss.HTTPGet, 60)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(signURL)
	if err != nil {
		t.Fatal(err)
	}
	keyBase64 := resp.Header.Get("x-oss-meta-client-side-encryption-keyBase64")
	ivBase64 := resp.Header.Get("x-oss-meta-client-side-encryption-start")
	t.Log("x-oss-meta-client-side-encryption-keyBase64\t", keyBase64)
	t.Log("x-oss-meta-client-side-encryption-start\t", ivBase64)

	//Financial Account 改成 Investment Account

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(bytes))
	keyCrypt, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		t.Fatal(err)
	}
	key, err := RsaDecrypt(prikey, keyCrypt)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(key)

	ivCrypt, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		t.Fatal(err)
	}
	iv, err := RsaDecrypt(prikey, ivCrypt)
	if err != nil {
		t.Fatal(err)
	}

	res, err := AesEncrypt(bytes, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(res))
}

func TestSignUrl(t *testing.T) {
	buckerName := "wanghao-demo"
	bucket, err := client.Bucket(buckerName)
	if err != nil {
		t.Fatal(err)
	}
	signPutURL, err := bucket.SignURL("3.png", oss.HTTPPut, 60)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(signPutURL)

	signGetURL, err := bucket.SignURL("2.txt", oss.HTTPGet, 60)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(signGetURL)

	////模拟前端直接使用signGetURL进行下载
	get, err := http.Get(signGetURL)
	t.Log(get.StatusCode)
	all, _ := ioutil.ReadAll(get.Body)
	t.Log(string(all))

	//模拟前端直接使用signPutURL进行文件上传

	//file, err := os.Open("./1.png")
	//if err != nil {
	//	t.Fatal(err)
	//}
	//request, err := http.NewRequest(http.MethodPut, signPutURL, file)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//response, err := http.DefaultClient.Do(request)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//defer response.Body.Close()
	//t.Log(response.StatusCode)
	//all, err := ioutil.ReadAll(response.Body)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//t.Log(string(all))
}

func TestUploadAndDownloadByClient(t *testing.T) {
	buckerName := "wanghao-demo"
	bucket, err := client.Bucket(buckerName)
	if err != nil {
		t.Fatal(err)
	}
	objectKey := "0913001.txt"

	aesKey, aesIV, err := generateAesKeyAndIV()
	if err != nil {
		t.Fatal(err)
	}
	aesKeyBase64 := base64.StdEncoding.EncodeToString(aesKey)
	aesIVBase64 := base64.StdEncoding.EncodeToString(aesIV)
	t.Log("aesKeyBase64:\t", aesKeyBase64)
	t.Log("aesIVBase64:\t", aesIVBase64)

	//使用 RSA 公钥进行加密
	encryptedAesKey, err := RsaEncrypt(pubkey, aesKey)
	if err != nil {
		t.Fatal(err)
	}
	encryptedAesIV, err := RsaEncrypt(pubkey, aesIV)
	if err != nil {
		t.Fatal(err)
	}
	encryptedAesKeyBase64 := base64.StdEncoding.EncodeToString(encryptedAesKey)
	encryptedAesIVBase64 := base64.StdEncoding.EncodeToString(encryptedAesIV)
	t.Log("encryptedAesKeyBase64:\t", encryptedAesKeyBase64)
	t.Log("encryptedAesIVBase64:\t", encryptedAesIVBase64)

	var opts []oss.Option
	opts = append(opts, oss.Meta(osscrypto.OssClientSideEncryptionKey, encryptedAesKeyBase64))
	opts = append(opts, oss.Meta(osscrypto.OssClientSideEncryptionStart, encryptedAesIVBase64))
	opts = append(opts, oss.Meta(osscrypto.OssClientSideEncryptionWrapAlg, osscrypto.RsaCryptoWrap))
	opts = append(opts, oss.Meta(osscrypto.OssClientSideEncryptionCekAlg, osscrypto.AesCtrAlgorithm))
	opts = append(opts, oss.ContentType("text/plain"))
	//opts = append(opts, oss.ContentLength(11))

	signPutURL, err := bucket.SignURL(objectKey, oss.HTTPPut, 60, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("signPutURL:\t", signPutURL)

	//前端上传
	data := "15651859999"
	t.Log("data:\t", data)
	//1.base64解码 AES key、IV
	aesKeyDecode, err := base64.StdEncoding.DecodeString(aesKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	aesIVDecode, err := base64.StdEncoding.DecodeString(aesIVBase64)
	if err != nil {
		t.Fatal(err)
	}
	//2.AES 加密数据
	encryptData, err := AesEncrypt([]byte(data), aesKeyDecode, aesIVDecode)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPut, signPutURL, bytes.NewReader(encryptData))
	if err != nil {
		t.Fatal(err)
	}
	//3.设置客户端加密所需的header
	request.Header.Set(oss.HTTPHeaderOssMetaPrefix+osscrypto.OssClientSideEncryptionKey, encryptedAesKeyBase64)
	request.Header.Set(oss.HTTPHeaderOssMetaPrefix+osscrypto.OssClientSideEncryptionStart, encryptedAesIVBase64)
	request.Header.Set(oss.HTTPHeaderOssMetaPrefix+osscrypto.OssClientSideEncryptionWrapAlg, osscrypto.RsaCryptoWrap)
	request.Header.Set(oss.HTTPHeaderOssMetaPrefix+osscrypto.OssClientSideEncryptionCekAlg, osscrypto.AesCtrAlgorithm)

	request.Header.Set(oss.HTTPHeaderContentType, "text/plain")
	//request.Header.Set(oss.HTTPHeaderContentLength, strconv.Itoa(len(encryptData)))

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	putResp, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("putResp:\t", string(putResp))
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}

	//前端下载
	signGetURL, err := bucket.SignURL(objectKey, oss.HTTPGet, 60)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("signGetURL:\t", signGetURL)
	//1.获取加密后的数据
	getResp, err := http.Get(signGetURL)
	if err != nil {
		t.Fatal(err)
	}
	defer getResp.Body.Close()

	getDataEncrypt, err := ioutil.ReadAll(getResp.Body)
	if err != nil {
		t.Fatal(err)
	}

	getKeyEncryptedBase64 := getResp.Header.Get(oss.HTTPHeaderOssMetaPrefix + osscrypto.OssClientSideEncryptionKey)
	getIVEncryptedBase64 := getResp.Header.Get(oss.HTTPHeaderOssMetaPrefix + osscrypto.OssClientSideEncryptionStart)
	t.Log("getKeyEncryptedBase64:\t", getKeyEncryptedBase64)
	t.Log("getIVEncryptedBase64:\t", getIVEncryptedBase64)
	t.Log("WrapAlg:\t", getResp.Header.Get(oss.HTTPHeaderOssMetaPrefix+osscrypto.OssClientSideEncryptionWrapAlg))
	t.Log("CekAlg:\t", getResp.Header.Get(oss.HTTPHeaderOssMetaPrefix+osscrypto.OssClientSideEncryptionCekAlg))

	getKeyEncrypted, err := base64.StdEncoding.DecodeString(getKeyEncryptedBase64)
	if err != nil {
		t.Fatal(err)
	}
	getIVEncrypted, err := base64.StdEncoding.DecodeString(getIVEncryptedBase64)
	if err != nil {
		t.Fatal(err)
	}
	//通过后端接口拿到 RSA 解密后的 AES key、IV
	getKey, err := RsaDecrypt(prikey, getKeyEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	getIV, err := RsaDecrypt(prikey, getIVEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	//前端通过 AES 算法加密数据
	decryptDara, err := AesEncrypt(getDataEncrypt, getKey, getIV)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(decryptDara))

	//用oss sdk直接解密的结果
	masterRsaCipher, err := osscrypto.CreateMasterRsa(nil, pubkey, prikey)
	if err != nil {
		t.Fatal(err)
	}
	contentProvider := osscrypto.CreateAesCtrCipher(masterRsaCipher)
	cryptoBucket, err := osscrypto.GetCryptoBucket(client, buckerName, contentProvider)
	if err != nil {
		t.Fatal(err)
	}
	object, err := cryptoBucket.GetObject(objectKey)
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	res, err := ioutil.ReadAll(object)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("res from sdk:\t", string(res))
}
