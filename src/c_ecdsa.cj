package jwt4cj

import std.crypto.digest.*
import crypto.digest.*
import crypto.keys.*
import encoding.base64.*
import std.convert.*
import encoding.hex.*
import std.io.*
@C
struct EVP_PKEY {}

@C
struct BIO {}


foreign func EVP_sign(t: Int32, m: CPointer<UInt8>, m_len: UInt32, sigret: CPointer<UInt8>, siglen: CPointer<UInt32>, pkey: CPointer<EVP_PKEY>): Int32

private func ecdsa(priKey:String,digestIns: Digest,  value:String):String{    

    // value的sha256 hash值  
    var md = digest(digestIns, value.toArray())
    
    // 将私钥字符串转换为EVP_PKEY结构体
    // 这里需要实现一个函数来解析私钥字符串并创建EVP_PKEY结构体
    var pkey = parsePrivateKey(priKey)
    
    
    // 分配签名缓冲区
    var sigret = unsafe { LibC.malloc<UInt8>() } // 假设签名最大长度为256字节
    var siglen = unsafe { LibC.malloc<UInt8>() } // 假设签名最大长度为256字节

    
    // 调用openssl EVP_sign方法进行签名
    var ret = unsafe {
        EVP_sign(NID_ecdsa_with_SHA256, md.getChars(), md.size().toUInt32(), sigret, siglen, pkey)
    }
    
    // 检查签名是否成功
    if (ret != 1) {
        // 签名失败，处理错误
        unsafe { LibC.free(sigret) }
        return "Signature failed"
    }
    
    // 将签名转换为字符串
    var signature = sigret.toCString().toString()
    
    // 释放资源
    unsafe { LibC.free(sigret) }
    
    return signature
}
@C
struct pem_password_cb{
    var buf: CString = CString("")
    var size : Int64 = 0
    var rwflag : Int64 = 0
    var u : CPointer<Unit> = unsafe{LibC.malloc<Unit>()}

    init(buf: CString, size: Int64, rwflag: Int64, u: CPointer<Unit>){
        this.buf = buf
        this.size = size
        this.rwflag = rwflag
        this.u = u
    }
}
foreign func BIO_new_mem_buf(data: CPointer<CString>, len: Int64): CPointer<BIO>
foreign func PEM_read_bio_PrivateKey(bp: CPointer<BIO>, x: CPointer<CPointer<EVP_PKEY>>, cb: CFunc<BIO_new_mem_buf>, u: CPointer<Unit>): CPointer<EVP_PKEY>

private func parsePrivateKey(priKeyStr: String): CPointer<EVP_PKEY> {
    // 将字符串转换为C风格的字符串
    let cStr = unsafe{LibC.mallocCString(priKeyStr)}
    let priPoint = unsafe{LibC.malloc<CString>()}
    unsafe{priPoint.write(cStr)}
    // 创建BIO对象
    var bio = unsafe{BIO_new_mem_buf(priPoint , cStr.size())}
    
    // 读取私钥
  
    let cPass = unsafe{LibC.mallocCString("")}

    var pkey: CPointer<EVP_PKEY> = unsafe{LibC.malloc<EVP_PKEY>()}
    var ppKey : CPointer<CPointer<EVP_PKEY>> = unsafe{LibC.malloc<CPointer<EVP_PKEY>>()}
    ppKey.write(pkey)

    var pCb : CPointer<pem_password_cb> = unsafe{LibC.malloc<pem_password_cb>()}
    pCb.write(pem_password_cb(cPass,cPass.size(),0,unsafe{LibC.malloc<Unit>()}))

    pkey = unsafe{PEM_read_bio_PrivateKey(bio, ppKey,pPass , unsafe{LibC.malloc<Unit>()})}
    
    // 检查是否成功读取私钥
    if (pkey.isNull()) {
        // 处理错误
        unsafe{LibC.free(bio)}
        return null
    }
    
    // 释放BIO对象
    unsafe{
        LibC.free(bio)
        LibC.free(cStr)
    }
    return pkey
}






