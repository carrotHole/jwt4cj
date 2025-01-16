package jwt4cj

import std.crypto.digest.*
import crypto.digest.*
import crypto.keys.*
import encoding.base64.*
import std.convert.*
import encoding.hex.*
import std.io.*
import std.math.numeric.*

@C
struct ECDSA_SIG {}

@C
struct EVP_MD_CTX {}

@C
struct EVP_PKEY {}

@C
struct EVP_PKEY_CTX {}
// @C
// struct BIGNUM  {}

@C
struct EVP_MD {}
@C
struct BIO{}

@C
struct BIO_METHOD{}



/*
 * 创建BIO_s_mem
*/
foreign func BIO_s_mem(void:CPointer<Unit>) : CPointer<BIO_METHOD>


/**
* 创建BIO
*/
foreign func BIO_new(typ:CPointer<BIO_METHOD>):CPointer<BIO>

/**
* 写入BIO
*/
foreign func BIO_puts(b: CPointer<BIO>, buf: CString): Int64

/**
* 读取私钥
*/
foreign func PEM_read_bio_PrivateKey(
    bp:CPointer<BIO>,
    x:CPointer<CPointer<EVP_PKEY>>,
    cb:CPointer<CFunc<(CPointer<UInt8>,Int64,Int64, CPointer<UInt>)->Int64>>,
    u:CPointer<Unit>   
    ):CPointer<EVP_PKEY >

foreign func d2i_ECDSA_SIG(psig: CPointer<CPointer<ECDSA_SIG>>, ppin: CPointer<CPointer<UInt8>>, len: Int64): CPointer<ECDSA_SIG>

foreign func BN_bn2bin(a: CPointer<Int64>, to: CPointer<UInt8>): Int64
foreign func BN_bn2binpad(a: CPointer<Int64>, to: CPointer<UInt8>): Int64

foreign func ECDSA_SIG_get0_r(sig: CPointer<ECDSA_SIG>): CPointer<Int64>

foreign func ECDSA_SIG_get0_s(sig: CPointer<ECDSA_SIG>): CPointer<Int64>

foreign func EVP_DecodeBlock(t: CString, f: CString, m: Int64): Int64

@C
public func cb1(buf:CPointer<UInt8>,size:Int64,rwflag:Int64, u:CPointer<Unit>):Int64{
    return 0
}

public func ecdsaSig(priKeyStr:String, md:Array<UInt8>){
    var pPriKey = unsafe{ LibC.mallocCString(priKeyStr) }
    // Str转BIO
    var voidParam = unsafe { LibC.malloc<Unit>() }
    var pBio = unsafe{BIO_new(BIO_s_mem(voidParam))}
    unsafe{BIO_puts(pBio,pPriKey)}

    // BIO转EVP_PKEY
    var x = unsafe{LibC.malloc<CPointer<EVP_PKEY>>()}
    var u = unsafe { LibC.malloc<Unit>() }
    var pCb = unsafe{LibC.malloc<CFunc<(CPointer<UInt8>,Int64,Int64, CPointer<UInt>)->Int64>>()}
    var pEvpKey = unsafe{PEM_read_bio_PrivateKey(pBio,x, pCb, u)}
    
}
/**
 * 将asn1格式签名转换为字符串拼接的格式
 * @param sig 签名hash
 */
public func convertEcdsa(sig: Array<UInt8>, size: Int64): String {
    var psig = unsafe { LibC.malloc<CPointer<ECDSA_SIG>>() }

    var cSigStr = unsafe { LibC.mallocCString(sig |> toBase64String) }
    println("2")
    var ppin = unsafe { LibC.malloc<CPointer<UInt8>>() }
    var pSigRaw = unsafe { acquireArrayRawData(sig) }
    unsafe { ppin.write(pSigRaw.pointer) }
    unsafe { releaseArrayRawData(pSigRaw) }
    println("3")
    var pEcdsaSig = unsafe { d2i_ECDSA_SIG(psig, ppin, sig.size) }
    println("4")
    if (pEcdsaSig.isNull()) {
        println("d2i_ECDSA_SIG error")
    }
    println("5")
    var r = unsafe { ECDSA_SIG_get0_r(pEcdsaSig) }
    println("6")
    var s = unsafe { ECDSA_SIG_get0_s(pEcdsaSig) }
    println("7")

    var a = VArray<UInt8,$66>(repeat: 0)
    var b = VArray<UInt8,$66>(repeat: 0)

    println(8)
    
    let rr = unsafe { BN_bn2bin(r, inout a) }
    let sr = unsafe { BN_bn2bin(s, inout b) }
    println(rr)
    println(sr)
    println(9)

    let aa = Array<UInt8>(66,repeat:0)
    for(i in 0..66){
        aa[i] = a[i]
    }
    println(aa)
    let bb = Array<UInt8>(66,repeat:0)
    for(i in 0..66){
        bb[i] = b[i]
    }
    println(bb)

    let res = aa.concat(bb)
    println(10)

    unsafe {
        LibC.free(psig)
        LibC.free(cSigStr)
        LibC.free(ppin)
        // LibC.free(ppin)
        // LibC.free(pEcdsaSig)
        // LibC.free(r)
        // LibC.free(s)
    }
    println(res)
    return res |> toBase64String |> JwtUtil.format
}
