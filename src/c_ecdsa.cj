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

@C
struct EC_KEY{}

@C
struct Engine{}

// EVP_MD_CTX *EVP_MD_CTX_create(void);
foreign func EVP_MD_CTX_create(void:CPointer<Unit>):CPointer<EVP_MD_CTX>

foreign func ECDSA_size(eckey:CPointer<EC_KEY>):Int64

// void *OPENSSL_malloc(size_t num)
foreign func OPENSSL_malloc(num:UIntNative):CPointer<UInt8>
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

foreign func PEM_read_bio_ECPrivateKey(
    out:CPointer<BIO>,
    x:CPointer<CPointer<EC_KEY>>,
    cb:CPointer<CFunc<(CPointer<UInt8>,Int64,Int64, CPointer<UInt>)->Int64>>,
    u:CPointer<Unit>
):CPointer<EC_KEY>

foreign func EVP_sha256():CPointer<EVP_MD>
/**
* evp转ec
*/
foreign func  EVP_PKEY_get1_EC_KEY(pkey:CPointer<EVP_PKEY>):CPointer<EC_KEY>

foreign func d2i_ECDSA_SIG(psig: CPointer<CPointer<ECDSA_SIG>>, ppin: CPointer<CPointer<UInt8>>, len: Int64): CPointer<ECDSA_SIG>

foreign func BN_bn2bin(a: CPointer<Int64>, to: CPointer<UInt8>): Int64
foreign func BN_bn2binpad(a: CPointer<Int64>, to: CPointer<UInt8>): Int64

foreign func ECDSA_SIG_get0_r(sig: CPointer<ECDSA_SIG>): CPointer<Int64>

foreign func ECDSA_SIG_get0_s(sig: CPointer<ECDSA_SIG>): CPointer<Int64>

foreign func EVP_DecodeBlock(t: CString, f: CString, m: Int64): Int64


// int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
foreign func EVP_DigestSignInit(
    ctx:CPointer<EVP_MD_CTX>,
    pctx: CPointer<CPointer<EVP_PKEY_CTX>>,
    typ: CPointer<EVP_MD>,
    e: CPointer<Engine>,
    pkey: CPointer<EC_KEY>
): Int64

// int EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
foreign func EVP_DigestSignUpdate(
    ctx:CPointer<EVP_MD_CTX>,
    d:CPointer<UInt8>,
    cnt:UIntNative
):Int64

// int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen);
foreign func EVP_DigestSignFinal(
    ctx:CPointer<EVP_MD_CTX>,
    sig:CPointer<UInt8>,
    siglen:CPointer<UIntNative>
):Int64

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

    // BIO转EV_PKEY
    var x = unsafe{LibC.malloc<CPointer<EC_KEY>>()}
    var u = unsafe { LibC.malloc<Unit>() }
    var pCb = unsafe{LibC.malloc<CFunc<(CPointer<UInt8>,Int64,Int64, CPointer<UInt>)->Int64>>()}
    var pEcKey = unsafe{PEM_read_bio_ECPrivateKey(pBio,x, pCb, u)}

    // 签名
    var pEmc = unsafe{EVP_MD_CTX_create(LibC.malloc<Unit>())}
    unsafe{
        EVP_DigestSignInit(
            pEmc,
            LibC.malloc<CPointer<EVP_PKEY_CTX>>(),
            EVP_sha256(),
            LibC.malloc<Engine>(),
            pEcKey)
        var msg = acquireArrayRawData(md)
        EVP_DigestSignUpdate(
            pEmc,
            msg.pointer,
            UIntNative(md.size)
        )
        var pSigLen = LibC.malloc<UIntNative>()
        EVP_DigestSignFinal(
            pEmc,
            LibC.malloc<UInt8>(),
            pSigLen
        )
        var sigLen = pSigLen.read()
        var signature = OPENSSL_malloc(
            sigLen
        )

        EVP_DigestSignFinal(
            pEmc,
            signature,
            pSigLen
        )

    }
    

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
