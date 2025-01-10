package jwt4cj

import std.crypto.digest.*
import crypto.digest.*
import crypto.keys.*
import encoding.base64.*
import std.convert.*
import encoding.hex.*
import std.io.*


@C
struct ECDSA_SIG {}

@C
struct EVP_MD_CTX{}

@C
struct EVP_PKEY_CTX {}

@C
struct EVP_MD{}



foreign func d2i_ECDSA_SIG(sig:CPointer<CPointer<ECDSA_SIG>>, pp : CPointer<CString>, len:Int64):CPointer<ECDSA_SIG>

foreign func ECDSA_SIG_get0_r(sig:CPointer<ECDSA_SIG>):CPointer<Int64>
foreign func ECDSA_SIG_get0_s(sig:CPointer<ECDSA_SIG>):CPointer<Int64>

foreign func EVP_DecodeBlock(t:CString, f:CString, m: Int64):Int64

/**
* 将asn1签名转换为字符串拼接的格式
* @param sig 签名
*/
public func convertEcdsa(sig:Array<UInt8>):String{
     println("1")
     println(sig)
    var ppSig = unsafe{LibC.malloc<CPointer<ECDSA_SIG>>()}

    var pp : CString = unsafe{LibC.mallocCString("")}
    var cSigStr = unsafe{LibC.mallocCString(sig |> toBase64String)}
    println("2")
    println("sig arr size ${sig.size}")
    println("cstring size ${cSigStr.size()}")
    println("base64 size  ${toBase64String(sig).size}")
    var len = unsafe{EVP_DecodeBlock(pp, cSigStr,cSigStr.size())}
    println("len ${len}")
    println("3")
    var  pPp = unsafe{LibC.malloc<CString>()}
    unsafe{pPp.write(pp)}

    println("4")
    var pEcdsaSig = unsafe{d2i_ECDSA_SIG(ppSig,pPp,cSigStr.size())}
    println("5")
    if(pEcdsaSig.isNull()){
        println("d2i_ECDSA_SIG error")
    }
    println("-6")
    var r = unsafe{ECDSA_SIG_get0_r(pEcdsaSig)}
    println("6")
    var s = unsafe{ECDSA_SIG_get0_s(pEcdsaSig)}
    println("7")
    var rInt = unsafe{r.read()}
    var sInt = unsafe{s.read()}
    println(rInt)
    println(sInt)
    println(rInt.toString().toArray())
    println(sInt.toString().toArray())
    let res = (rInt.toString() + sInt.toString())

    unsafe{
        LibC.free(ppSig)
        LibC.free(pp)
        LibC.free(cSigStr)
        LibC.free(pPp)
        LibC.free(pEcdsaSig)
        LibC.free(r)
        LibC.free(s)
    }

    return res.toArray() |> toBase64String |> JwtUtil.format
  
}


