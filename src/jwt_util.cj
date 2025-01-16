package jwt4cj

import std.crypto.digest.*
import crypto.digest.*
import crypto.keys.*
import encoding.base64.*
import std.convert.*
import encoding.hex.*
import std.io.*

internal  class JwtUtil {
    internal  static func format(s:String):String{
        return s.replace("/","_").replace("+","-").replace("=","")
    }

    internal  static func unformat(s:String):String{
         var res = s.replace("_","/").replace("-","+")
         let i = res.size % 4
         if(i != 0){
            for(j in 0..(4-i)){
             res += "="
            }
         }

         return res
    }

    internal static func sign(secret:String, alg: SignatureAlgorithm, value:String):String{
        return  match(alg){
            case HS256 => hms(secret, HashType.SHA256, value)
            case HS384 => hms(secret, HashType.SHA384, value)
            case HS512 => hms(secret, HashType.SHA512, value)
            case ES256 => ecdsa(secret, SHA256(), value, 256)
            case ES384 => ecdsa(secret, SHA384(), value, 384)
            case ES512 => ecdsa(secret, SHA512(), value, 512)
            case RS256 => rs(secret, SHA256(), value)
            case RS384 => rs(secret, SHA384(), value)
            case RS512 => rs(secret, SHA512(), value)
            case PS256 => ps(secret, SHA256(), value)
            case PS384 => ps(secret, SHA384(), value)
            case PS512 => ps(secret, SHA512(), value)
            case _ => throw UnsupportedException("Unsupported algorithm: ${alg.name()}")
        }
    }

    private static func hms(secret:String, hashType: HashType, value:String):String{
        return digest(HMAC(secret.toArray(),hashType),value) |> toBase64String |> format
    }

    private static func ecdsa(secret:String, digestIns: Digest, value:String, size: Int64):String{    
        let pri = ECDSAPrivateKey.decodeFromPem(secret)  
        let md = digest(digestIns, value.toArray())
        convertEcdsa(ECDSAPrivateKey.decodeFromPem(secret).sign(md), size)
    }

    private static func rs(secret:String, digestIns: Digest, value:String):String{
        return RSAPrivateKey.decodeFromPem(secret).sign(digestIns, digest(digestIns, value), padType: PKCS1) |> toBase64String |> format
    }

    private static func ps(secret:String, digestIns: Digest, value:String):String{
        println("pss type")
        return RSAPrivateKey.decodeFromPem(secret).sign(digestIns, digest(digestIns, value), padType: PSS(PSSOption(12))) |> toBase64String |> format
    }

}