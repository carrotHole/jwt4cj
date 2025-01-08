package jwt4cj

import std.collection.*
import serialization.serialization.*
import encoding.json.*
import encoding.base64.*
import std.convert.*
import crypto.digest.*
import std.crypto.digest.digest

public class JWTParser {

    private var secret = ""

    public func setSecret(secret:String) : JWTParser{
        this.secret = secret
        return this
    }

    public func parseClaimsJws(token:String):JWS{
        let tokenArr = token.split(".")
        if(tokenArr.size != 3){
            throw IllegalStateException("token is not valid")
        }

        // 头
        let headArr = tokenArr[0] |> JwtUtil.unformat |> fromBase64String
        let headMap = headArr.getOrThrow(){IllegalStateException("header is not valid")} |> String.fromUtf8 |> JsonValue.fromStr |> DataModel.fromJson |> HashMap<String,String>.deserialize
        let jwsHeader = JWSHeader(headMap)

        // 签名校验
        let hmac = HMAC(secret.toArray(),HashType.SHA256)
        let sBase64 = digest(hmac, "${tokenArr[0]}.${tokenArr[1]}") |> toBase64String|> JwtUtil.format
        if(sBase64 != tokenArr[2]){
            throw IllegalStateException("token is not valid")
        }

        // 载荷
        let payloadArr = tokenArr[1] |> JwtUtil.unformat |> fromBase64String
        let claimsMap = payloadArr.getOrThrow(){IllegalStateException("payload is not valid")} |> String.fromUtf8 |> JsonValue.fromStr |> DataModel.fromJson |> HashMap<String,String>.deserialize
        let jwsClaims = JWSClaims(claimsMap)

        return JWS(
            jwsHeader,
            jwsClaims,
            tokenArr[2]
        )
    }
}
