package jwt4cj

import std.collection.{Map,HashMap}
import std.time.DateTime
import encoding.json.*
import encoding.base64.*
import serialization.serialization.*
import crypto.digest.*
import std.crypto.digest.digest

public class JWTBuilder{

    private var secret = ""
    private var alg: SignatureAlgorithm = HS256
    private let claims: HashMap<String, String> = HashMap<String, String>()


    private let header:HashMap<String,String> = HashMap<String,String>()

    public func setClaims(claims: Map<String, String>): JWTBuilder {
        this.claims.putAll(claims)
        return this
    }

    public func signWith(alg: SignatureAlgorithm, secret: String): JWTBuilder {
        this.alg = alg
        this.secret = secret
        return this;
    }

    public func compact(): String {

        if (claims.isEmpty()){
            throw IllegalStateException("claims most be specified")
        }

        if(secret.isEmpty()){
            throw IllegalStateException("secret most be specified")
        }

        // 头
        header.put("typ", "JWT")
        header.put("alg", alg.name())
        let hBase64 = header.serialize().toJson().toString().toArray() |> toBase64String |> JwtUtil.format


        // 负载
        let pBase64 = claims.serialize().toJson().toString().toArray() |> toBase64String|> JwtUtil.format

        // 签名
        let sBase64 = JwtUtil.sign(secret, alg, "${hBase64}.${pBase64}")


        return "${hBase64}.${pBase64}.${sBase64}"
    }




    public func setIssuer( iss:String):JWTBuilder{
        claims.put("iss", iss)
        return this
    }

    public func setSubject( sub:String):JWTBuilder{
         claims.put("sub", sub)
         return this
    }

    public func setAudience( aud:String):JWTBuilder{
         claims.put("aud", aud)
         return this
    }

    public func setExpiration( exp:DateTime):JWTBuilder{
        claims.put("exp", exp.toString())
         return this
    }

    public func setNotBefore( nbf:DateTime):JWTBuilder{
        claims.put("nbf", nbf.toString())
         return this
    }

    public func setIssuedAt( iat:DateTime):JWTBuilder{
        claims.put("iat", iat.toString())
         return this
    }

    public func setId( jti:String):JWTBuilder{
        claims.put("jti", jti)
         return this
    }



}