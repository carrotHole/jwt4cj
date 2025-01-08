package jwt4cj

import std.crypto.digest.Digest
import crypto.digest.*

public enum SignatureAlgorithm{
 
    HS256|HS384|HS512|ES256|ES384|ES512|RS256|RS384|RS512|PS256|PS384|PS512 

    public func name(){
        match(this){
            case HS256 => "HS256"
            case HS384 => "HS384"
            case HS512 => "HS512"
            case ES256 => "ES256"
            case ES384 => "ES384"
            case ES512 => "ES512"
            case RS256 => "RS256"
            case RS384 => "RS384"
            case RS512 => "RS512"
            case PS256 => "PS256"
            case PS384 => "PS384"
            case PS512 => "PS512"
        }
    }


    public static func fromName(name:String):SignatureAlgorithm{
        match(name){
            case "HS256" => HS256
            case "HS384" => HS384
            case "HS512" => HS512
            case "ES256" => ES256
            case "ES384" => ES384
            case "ES512" => ES512
            case "RS256" => RS256
            case "RS384" => RS384
            case "RS512" => RS512
            case "PS256" => PS256
            case "PS384" => PS384
            case "PS512" => PS512
            case _ => throw IllegalStateException("Invalid signature algorithm name")
        }
    
    }

}