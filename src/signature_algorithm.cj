package jwt4cj

import std.crypto.digest.Digest
import crypto.digest.*

public enum SignatureAlgorithm{
 
    HS256|HS384|HS512

    public func name(){
        match(this){
            case HS256 => "HS256"
            case HS384 => "HS384"
            case HS512 => "HS512"
        }
    }

    public func hashType():HashType{
        match(this){
            case HS256 => HashType.SHA256
            case HS384 => HashType.SHA384
            case HS512 => HashType.SHA512
        }
    }

    public static func fromName(name:String):HashType{
        match(name){
            case "HS256" => HashType.SHA256
            case "HS384" => HashType.SHA384
            case "HS512" => HashType.SHA512
            case _ => throw IllegalStateException("Invalid signature algorithm name")
        }
    
    }

}