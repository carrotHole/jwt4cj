package jwt4cj

import std.collection.HashMap;
import serialization.serialization.*
import encoding.json.*

public class JWS{
    public JWS(
        private let _header:JWSHeader,
        private let _claims:JWSClaims,
        private let _signature:String
    ){}

    public prop header:JWSHeader{
        get(){
            return this._header
        }
    }
    public prop claims:JWSClaims{
        get(){
            return this._claims
        }
    }
    public prop signature:String{
        get(){
            return this._signature
        }
    }
}

public class JWSHeader {
    private let _kvMap : HashMap<String,String>

    public JWSHeader(headerMap:HashMap<String,String>){
        this._kvMap = headerMap
    }

    public prop typ:String{
        get(){
            this._kvMap.get("typ").getOrThrow(){IllegalStateException("typ is not set")}
        }
    }

    public mut prop alg:String{
        get(){
            this._kvMap.get("alg").getOrThrow(){IllegalStateException("alg is not set")}
        }
        set(alg){
            this._kvMap.put("alg",alg)
        }
    }

    public prop kvMap:HashMap<String,String>{
        get(){
            return this._kvMap
        }
    }

    public func get(key:String):?String{
        return this._kvMap.get(key)
    }

    public func toJsonString():String{
        return this._kvMap.serialize().toJson().toString()
    }
}

public class JWSClaims{
    
    private let _kvMap : HashMap<String,String>

    public JWSClaims(claimsMap:HashMap<String,String>){
        this._kvMap = claimsMap
    }

    public prop kvMap:HashMap<String,String>{
        get(){
            return this._kvMap
        }
    }

    public func get(key:String):?String{
        return this._kvMap.get(key)
    }
    public func toJsonString():String{
        return this._kvMap.serialize().toJson().toString()
    }
}