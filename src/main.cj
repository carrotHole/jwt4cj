package jwt4cj

import std.collection.HashMap
import serialization.serialization.*
import encoding.json.*
import encoding.base64.*

main(): Int64 {

    let secret = "hello  "

    let jwt = JWT.builder()
    let claims = HashMap<String,String>()
    claims.put("name", "张w三")
    claims.put("age", "23")
    let token = jwt.signWith(HS384,secret)
    .setClaims(claims)
    .setId("123")
    .compact()
    println(token)
    
    let jws = JWT.parser()
    .setSecret(secret)
    .parseClaimsJws(token)
    
    println(jws.header.kvMap.serialize().toJson())
    println(jws.claims.kvMap.serialize().toJson())


    return 0
}