package jwt4cj

import std.collection.HashMap
import serialization.serialization.*
import encoding.json.*
import encoding.base64.*
import crypto.keys.*

let privatekey = 
'''
-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAI/L67AwtQ4bbr8uJ
HGyPrW2py9M4y+jIFY8IRxEFyikWVD+PuZUkfitRQyYysDY5vXV1QKvBrXfVrfeH
zF2LnQ+hgYkDgYYABADkkeFKdFNYBT0Uh+oM96hTu3yyuVmWJtq04TQ4ckrXu7M1
qY9j68NTNFBszDjePgyYAeMEAu7aHXkDRqVmlgp24QB2P3RCXttnJgU0JLYGBn4J
7mFkQVaydS/norQWbZEmfMnP4EbL+MO+SHr2iS/kuognBwfPpgleqUQAdduy8ucx
6g==
-----END PRIVATE KEY-----'''

let publickey = 
'''
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA5JHhSnRTWAU9FIfqDPeoU7t8srlZ
libatOE0OHJK17uzNamPY+vDUzRQbMw43j4MmAHjBALu2h15A0alZpYKduEAdj90
Ql7bZyYFNCS2BgZ+Ce5hZEFWsnUv56K0Fm2RJnzJz+BGy/jDvkh69okv5LqIJwcH
z6YJXqlEAHXbsvLnMeo=
-----END PUBLIC KEY-----'''



main(): Int64 {

    let secret = "hellow"

    let jwt = JWT.builder()
    let claims = HashMap<String,String>()
    claims.add("name", "张w三2")
    claims.add("age", "23")
    // let token = jwt.signWith(HS256,secret)
    let token = jwt.signWith(ES512,privatekey)
    .setClaims(claims)
    .setId("123")
    .compact()
    println("---")
    println(token)
    println("---")
    
    // let jws = JWT.parser()
    // .setSecret(secret)
    // .parseClaimsJws(token)
    
    // println(jws.header.kvMap.serialize().toJson())
    // println(jws.claims.kvMap.serialize().toJson())



    return 0
}