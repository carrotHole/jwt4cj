package jwt4cj

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
}