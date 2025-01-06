package jwt4cj

public class JWT {

    public static func builder(): JWTBuilder {
        return JWTBuilder()
    }
    
    public static func parser(): JWTParser {
        return JWTParser()
    }

}
