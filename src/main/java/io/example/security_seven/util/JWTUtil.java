package io.example.security_seven.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * JWT 관련 서명할 비밀키 를 application.yaml 에 변수로 등록하고 그것을 추출하여 서명 및 검증에 사용,
 * 생성한 JWT 가 얼마나 생존 할 것인지 생존 시간을 관리
 * 하기 때문에 static method로 는 불가능 함으로써 @Component 로 관리
 */
@Component
public class JWTUtil {
    //
    private final SecretKey key;
    private final long accessTokenExpireTime;
    private final long refreshTokenExpireTime;

    public JWTUtil (@Value("${jwt.secret}") String secret,
                    @Value("${jwt.access-token-expire-time}") long accessTokenExpireTime,
                    @Value("${jwt.refresh-token-expire-time}") long refreshTokenExpireTime
    ) {
        //
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpireTime = accessTokenExpireTime;
        this.refreshTokenExpireTime = refreshTokenExpireTime;
    }

    /**
     * 토큰 생성
     * @param username
     * @param role
     * @return String
     */
    public String createAccessToken(String username, String role) {
        //
        Date now = new Date();
        Date expireDate = new Date(now.getTime() + accessTokenExpireTime);
        return Jwts.builder()
                .subject(username) // 사용자ID, 이메일 등
                .claim("role", role)
                .claim("tokenType", "ACCESS")
                .issuedAt(now)
                .expiration(expireDate)
                .signWith(key)
                .compact();
    }

    /**
     * 성공을 하면 Claims 객체에는 다음의 Payload의 정보가 담겨 있다
     * - sub	: claims.getSubject()	: 사용자 식별자
     * - role	: claims.get("role", String.class)	: 사용자 권한
     * - tokenType : claims.get("tokenType", String.class) : 토큰 유형
     * - iat : claims.getIssuedAt() :	토큰 발급 시각
     * - exp : claims.getExpiration() : 토큰 만료 시각
     * @param token
     * @return Claims,  실패하면 Exception
     */
    public Claims getClaims(String token) {
        //
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

    }

    /**
     * refresh Token 생성
     * @param username
     * @param role
     * @return
     */
    public String createRefreshToken(String username, String role) {

        Date now = new Date();
        Date expireDate = new Date(now.getTime() + refreshTokenExpireTime);

        return Jwts.builder()
                .subject(username)
                .claim("role", role)
                .claim("tokenType", "REFRESH")
                .issuedAt(now)
                .expiration(expireDate)
                .signWith(key)
                .compact();
    }
}
