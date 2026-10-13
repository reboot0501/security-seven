package io.example.security_seven.domain.jwt.service;

import io.example.security_seven.domain.jwt.entity.RefreshEntity;
import io.example.security_seven.domain.jwt.repository.RefreshRepository;
import io.example.security_seven.util.JWTUtil;
import io.jsonwebtoken.Claims;
import org.springframework.stereotype.Service;

@Service
public class RefreshService {
    //
    private final RefreshRepository refreshRepository;
    private final JWTUtil jwtUtil;

    public RefreshService (RefreshRepository refreshRepository, JWTUtil jwtUtil) {
        //
        this.refreshRepository = refreshRepository;
        this.jwtUtil = jwtUtil;
    }

    public void registerRefreshEntity(String username, String refreshToken) {
        //
        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refreshToken);
        refreshRepository.save(refreshEntity);
    }

    public String refresh(String refreshToken) {
        // refresh token 검증
        Claims claims;
        try {
            //
            claims = jwtUtil.getClaims(refreshToken);
        } catch (Exception e) {
            //
            throw new IllegalArgumentException("유효하지 않은 Refresh Token 입니다, !!!!");
        }
        String tokenType = claims.get("tokenType", String.class);

        if (!"REFRESH".equals(tokenType)) {
            throw new IllegalArgumentException("Refresh Token이 아닙니다.");
        }

        // 화이트 리스트 확인
        boolean exists = refreshRepository.existsByRefresh(refreshToken);

        if (!exists) {
            throw new IllegalArgumentException("로그아웃되었거나 만료된 Refresh Token입니다.");
        }

        // 재발급
        String username = claims.getSubject();
        String role = claims.get("role", String.class);

        return jwtUtil.createAccessToken(username, role);

    }
}
