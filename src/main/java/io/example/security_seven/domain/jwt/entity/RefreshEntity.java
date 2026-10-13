package io.example.security_seven.domain.jwt.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class RefreshEntity {
    // 발급한 Refresh 기억하여 로그아웃시 화이트 리스트에서 제거하여 탈취된 Refresh로 접근하는 요청울 벙지
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    @Column(name = "refresh", nullable = false, length = 512)
    private String refresh;
}
