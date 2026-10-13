package io.example.security_seven.domain.jwt.repository;

import io.example.security_seven.domain.jwt.entity.RefreshEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshRepository extends JpaRepository<RefreshEntity, Long> {
    //
    boolean existsByRefresh(String refreshToken);
}
