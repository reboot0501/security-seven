package io.example.security_seven.api;

import io.example.security_seven.domain.jwt.entity.RefreshRequestDTO;
import io.example.security_seven.domain.jwt.service.RefreshService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class JWTController {
    //
    private final RefreshService refreshService;

    public JWTController(RefreshService refreshService) {
        this.refreshService = refreshService;
    }

    @PostMapping("/jwt/refresh")
    public String refresh(@RequestBody RefreshRequestDTO dto) {
        //
        return refreshService.refresh(dto.refreshToken());
    }

}
