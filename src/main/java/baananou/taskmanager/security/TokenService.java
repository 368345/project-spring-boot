package baananou.taskmanager.security;

import baananou.taskmanager.models.User;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

@Service
public class TokenService {
    private final JwtEncoder jwtEncoder;

    public TokenService(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    public Map<String, String> generateJwtToken(User user, boolean withRefreshToken) {
        Map<String, String> idToken = new HashMap<>();
        Instant instant = Instant.now();

        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .issuer("auth-service")
                .issuedAt(instant)
                .expiresAt(instant.plus(withRefreshToken ? 5 : 30, ChronoUnit.MINUTES))
                .subject(user.getEmail())
                .claim("scope", user.getRole())
                .claim("enabled", user.isEnabled())
                .claim("userId", user.getId())
                .claim("userName", user.getFullName())
                .build();

        String accessToken = this.jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        idToken.put("accessToken", accessToken);

        if (withRefreshToken) {
            JwtClaimsSet jwtRefreshTokenClaimsSet = JwtClaimsSet.builder()
                    .issuer("auth-service")
                    .issuedAt(instant)
                    .expiresAt(instant.plus(10, ChronoUnit.MINUTES))
                    .subject(user.getEmail())
                    .build();
            String refreshToken = this.jwtEncoder.encode(JwtEncoderParameters.from(jwtRefreshTokenClaimsSet)).getTokenValue();
            idToken.put("refreshToken", refreshToken);
        }
        return idToken;
    }
}
