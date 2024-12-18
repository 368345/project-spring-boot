package baananou.taskmanager.restController;


import baananou.taskmanager.dto.LoginRequest;
import baananou.taskmanager.models.User;
import baananou.taskmanager.security.TokenService;
import baananou.taskmanager.dto.UserDTO;
import baananou.taskmanager.services.UserService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
//@CrossOrigin(origins = "http://http://localhost:4200")
public class AuthRestController {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthRestController.class);
    private final TokenService tokenService;
    private final JwtDecoder jwtDecoder;
    private final AuthenticationManager authenticationManager;
    private final UserService userService;

    public AuthRestController(TokenService tokenService, JwtDecoder jwtDecoder,
                              AuthenticationManager authenticationManager, UserService userService) {
        this.tokenService = tokenService;
        this.jwtDecoder = jwtDecoder;
        this.authenticationManager = authenticationManager;
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody @Valid UserDTO userDTO) {
        try {
            userService.registerUser(userDTO);
            return ResponseEntity.ok(Map.of("message", "User registered successfully. Awaiting admin approval."));
        } catch (Exception e) {
            LOGGER.error("Error during registration: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody @Valid LoginRequest loginRequest) {
        if (loginRequest.grantType().equals("password")) {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.email(), loginRequest.password()
                    )
            );
            User user = userService.getUserByEmail(loginRequest.email());
            Map<String, String> tokens = tokenService.generateJwtToken(user, loginRequest.withRefreshToken());
            return ResponseEntity.ok(Map.of(
                    "tokens", tokens
            ));
        } else if (loginRequest.grantType().equals("refreshToken")) {
            String refreshToken = loginRequest.refreshToken();
            if (refreshToken == null) {
                return new ResponseEntity<>(Map.of("error", "RefreshToken Not Present"), HttpStatus.UNAUTHORIZED);
            }
            Jwt decodedJwt = jwtDecoder.decode(refreshToken);
            String email = decodedJwt.getSubject();
            User user = userService.getUserByEmail(email);
            Map<String, String> tokens = tokenService.generateJwtToken(user, loginRequest.withRefreshToken());
            return ResponseEntity.ok(Map.of(
                    "tokens", tokens
            ));
        }
        return new ResponseEntity<>(Map.of("error", String.format("grantType <<%s>> not supported", loginRequest.grantType())), HttpStatus.UNAUTHORIZED);
    }

}
