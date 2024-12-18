package baananou.taskmanager.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDTO {
    private String fullName;
    private String email;
    private String password; // Only used during registration.
}

