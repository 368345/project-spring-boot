package baananou.taskmanager.services;

import baananou.taskmanager.models.User;
import baananou.taskmanager.repositories.UserRepository;
import baananou.taskmanager.security.PasswordEncoderConfig;
import baananou.taskmanager.dto.UserDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoderConfig passwordEncoderConfig;

    public void registerUser(UserDTO userDTO) {
        User user = new User();
        user.setFullName(userDTO.getFullName());  // Correctly use userDTO
        user.setEmail(userDTO.getEmail());  // Correctly use userDTO
        user.setPassword(passwordEncoderConfig.passwordEncoder().encode(userDTO.getPassword()));  // Uncomment if using password encoding
        user.setRole("ROLE_USER");
        user.setEnabled(false);
        userRepository.save(user);
    }
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }



    public void approveUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setEnabled(true);
        userRepository.save(user);
    }
}
