package baananou.taskmanager;

import baananou.taskmanager.models.Category;
import baananou.taskmanager.models.Task;
import baananou.taskmanager.models.User;
import baananou.taskmanager.repositories.CategoryRepository;
import baananou.taskmanager.repositories.TaskRepository;
import baananou.taskmanager.repositories.UserRepository;
import baananou.taskmanager.security.PasswordEncoderConfig;
import baananou.taskmanager.security.RsaKeyProperties;
import com.github.javafaker.Faker;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.Calendar;

@Configuration
@SpringBootApplication
@EnableConfigurationProperties(RsaKeyProperties.class)
public class TaskManagerApplication {
	Faker faker = new Faker();
	Calendar calendar = Calendar.getInstance();



	public static void main(String[] args) {
		SpringApplication.run(TaskManagerApplication.class, args);
	}

	@Bean
	KeyPair keyPair() throws NoSuchAlgorithmException, IOException {
		KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
		var keyPair=keyPairGenerator.generateKeyPair();
		return keyPair;
	}
	@Bean
	CommandLineRunner commandLineRunner(TaskRepository taskRepository,
										CategoryRepository categoryRepository,
										UserRepository userRepository,
										PasswordEncoderConfig passwordEncoderConfig)
	{
		return args -> {
//			User user1 = new User();
//			user1.setFullName("admin");
//			user1.setEmail("aa@aa.aa");
//			user1.setPassword(passwordEncoderConfig.passwordEncoder().encode("123456"));
//			user1.setRole("ROLE_ADMIN");
//			userRepository.save(user1);
//			categoryRepository.save(Category.builder()
//					.name(faker.lorem().word())
//					.description(faker.lorem().sentence())
//					.build());
//			calendar.add(Calendar.DAY_OF_MONTH, faker.random().nextInt(30) + 1); // Adding 1 to avoid getting the current date
//			taskRepository.save(Task.builder()
//					.title(faker.lorem().sentence())
//					.description(faker.lorem().paragraph())
//					.date(new SimpleDateFormat("yyyy-MM-dd").format(calendar.getTime()))
//					.isCompleted(faker.random().nextBoolean())
//					.isImportant(faker.random().nextBoolean())
//					.createdAt(LocalDateTime.now())
//					.updatedAt(LocalDateTime.now())
//					.category(categoryRepository.findById(2L).get())
//					.build());
		};
	}
}
