package CRM_Application_Backend.servive;

import CRM_Application_Backend.model.Role;
import CRM_Application_Backend.model.User;
import CRM_Application_Backend.repository.UserRepository;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private final ConcurrentHashMap<String, String> otpStorage = new ConcurrentHashMap<>();

    public void addUser(String name, String email, Role role) {
        User user = new User();
        user.setName(name);
        user.setEmail(email);
        user.setRole(role);

        String token = UUID.randomUUID().toString();
        user.setVerificationToken(token);
        user.setVerified(false);

        userRepository.save(user);
        sendVerificationEmail(user);
    }

    public ResponseEntity<String> freezeUser(String email, boolean freeze) {
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isEmpty()) {
            return ResponseEntity.badRequest().body("User not found.");
        }

        User user = optionalUser.get();
        user.setFreezed(freeze);
        userRepository.save(user);

        String status = freeze ? "frozen" : "unfrozen";
        return ResponseEntity.ok("User " + email + " has been " + status + ".");
    }


    public void setUserPassword(String email, String newPassword) {
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isEmpty()) {
            throw new IllegalArgumentException("User not found.");
        }

        User user = optionalUser.get();

        String passwordRegex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,12}$";
        if (!newPassword.matches(passwordRegex)) {
            throw new IllegalArgumentException("Password must be 8-12 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    public boolean verifyUser(String email, String password) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        return optionalUser.map(user -> passwordEncoder.matches(password, user.getPassword())).orElse(false);
    }

    private void sendVerificationEmail(User user) {
        String subject = "Set Your Password";
        String link = "http://localhost:8089/auth/set-password?email=" + user.getEmail() + "&token=" + user.getVerificationToken();
        String body = "Click here to set your password: " + link;

        sendEmail(user.getEmail(), subject, body);
    }

    // Generate and send the OTP to Reset-Password
    public void generateAndSendOTP(String email) {
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isEmpty()) {
            throw new IllegalArgumentException("User not found.");
        }

        User user = optionalUser.get();
        String otp = String.valueOf(new Random().nextInt(900000) + 100000); // Generate 6-digit OTP
        user.setVerificationToken(otp); // Store OTP in place of the token
        user.setOtpExpiry(LocalDateTime.now().plusMinutes(5)); // Set expiry (5 minutes)

        userRepository.save(user);

        String subject = "Reset Password OTP";
        String body = "Your OTP for password reset is: " + otp + ". It is valid for 5 minutes.";

        sendEmail(user.getEmail(), subject, body);
    }

    private void sendEmail(String to, String subject, String body) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(body);
            mailSender.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

}
