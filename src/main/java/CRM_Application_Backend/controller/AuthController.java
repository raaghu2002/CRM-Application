package CRM_Application_Backend.controller;

import CRM_Application_Backend.model.User;
import CRM_Application_Backend.repository.UserRepository;
import CRM_Application_Backend.servive.UserService;
import CRM_Application_Backend.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    // Endpoint for verifying user and setting password
    @PostMapping(value = "/set-password", produces = "application/json")
    public ResponseEntity<Map<String, String>> setPassword(@RequestBody Map<String, String> requestData) {
        String email = requestData.get("email");
        String token = requestData.get("token");
        String password = requestData.get("newPassword");

        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "User not found"));
        }

        User user = optionalUser.get();

        // Verify the token before setting the password
        if (!token.equals(user.getVerificationToken())) {
            return ResponseEntity.badRequest().body(Map.of("message", "Invalid or expired token"));
        }

        // Validate and set password
        try {
            userService.setUserPassword(email, password);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage())); // Return validation error
        }

        user.setVerified(true);
        user.setVerificationToken(null); // Clear token after use
        userRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "Password set successfully. You can now log in."));
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> requestData) {
        String email = requestData.get("email");
        String password = requestData.get("password");

        Optional<User> optionalUser = userRepository.findByEmail(email);

        Map<String, String> response = new HashMap<>();

        if (optionalUser.isPresent() && userService.verifyUser(email, password)) {
            User user = optionalUser.get();

            // Prevent login if user is frozen
            if (user.isFreezed()) {
                return ResponseEntity.badRequest().body(Map.of("message", "Your account is frozen. Contact admin."));
            }

            String jwtToken = jwtUtil.generateToken(email); // Generate JWT token

            response.put("message", "Login successful!");
            response.put("jwtToken", jwtToken);
            response.put("name", user.getName());
            response.put("email", user.getEmail());
            response.put("role", String.valueOf(user.getRole()));

            return ResponseEntity.ok(response);
        } else {
            response.put("error", "Invalid email or password.");
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestHeader("Authorization") String authHeader) {
        Map<String, String> response = new HashMap<>();

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            response.put("message", "Logout successful! Please remove the token on the client-side.");
            return ResponseEntity.ok(response);
        } else {
            response.put("error", "No token provided, user might already be logged out.");
            return ResponseEntity.badRequest().body(response);
        }
    }

    // Forgot Password - Send OTP
    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(@RequestBody Map<String, String> requestData) {
        String email = requestData.get("email");

        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "User not found"));
        }

        User user = optionalUser.get();

        // Prevent forgot password if user is frozen
        if (user.isFreezed()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Your account is frozen. Contact admin."));
        }

        try {
            userService.generateAndSendOTP(email);
            return ResponseEntity.ok(Map.of("message", "OTP sent to your email."));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }


    // Reset Password - Verify OTP
    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(@RequestBody Map<String, String> requestData) {
        String email = requestData.get("email");
        String otp = requestData.get("otp");
        String newPassword = requestData.get("newPassword");

        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "User not found"));
        }

        User user = optionalUser.get();

        // Prevent password reset if user is frozen
        if (user.isFreezed()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Your account is frozen. Contact admin."));
        }

        if (!user.getVerificationToken().equals(otp) || user.getOtpExpiry().isBefore(LocalDateTime.now())) {
            return ResponseEntity.badRequest().body(Map.of("message", "Invalid or expired OTP"));
        }

        // Reset password
        try {
            userService.setUserPassword(email, newPassword);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }

        // Clear OTP
        user.setVerificationToken(null);
        user.setOtpExpiry(null);
        userRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "Password reset successfully!"));
    }

}
