package CRM_Application_Backend.controller;

import CRM_Application_Backend.model.Role;
import CRM_Application_Backend.model.User;
import CRM_Application_Backend.repository.UserRepository;
import CRM_Application_Backend.servive.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    // Only ADMIN can add users
    @PreAuthorize("hasRole('ADMIN')") // Use hasRole if roles are prefixed with ROLE_
    @PostMapping("/add-user")
    public ResponseEntity<String> addUser(
            @RequestParam String name,
            @RequestParam String email,
            @RequestParam String role) { // Accept role as a String

        // Check if user already exists
        if (userRepository.findByEmail(email).isPresent()) {
            return ResponseEntity.badRequest().body("User with this email already exists.");
        }

        try {
            Role userRole = Role.valueOf(role.toUpperCase()); // Convert string to enum
            userService.addUser(name, email, userRole);
            return ResponseEntity.ok("User added successfully! Verification email sent.");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body("Invalid role. Allowed values: ADMIN, USER, VP, RECRUITER.");
        }
    }

    // Only Admin can Freeze
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/freeze-user/{email}")
    public ResponseEntity<String> freezeUser(@PathVariable String email, @RequestParam boolean freeze) {
        System.out.println("Freeze request for: " + email + ", Status: " + freeze);
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isEmpty()) {
            return ResponseEntity.badRequest().body("User not found.");
        }

        User user = userOptional.get();
        user.setFreezed(freeze);
        userRepository.save(user);
        return ResponseEntity.ok("User freeze status updated.");
    }

}
