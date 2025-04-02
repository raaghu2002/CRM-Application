package CRM_Application_Backend.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Name is required")
    @Size(min = 2, max = 50, message = "Name must be between 2 and 50 characters")
    @Column(nullable = false)
    private String name;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Column(unique = true, nullable = false)
    private String email;


    private String password;

    private LocalDateTime otpExpiry;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    private String verificationToken;

    @Column(nullable = false)
    private boolean isFreezed = false;


    @Column(nullable = false)
    private boolean verified = false;
}