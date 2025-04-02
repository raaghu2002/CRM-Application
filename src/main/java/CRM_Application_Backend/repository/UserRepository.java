package CRM_Application_Backend.repository;

import CRM_Application_Backend.model.User;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    // Find user by email
    Optional<User> findByEmail(String email);

    // Get email associated with a verification token
    @Query("SELECT u.email FROM User u WHERE u.verificationToken = :token")
    Optional<String> getEmailByToken(@Param("token") String token);

    // Delete token after verification
    @Transactional
    @Modifying
    @Query("UPDATE User u SET u.verificationToken = NULL WHERE u.verificationToken = :token")
    void deleteToken(@Param("token") String token);


}
