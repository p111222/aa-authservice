package com.aa_authservice.authservice.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import com.aa_authservice.authservice.modal.User;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

    Optional<User> findByUserEmail(String userEmail);

    @Query("SELECT COUNT(u) > 0 FROM User u WHERE u.sessionId = :sid AND u.id = :sub")
    boolean existsBySessionIdAndId(@Param("sid") String sid, @Param("sub") String sub);

}
