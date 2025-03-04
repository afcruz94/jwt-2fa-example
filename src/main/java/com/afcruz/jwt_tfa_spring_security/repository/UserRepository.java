package com.afcruz.jwt_tfa_spring_security.repository;

import com.afcruz.jwt_tfa_spring_security.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByEmail(String email);

    @Query(nativeQuery = true, value = "SELECT count(*) FROM _user WHERE email = :email")
    Integer verifyIfEmailExist(@Param("email") String email);
}
