package com.mgv.dnd.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, String> {
    @Query(value = "SELECT * FROM token where user_id = ?1 AND (expired = 0 OR revoked = 0)", nativeQuery = true)
    List<Token> findAllValidTokenByUser(String id);

    Optional<Token> findByToken(String token);
}
