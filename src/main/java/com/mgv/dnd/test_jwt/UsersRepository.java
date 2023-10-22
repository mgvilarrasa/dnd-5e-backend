package com.mgv.dnd.test_jwt;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsersRepository extends CrudRepository<User, String> {
    Optional<User> findByEmail(String email);
}
