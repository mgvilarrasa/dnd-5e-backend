package com.mgv.dnd.test_jwt;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class UserService {
    private final UsersRepository repository;
    private final PasswordEncoder encoder;

    public UserService(
            UsersRepository repository,
            PasswordEncoder encoder
    ) {
        this.repository = repository;
        this.encoder = encoder;
    }

    public User findById(String id) {
        return repository.findById(id).orElse(null);
    }

    public User findByEmail(String email) {
        return repository.findByEmail(email).orElse(null);
    }

    public void createUser(String name, String surname, String email, String password) {
        User user = new User(
                UUID.randomUUID().toString(),
                name,
                surname,
                email,
                encoder.encode(password),
                "ROLE_USER"
        );
        repository.save(user);
    }
}
