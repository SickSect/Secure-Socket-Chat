package org.ugina.repository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;
import org.ugina.entity.User;

import java.util.Optional;

import static org.testng.Assert.*;

@SpringBootTest
public class UserRepositoryTest extends AbstractTestNGSpringContextTests {

    @Autowired
    private UserRepository userRepository;

    @AfterMethod
    public void cleanup() {
        // Чистим тестовые данные после каждого теста
        userRepository.findByUsername("test_user").ifPresent(userRepository::delete);
    }

    @Test
    public void saveAndFindUser() {
        User user = new User();
        user.setUsername("test_user");
        user.setPasswordHash("$2a$10$fakehashfakehashfakehash");
        user.setPublicKey("MIIBIjANBgkqhkiG9w0BAQEF...");

        User saved = userRepository.save(user);

        assertNotNull(saved.getId(), "id должен быть сгенерирован БД");
        assertNotNull(saved.getCreatedAt(), "createdAt должен проставиться");

        Optional<User> found = userRepository.findByUsername("test_user");
        assertTrue(found.isPresent(), "пользователь должен находиться по username");
        assertEquals(found.get().getUsername(), "test_user");
    }

    @Test
    public void existsByUsernameWorks() {
        assertFalse(userRepository.existsByUsername("test_user"),
                "до сохранения пользователя нет");

        User user = new User();
        user.setUsername("test_user");
        user.setPasswordHash("$2a$10$fakehash");
        user.setPublicKey("fakekey");
        userRepository.save(user);

        assertTrue(userRepository.existsByUsername("test_user"),
                "после сохранения пользователь есть");
    }

    @Test
    public void findByUsernameReturnsEmptyForUnknown() {
        Optional<User> found = userRepository.findByUsername("nonexistent_user_xyz");
        assertTrue(found.isEmpty(), "несуществующий пользователь → Optional.empty");
    }
}