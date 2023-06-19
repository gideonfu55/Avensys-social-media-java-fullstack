package com.avensys.SocialMediaWebApplication.user;

import com.avensys.SocialMediaWebApplication.response.CustomResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("users/email")
    public ResponseEntity<Boolean> existUserByEmail(@RequestParam String email) {
        Boolean isEmailExist = userService.existUserByEmail(email);
        return new ResponseEntity<>(isEmailExist, HttpStatus.OK);
    }

    @GetMapping("users")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.findAllUsers();
        return new ResponseEntity<>(users, HttpStatus.OK);
    }

    @GetMapping("users/{userId}")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<UserResponseDTO> getUser(@PathVariable long userId) {
        UserResponseDTO user = userService.findUserByIdDTO(userId);
        if (user != null) {
            return new ResponseEntity<>(user, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @PatchMapping("users/{userId}")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<UserUpdateResponseDTO> UpdateUser(@PathVariable long userId, @ModelAttribute UserUpdateRequestDTO userUpdateRequest) {
        UserUpdateResponseDTO userResponse = userService.updateUserById(userId, userUpdateRequest);
        return new ResponseEntity<>(userResponse, HttpStatus.OK);
    }

    @GetMapping("users/search")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<List<UserResponseDTO>> searchUser(@RequestParam String keyword) {
        List<UserResponseDTO> users = userService.searchUser(keyword);
        return new ResponseEntity<>(users, HttpStatus.OK);
    }

    // Admin Routes to manage users

    @GetMapping("admin/users")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<List<User>> adminGetAllUsers() {
        List<User> users = userService.findAllUsers();
        return new ResponseEntity<>(users, HttpStatus.OK);
    }

    @DeleteMapping("admin/users/{userId}")
    public ResponseEntity<CustomResponse> adminDeleteUser(@PathVariable long userId) {
        userService.deleteUserById(userId);
        return new ResponseEntity<>(new CustomResponse("User deleted successfully"), HttpStatus.OK);
    }

    @PatchMapping("admin/users/{userId}")
    public ResponseEntity<UserUpdateResponseDTO> adminUpdateUser(@PathVariable long userId, @ModelAttribute UserUpdateRequestDTO userUpdateRequest) {
        UserUpdateResponseDTO userResponse = userService.updateUserByIdWithRoles(userId, userUpdateRequest);
        return new ResponseEntity<>(userResponse, HttpStatus.OK);
    }

}
