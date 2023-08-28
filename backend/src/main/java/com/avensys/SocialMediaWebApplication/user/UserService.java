package com.avensys.SocialMediaWebApplication.user;

import com.avensys.SocialMediaWebApplication.cloudinary.CloudinaryHelper;
import com.avensys.SocialMediaWebApplication.exceptions.ResourceAccessDeniedException;
import com.avensys.SocialMediaWebApplication.exceptions.ResourceNotFoundException;
import com.avensys.SocialMediaWebApplication.jwt.JwtService;
import com.avensys.SocialMediaWebApplication.role.Role;
import com.avensys.SocialMediaWebApplication.role.RoleRepository;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final CloudinaryHelper cloudinaryHelper;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public UserService(UserRepository userRepository, RoleRepository roleRepository, CloudinaryHelper cloudinaryHelper, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.cloudinaryHelper = cloudinaryHelper;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    public User findUserById(long id) {
        Optional<User> user = userRepository.findById(id);
        if (user.isPresent()) {
            return user.get();
        } else {
            throw new ResourceNotFoundException("User with id %s not found".formatted(id));
        }
    }

    public UserResponseDTO findUserByIdDTO(long id) {
        Optional<User> user = userRepository.findById(id);
        if (user.isPresent()) {
            return userToUserResponseDTO(user.get());
        } else {
            throw new ResourceNotFoundException("User with id %s not found".formatted(id));
        }
    }

    public UserUpdateResponseDTO updateUserById(long id, UserUpdateRequestDTO userUpdateRequest) {
        User userUpdate = findUserById(id);

        // Check if user is admin or user to update belong to user before user is allowed update user profile
        //    if (!checkIsAdmin()){
        //        checkUserToUpdateBelongsToUser(userUpdate);
        //    }

        userUpdate.setPassword(passwordEncoder.encode(userUpdateRequest.password()));
        userUpdate.setEmail(userUpdateRequest.email());
        userUpdate.setFirstName(userUpdateRequest.firstName());
        userUpdate.setLastName(userUpdateRequest.lastName());
        userUpdate.setGender(userUpdateRequest.gender());

        if (userUpdateRequest.avatarFile() != null && !userUpdateRequest.avatarFile().isEmpty()) {
            System.out.println("------------> 1");
            if (userUpdate.getAvatarPublicId() != null && !userUpdate.getAvatarPublicId().isEmpty()) {
                deleteFile(userUpdate);
            }
            Map uploadResult = addFile(userUpdateRequest);
            userUpdate.setAvatarUrl(uploadResult.get("url").toString());
            userUpdate.setAvatarPublicId(uploadResult.get("public_id").toString());
            System.out.println(userUpdate.getAvatarUrl());
        } else if (userUpdateRequest.avatarUrl() == null) {
            System.out.println("------------> 2");
            if (userUpdate.getAvatarPublicId() != null && !userUpdate.getAvatarPublicId().isEmpty()) {
                deleteFile(userUpdate);
            }
            userUpdate.setAvatarUrl(null);
            userUpdate.setAvatarPublicId(null);
        }

        User updatedUser = userRepository.save(userUpdate);
        String token = jwtService.generateToken(updatedUser.getEmail());

        return userToUserUpdateResponseDTO(userUpdate, token);
    }

    public UserUpdateResponseDTO updateUserByIdWithRoles(long id, UserUpdateRequestDTO userUpdateRequest) {
        User userUpdate = findUserById(id);

        // Check if user is admin or user to update belong to user before user is allowed update user profile
        if (!checkIsAdmin()){
            throw new ResourceAccessDeniedException("Access denied to resource");
        }

        userUpdate.setPassword(passwordEncoder.encode(userUpdateRequest.password()));
        userUpdate.setEmail(userUpdateRequest.email());
        userUpdate.setFirstName(userUpdateRequest.firstName());
        userUpdate.setLastName(userUpdateRequest.lastName());
        userUpdate.setGender(userUpdateRequest.gender());

        if (userUpdateRequest.avatarFile() != null && !userUpdateRequest.avatarFile().isEmpty()) {
            System.out.println("------------> 1");
            if (userUpdate.getAvatarPublicId() != null && !userUpdate.getAvatarPublicId().isEmpty()) {
                deleteFile(userUpdate);
            }
            Map uploadResult = addFile(userUpdateRequest);
            userUpdate.setAvatarUrl(uploadResult.get("url").toString());
            userUpdate.setAvatarPublicId(uploadResult.get("public_id").toString());
            System.out.println(userUpdate.getAvatarUrl());
        } else if (userUpdateRequest.avatarUrl() == null) {
            System.out.println("------------> 2");
            if (userUpdate.getAvatarPublicId() != null && !userUpdate.getAvatarPublicId().isEmpty()) {
                deleteFile(userUpdate);
            }
            userUpdate.setAvatarUrl(null);
            userUpdate.setAvatarPublicId(null);
        }

        // Update Roles
        userUpdate.getRoles().clear();
        Arrays.stream(userUpdateRequest.roles()).forEach(role -> {
            System.out.println(role);
            Role roleFound = roleRepository.findRolesByName(role);
            userUpdate.addRole(roleFound);
        });

        User updatedUser = userRepository.save(userUpdate);
        String token = jwtService.generateToken(updatedUser.getEmail());

        return userToUserUpdateResponseDTO(userUpdate, token);
    }

    public void deleteUserById(long id) {
        User user = findUserById(id);
        userRepository.delete(user);
    }

    public boolean existUserByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public List<UserResponseDTO> searchUser(String keyword) {
        List<User> users = userRepository.findByUserByFirstNameOrLastNameOrEmail(keyword);
        List<UserResponseDTO> userResponseDTOs = users.stream()
            .map(user -> userToUserResponseDTO(user))
            .collect(Collectors.toList());
//        users.stream().map(this::userToUserResponseDTO).toList();
        return userResponseDTOs;
    }


    private UserResponseDTO userToUserResponseDTO(User user) {
        return new UserResponseDTO(
            user.getId(),
            user.getEmail(),
            user.getFirstName(),
            user.getLastName(),
            user.getGender(),
            user.getAvatarUrl(),
            user.getCreatedAt(),
            user.getUpdatedAt()
        );
    }

    private UserUpdateResponseDTO userToUserUpdateResponseDTO(User user, String token) {
        return new UserUpdateResponseDTO(
            user.getId(),
            user.getEmail(),
            user.getFirstName(),
            user.getLastName(),
            user.getGender(),
            user.getAvatarUrl(),
            token,
            user.getRolesList(),
            user.getCreatedAt(),
            user.getUpdatedAt()
        );
    }

    private void checkUserToUpdateBelongsToUser(User UserUpdateRequest) {
        Principal principal = SecurityContextHolder.getContext().getAuthentication();
        Optional<User> user = userRepository.findByEmail(principal.getName());
        if (UserUpdateRequest.getId() != user.get().getId()) {
            throw new ResourceAccessDeniedException("Access denied to resource");
        }
    }

    private boolean checkIsAdmin() {
        return SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
                .anyMatch(role -> role.getAuthority().equals("ROLE_ADMIN"));
    }

    private void deleteFile(User user) {
        try {
            Map deleteResult = cloudinaryHelper.delete(user.getAvatarPublicId(), user.getAvatarUrl());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private Map addFile(UserUpdateRequestDTO userUpdateRequest) {
        try {
            return cloudinaryHelper.upload(userUpdateRequest.avatarFile());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
