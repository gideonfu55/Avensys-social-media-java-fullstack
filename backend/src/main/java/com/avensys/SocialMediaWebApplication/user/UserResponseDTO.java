package com.avensys.SocialMediaWebApplication.user;

import java.time.LocalDateTime;

public record UserResponseDTO (
  long id,
  String email,
  String firstName,
  String lastName,
  String gender,
  String avatarUrl,
  LocalDateTime createdAt,
  LocalDateTime updatedAt
) {}
