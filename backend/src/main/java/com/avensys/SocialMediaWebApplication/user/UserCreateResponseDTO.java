package com.avensys.SocialMediaWebApplication.user;

import java.time.LocalDateTime;

public record UserCreateResponseDTO(
	long id,
	String email,
	String firstName,
	String lastName,
	String gender,
	LocalDateTime createdAt,
	LocalDateTime updatedAt) {
}
