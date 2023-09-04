package com.avensys.SocialMediaWebApplication.post;

import com.avensys.SocialMediaWebApplication.cloudinary.CloudinaryHelper;
import com.avensys.SocialMediaWebApplication.exceptions.ResourceAccessDeniedException;
import com.avensys.SocialMediaWebApplication.exceptions.ResourceNotFoundException;
import com.avensys.SocialMediaWebApplication.user.User;
import com.avensys.SocialMediaWebApplication.user.UserRepository;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class PostService {

    private final PostRepository postRepository;
    private final UserRepository userRepository;
    private final CloudinaryHelper cloudinaryHelper;

    public PostService(PostRepository postRepository, UserRepository userRepository, CloudinaryHelper cloudinaryHelper) {
        this.postRepository = postRepository;
        this.userRepository = userRepository;
        this.cloudinaryHelper = cloudinaryHelper;
    }

    public List<PostResponseDTO> findAllPosts() {
        return postRepository.findAll().stream()
            .map(post -> postToPostResponseDTO(post))
            .collect(Collectors.toList());

    }

    public Post findPostById(long id) {
        Optional<Post> post = postRepository.findById(id);
        if (post.isPresent()) {
            return post.get();
        } else {
            throw new ResourceNotFoundException("Post with id %s not found".formatted(id));
        }
    }

    public PostResponseDTO createPost(PostCreateRequestDTO postCreateRequest) {
        Principal principal = SecurityContextHolder.getContext().getAuthentication();
        Optional<User> user = userRepository.findByEmail(principal.getName());

        // Check if user is admin or post belong to user before user is allowed to create a post:
        if (!user.isPresent()) {
            throw new UsernameNotFoundException("User not found");
        }

        Post post = new Post();
        post.setTitle(postCreateRequest.title());
        post.setCaption(postCreateRequest.caption());

        if (postCreateRequest.link() != null && !postCreateRequest.link().isEmpty()) {
            post.setContentUrl(postCreateRequest.link());
        } else if (postCreateRequest.file() != null && !postCreateRequest.file().isEmpty()) {
            System.out.println("Uploading file.....");
            try {
                Map uploadResult = cloudinaryHelper.upload(postCreateRequest.file());
                post.setContentUrl((uploadResult.get("url").toString()));
                post.setContentId((uploadResult.get("public_id").toString()));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        post.setUser(user.get());
        Post postSaved = postRepository.save(post);
        PostUserInfoDTO postUserInfo = userToPostUserInfoDTO(user.get());

        PostResponseDTO postCreateResponse = new PostResponseDTO(postSaved.getId(), postSaved.getTitle(), postSaved.getCaption(), postSaved.getContentUrl(), postSaved.getCreatedAt(), postSaved.getUpdatedAt(), postUserInfo);
        return postCreateResponse;
    }

    public PostResponseDTO updatePost(long id, PostUpdateRequestDTO postUpdateRequest) {
        Post post = findPostById(id);

        // Check if user is admin or post belong to user before user is allowed to update a post
//        if (!checkIsAdmin()) {
//            checkPostBelongToUser(post);
//        }

        post.setTitle(postUpdateRequest.title());
        post.setCaption(postUpdateRequest.caption());

        System.out.println("FILE: " + postUpdateRequest.file());

        if (!isPostLinkEmpty(postUpdateRequest) && !postUpdateRequest.link().equals(post.getContentUrl())) {
            System.out.println("------------->>>> 1");
            if (post.getContentId() != null && !post.getContentId().isEmpty()) {
                deleteFile(post);
                post.setContentId(null);
            }
            post.setContentUrl(postUpdateRequest.link());
        } else if (isPostLinkEmpty(postUpdateRequest) && !isPostFileEmpty(postUpdateRequest)) {
            System.out.println("------------->>>> 2");
            if (post.getContentId() != null && !post.getContentId().isEmpty()) {
                deleteFile(post);
                post.setContentId(null);
                post.setContentUrl(null);
            }
            Map uploadResult = addFile(postUpdateRequest);
            post.setContentUrl((uploadResult.get("url").toString()));
            post.setContentId((uploadResult.get("public_id").toString()));
        } else if (!isPostLinkEmpty(postUpdateRequest) && postUpdateRequest.link() != post.getContentUrl()) {
            if (post.getContentId() != null && !post.getContentId().isEmpty()) {
                deleteFile(post);
                post.setContentId(null);
                post.setContentUrl(null);
            }
            post.setContentUrl(postUpdateRequest.link());
        } else if (isPostFileEmpty(postUpdateRequest) && isPostLinkEmpty(postUpdateRequest)) {
            System.out.println("------------->>>> 3");
            if (post.getContentId() != null && !post.getContentId().isEmpty()) {
                deleteFile(post);
            }
            post.setContentId(null);
            post.setContentUrl(null);
        }

        System.out.println("=============================================");
        Post postSaved = postRepository.save(post);
        PostUserInfoDTO postUserInfo = userToPostUserInfoDTO(postSaved.getUser());
        PostResponseDTO postUpdateResponse = new PostResponseDTO(postSaved.getId(), postSaved.getTitle(), postSaved.getCaption(), postSaved.getContentUrl(), postSaved.getCreatedAt(), postSaved.getUpdatedAt(), postUserInfo);
        return postUpdateResponse;
    }


    public void deletePostById(long id) {
        Post post = findPostById(id);

        // Check if user is admin or post belong to user before user is allowed to delete a post
//        if (!checkIsAdmin()) {
//            checkPostBelongToUser(post);
//        }

//        Optional<User> user = userRepository.findByEmail("k1@gmail.com");
//        user.get().getPosts().remove(post);
//        userRepository.save(user.get());

        if (post.getContentId() != null && !post.getContentId().isEmpty()) {
            try {
                Map deleteResult = cloudinaryHelper.delete(post.getContentId(), post.getContentUrl());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        System.out.println("Deleting post.....");
        postRepository.deleteById(id);
        System.out.println("Post deleted.....");
    }

    public List<PostResponseDTO> getPostsByUserId(long id) {
        Optional<List<Post>> userPosts = postRepository.findAllByUserId(id);
        if (userPosts.isPresent()) {
            return userPosts.get().stream()
                .map(post -> postToPostResponseDTO(post))
                .collect(Collectors.toList());
        } else {
            throw new ResourceNotFoundException("Posts for users not found");
        }
    }

    private boolean isPostLinkEmpty(PostUpdateRequestDTO postUpdateRequest) {
        return postUpdateRequest.link() == null || postUpdateRequest.link().isEmpty();
    }

    private boolean isPostFileEmpty(PostUpdateRequestDTO postUpdateRequest) {
        return postUpdateRequest.file() == null || postUpdateRequest.file().isEmpty();
    }

    private void deleteFile(Post post) {
        try {
            Map deleteResult = cloudinaryHelper.delete(post.getContentId(), post.getContentUrl());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private Map addFile(PostUpdateRequestDTO postUpdateRequest) {
        try {
            return cloudinaryHelper.upload(postUpdateRequest.file());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private PostUserInfoDTO userToPostUserInfoDTO(User user) {
        return new PostUserInfoDTO(
            user.getEmail(),
            user.getFirstName(),
            user.getLastName(),
            user.getGender(),
            user.getAvatarUrl()
        );
    }

    private PostResponseDTO postToPostResponseDTO(Post post) {
        PostUserInfoDTO postUserInfo = userToPostUserInfoDTO(post.getUser());
        PostResponseDTO postResponse = new PostResponseDTO(
            post.getId(),
            post.getTitle(),
            post.getCaption(),
            post.getContentUrl(),
            post.getCreatedAt(),
            post.getUpdatedAt(),
            postUserInfo
        );
        return postResponse;
    }


    public void checkPostBelongToUser(Post post) {
        Principal principal = SecurityContextHolder.getContext().getAuthentication();
        Optional<User> user = userRepository.findByEmail(principal.getName());
        System.out.println("USER1: " + user.get().getId());
        System.out.println("USER2: " + post.getUser().getId());
        System.out.println(user.get().getId() == post.getUser().getId());
        if (post.getUser().getId() != user.get().getId()) {
            throw new ResourceAccessDeniedException("Access denied to resource");
        }
    }

    private boolean checkIsAdmin() {
        return SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
            .anyMatch(role -> role.getAuthority().equals("ROLE_ADMIN"));
    }


}
