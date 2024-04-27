package com.avensys.SocialMediaWebApplication.bootstrap;

import com.avensys.SocialMediaWebApplication.post.Post;
import com.avensys.SocialMediaWebApplication.post.PostRepository;
import com.avensys.SocialMediaWebApplication.role.Role;
import com.avensys.SocialMediaWebApplication.role.RoleRepository;
import com.avensys.SocialMediaWebApplication.user.User;
import com.avensys.SocialMediaWebApplication.user.UserRepository;
import com.github.javafaker.Faker;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@Component
public class SocialMediaAppCommandLineRunner implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PostRepository postRepository;
    private final PasswordEncoder bcryptPasswordEncoder;
    private final RoleRepository roleRepository;

    public SocialMediaAppCommandLineRunner(UserRepository userRepository, PostRepository postRepository, PasswordEncoder bcryptPasswordEncoder, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.postRepository = postRepository;
        this.bcryptPasswordEncoder = bcryptPasswordEncoder;
        this.roleRepository = roleRepository;
    }

    @Override
    public void run(String... args) throws Exception {
        seedDataToDb( 100, 1);
    }

    private void seedDataToDb(int noOfUser, int noOfPost) {
        Faker faker = new Faker();
        Random random = new Random();
        String genderArray[] = {"male", "female"};

        // get user role
        Role userRole = roleRepository.findRolesByName("ROLE_USER");

        // Generate user array
        List<User> users = new ArrayList<>();
        for (int j = 0; j < noOfUser; j++) {
            String password = bcryptPasswordEncoder.encode("password");
            String firstName = faker.name().firstName(); // Emory
            String lastName = faker.name().lastName(); // Barton
            String email = firstName + lastName + "@gmail.com";
            String gender = genderArray[new Random().nextInt(genderArray.length)];
            String avatarUrl = "https://i.pravatar.cc/150?img=" + random.nextInt(50);

            User user = new User();
            user.setFirstName(firstName);
            user.setLastName(lastName);
            user.setEmail(email);
            user.setGender(gender);
            user.setPassword(password);
            user.setAvatarUrl(avatarUrl);
            user.addRole(userRole);

            List<Post> posts = new ArrayList<>();
            for (int i = 0; i < noOfPost; i++) {
                String postTitle = faker.book().title();
                String postContent = faker.lorem().paragraph();
                String postImageUrl = faker.avatar().image();

                Post post = new Post();
                post.setTitle(postTitle);
                post.setCaption(postContent);
                post.setContentUrl("https://picsum.photos/650/400?random=" + random.nextInt(100));

                posts.add(post);
                user.addPost(post);
            }
            users.add(user);
        }
        userRepository.saveAll(users);
    }


}
