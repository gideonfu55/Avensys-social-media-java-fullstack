# Social Media Platform

This project aims to create a social media platform using Java, Spring, and Angular/ReactJs. The platform allows users to view and create posts with various types of content, including hyperlinks and media (videos), along with captions. Users can sign up, log in, and manage their own posts. An admin role is available to manage the platform, including maintaining posts and users.

## My Role in Project

Designing and implementing the following pages – user login, registration, post management, and user profile management.

## Features

1. **Feeds Page**: Users can view the contents of posts on the feeds page. All users see the same posts.

2. **User Feed Page**: User can visit his own profile page where he can view all his own post. 

3. **Post Content**: Each post can contain either a hyperlink or media (image or video) along with a caption.

4. **User Authentication**: Users are required to log in to view and create posts. The platform provides a sign-up page for account creation and login page for users to login.

5. **Post Creation**: Users can create posts from the all feeds page and user feed page.

6. **Post Updates and Delete**: Only the user who created a post can update it. As a user viewing his own profile page, he can update and delete his own posts. In his own profile page, he can also edit his own profile.

7. **Admin Role**: An admin role is available to manage the platform. Admins can maintain posts (delete/update any posts) and maintain users (delete/update). A user can also chnage the role of other users.

8. ## Additional Features
   - Main search function in the navbar for users to search and view others profile
   - Admin manage post and user profile table has pagination function which allow users to change size of each page
   - Admin filter function to filter posts by content and filter user profiles based on first name, last name and email.
   - Allow user to preview image and video when creating post before uploading to database

## Technical Considerations

- **Entity Design**: Entities should be well-designed and include audit fields such as "created by" and "created date." 

- **API Security**: APIs should be secured to allow access only to logged-in users, ensuring the privacy and security of the platform.

- **Input Validations**: The platform should include input validations, and appropriate error messages should be displayed to users when validation fails.

- **Component Design**: The design of the Angular/React frontend should use small, reusable components to cater to the requirements. Different components should be used to display different types of media.

- **Post Types**: Consider implementing three types of posts to handle hyperlinks, images, and videos. The fields "link" and "media" should be optional depending on the post type.

- **Media Management**: When deleting a post, the associated media should also be deleted to maintain data consistency.

## Installation and Setup

To set up the social media platform, follow these steps:

1. Clone the repository to your local machine.

2. Install the necessary dependencies for the backend and frontend components.

3. Configure the database connection and other server settings in the backend.

4. Set up the frontend by configuring API endpoints and any additional settings.

5. Build the project to compile the source code and generate the required files.

6. Deploy the application to a suitable hosting environment or run it locally for development and testing purposes.

For detailed installation and setup instructions specific to your chosen technologies, please refer to the project's documentation.

## Usage

Once the social media platform is set up, follow these steps to use the application:

1. Access the platform through a web browser.

2. Log in using your credentials or create a new account using the provided sign-up page.

3. Explore the feeds page to view the posts and their contents.

4. Click on a post to open the associated link or play the video.

5. Create your own posts that will appear on the feeds page.

6. If you have the admin role, you can manage posts and users, including deleting or updating them.
