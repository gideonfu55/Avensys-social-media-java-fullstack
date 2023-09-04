package com.avensys.SocialMediaWebApplication.exceptions;

public class DuplicateResourceException extends GlobalException {

    public DuplicateResourceException(String message) {
        super(message);
    }

    public DuplicateResourceException(String message, boolean includeStackTrace) {
        super(message, includeStackTrace);
    }
}
