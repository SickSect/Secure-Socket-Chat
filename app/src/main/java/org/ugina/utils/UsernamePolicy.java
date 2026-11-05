package org.ugina.utils;

/**
 * Single place that defines which usernames are acceptable. Keeping the rule
 * here means the REST API and the chat protocol cannot drift apart.
 */
public final class UsernamePolicy {

    public static final int MAX_LENGTH = 32;

    private UsernamePolicy() {
    }

    public static boolean isValid(String username) {
        if (username == null) {
            return false;
        }
        int length = username.length();
        if (length < 1 || length > MAX_LENGTH) {
            return false;
        }
        for (int i = 0; i < length; i++) {
            char c = username.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '_';
            if (!allowed) {
                return false;
            }
        }
        return true;
    }
}
