package org.ugina.client;

public interface TokenRefresher {
    /**
     * @return a new access token (JWT), or null if refresh failed and full login is needed
     */
    String refresh() throws Exception;
}
