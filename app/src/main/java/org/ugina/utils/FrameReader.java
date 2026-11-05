package org.ugina.utils;

import java.io.IOException;
import java.io.Reader;

/**
 * Reads a newline-delimited frame without allowing an attacker to exhaust
 * memory with an unbounded line. Both the TCP server and the client use it.
 */
public final class FrameReader {

    private FrameReader() {
    }

    /**
     * @return the frame without the trailing newline, or {@code null} on EOF
     *         before any character was read
     */
    public static String readLine(Reader reader, int maxChars) throws IOException {
        StringBuilder line = new StringBuilder();
        int read;
        while ((read = reader.read()) != -1) {
            char c = (char) read;
            if (c == '\n') {
                return line.toString();
            }
            if (c == '\r') {
                continue;
            }
            if (line.length() >= maxChars) {
                throw new IOException("Frame exceeds maximum length of " + maxChars + " characters");
            }
            line.append(c);
        }
        if (line.length() == 0) {
            return null;
        }
        return line.toString();
    }
}
