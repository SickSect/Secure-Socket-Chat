package org.ugina.server;
import org.ugina.protocol.ClientMessage;
import org.ugina.protocol.ErrorCode;

import java.io.IOException;

public class ServerHandlerService {
    public static ErrorCode validateSendMessage(ClientMessage msg, ChatRoom room) throws IOException {
        long now = System.currentTimeMillis();
        if (Math.abs(now - msg.timestamp) > 30_000) {
            System.err.println("[ ERROR ] EXPIRED ERROR");
            return ErrorCode.EXPIRED;
        }
        if (!room.checkAndAddNonce(msg.nonce)){
            System.err.println("[ ERROR ] REPLY ATTACK");
            return ErrorCode.REPLAY;
        }
        return null;
    }
}
