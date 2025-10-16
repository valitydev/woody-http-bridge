package dev.vality.woody.http.bridge.exceptions;

public class WoodyHttpBridgeException extends RuntimeException {

    public WoodyHttpBridgeException(String message) {
        super(message);
    }

    public WoodyHttpBridgeException(String message, Throwable cause) {
        super(message, cause);
    }
}
