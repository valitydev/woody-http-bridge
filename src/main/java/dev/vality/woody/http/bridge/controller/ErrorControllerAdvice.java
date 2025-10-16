package dev.vality.woody.http.bridge.controller;

import dev.vality.woody.http.bridge.exceptions.WoodyHttpBridgeException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class ErrorControllerAdvice {

    @ExceptionHandler({WoodyHttpBridgeException.class})
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public void handleWoodyHttpBridgeException(WoodyHttpBridgeException e) {
        log.error("<- Res [500]: Unrecognized inner error", e);
    }
}
