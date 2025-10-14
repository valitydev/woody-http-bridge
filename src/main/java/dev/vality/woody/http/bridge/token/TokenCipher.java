package dev.vality.woody.http.bridge.token;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

@Slf4j
public class TokenCipher {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int MAX_STRING_LENGTH = 0xFFFF;
    private static final int TRACE_ID_HEX_LENGTH = 32;
    private static final int SPAN_ID_HEX_LENGTH = 16;
    private static final int VERSION_HEX_LENGTH = 2;
    private static final int FLAGS_HEX_LENGTH = 2;
    private static final int FLAG_TEXT = 0;
    private static final int FLAG_HEX = 1;
    private static final int FLAG_LONG = 2;
    private static final int STRING_LITERAL_FLAG = 0;
    private static final int URL_PREFIX_HTTPS = 2;
    private static final int URL_PREFIX_HTTP = 3;
    private static final long EPOCH_OFFSET_SECONDS = 1577836800L;
    private static final String HEX_CHARS = "0123456789abcdefABCDEF";
    private static final SecureRandom secureRandom = new SecureRandom();

    public String encrypt(TokenPayload payload, String secretKey) {
        try {
            log.info("encrypt {}", payload);
            var iv = new byte[IV_LENGTH_BYTES];
            secureRandom.nextBytes(iv);

            var cipher = Cipher.getInstance(TRANSFORMATION);
            var keySpec = deriveKey(secretKey);
            var parameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, parameterSpec);

            var cipherBytes = cipher.doFinal(compress(serialize(payload)));
            var result = new byte[iv.length + cipherBytes.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(cipherBytes, 0, result, iv.length, cipherBytes.length);

            return Base64.getUrlEncoder().withoutPadding().encodeToString(result);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to encrypt token", ex);
        }
    }

    public TokenPayload decrypt(String token, String secretKey) {
        try {
            var decoded = Base64.getUrlDecoder().decode(token);
            if (decoded.length <= IV_LENGTH_BYTES) {
                throw new IllegalArgumentException("Invalid token");
            }

            var iv = Arrays.copyOfRange(decoded, 0, IV_LENGTH_BYTES);
            var cipherBytes = Arrays.copyOfRange(decoded, IV_LENGTH_BYTES, decoded.length);

            var cipher = Cipher.getInstance(TRANSFORMATION);
            var keySpec = deriveKey(secretKey);
            var parameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, parameterSpec);

            var plainBytes = decompress(cipher.doFinal(cipherBytes));
            var result = deserialize(plainBytes);
            log.info("decrypted {}", result);
            return result;
        } catch (AEADBadTagException ex) {
            if ("Tag mismatch".equals(ex.getMessage())) {
                throw new IllegalArgumentException("Wrong secret key", ex);
            }
            throw new IllegalArgumentException("Failed to decrypt token", ex);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to decrypt token", ex);
        }
    }

    private byte[] serialize(TokenPayload payload) throws IOException {
        var buffer = new ByteArrayOutputStream();
        try (var data = new DataOutputStream(buffer)) {
            var urlPrefixType = determineUrlPrefixType(payload.termUrl());
            var traceIdType = determineTraceFieldType(payload.traceId(), TRACE_ID_HEX_LENGTH);
            var spanIdType = determineTraceFieldType(payload.spanId(), SPAN_ID_HEX_LENGTH);
            var newSpanIdType = determineTraceFieldType(payload.newSpanId(), SPAN_ID_HEX_LENGTH);

            var packedFlags = packFlags(urlPrefixType, traceIdType, spanIdType, newSpanIdType);
            data.writeByte(packedFlags);

            writeCompactStringData(data, payload.termUrl(), urlPrefixType);

            var timestamp = payload.timestamp();
            var secondsSinceEpoch = timestamp.toEpochSecond(ZoneOffset.UTC);
            var minutesSinceEpoch = (int) ((secondsSinceEpoch - EPOCH_OFFSET_SECONDS) / 60);
            data.writeByte((minutesSinceEpoch >> 16) & 0xFF);
            data.writeByte((minutesSinceEpoch >> 8) & 0xFF);
            data.writeByte(minutesSinceEpoch & 0xFF);

            writeString(data, payload.invoiceFormatPaymentId());
            writeTraceFieldData(data, payload.traceId(), traceIdType, TRACE_ID_HEX_LENGTH);
            writeTraceFieldData(data, payload.spanId(), spanIdType, SPAN_ID_HEX_LENGTH);
            writeTraceFieldData(data, payload.newSpanId(), newSpanIdType, SPAN_ID_HEX_LENGTH);
            writeTraceparent(data, payload.traceparent());
        }
        return buffer.toByteArray();
    }

    private TokenPayload deserialize(byte[] bytes) throws IOException {
        try (DataInputStream data = new DataInputStream(new ByteArrayInputStream(bytes))) {
            var packedFlags = data.readUnsignedByte();
            var urlPrefixType = packedFlags & 0x03;
            var traceIdType = (packedFlags >> 2) & 0x03;
            var spanIdType = (packedFlags >> 4) & 0x03;
            var newSpanIdType = (packedFlags >> 6) & 0x03;

            var termUrl = readCompactStringData(data, urlPrefixType);

            var byte1 = data.readUnsignedByte();
            var byte2 = data.readUnsignedByte();
            var byte3 = data.readUnsignedByte();
            var minutesSinceEpoch = (byte1 << 16) | (byte2 << 8) | byte3;
            var epochSeconds = (minutesSinceEpoch * 60L) + EPOCH_OFFSET_SECONDS;

            var invoiceFormatPaymentId = readString(data);
            var traceId = readTraceFieldData(data, traceIdType, TRACE_ID_HEX_LENGTH);
            var spanId = readTraceFieldData(data, spanIdType, SPAN_ID_HEX_LENGTH);
            var newSpanId = readTraceFieldData(data, newSpanIdType, SPAN_ID_HEX_LENGTH);
            var traceparent = readTraceparent(data);

            return new TokenPayload(
                    termUrl,
                    LocalDateTime.ofEpochSecond(epochSeconds, 0, ZoneOffset.UTC),
                    invoiceFormatPaymentId,
                    traceId,
                    spanId,
                    newSpanId,
                    traceparent
            );
        }
    }

    private void writeString(DataOutputStream output, String value) throws IOException {
        var bytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (bytes.length > MAX_STRING_LENGTH) {
            throw new IllegalArgumentException("String too long for token serialization");
        }
        if (bytes.length < 128) {
            output.writeByte(bytes.length);
        } else {
            output.writeByte(0x80 | (bytes.length >> 8));
            output.writeByte(bytes.length & 0xFF);
        }
        output.write(bytes);
    }

    private String readString(DataInputStream input) throws IOException {
        var firstByte = input.readUnsignedByte();
        var length = ((firstByte & 0x80) != 0) ?
                ((firstByte & 0x7F) << 8) | input.readUnsignedByte() :
                firstByte;
        var bytes = new byte[length];
        input.readFully(bytes);
        return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
    }

    private byte[] compress(byte[] bytes) {
        var deflater = new Deflater(Deflater.BEST_COMPRESSION, true);
        deflater.setInput(bytes);
        deflater.finish();
        var buffer = new ByteArrayOutputStream();
        var chunk = new byte[256];
        while (!deflater.finished()) {
            var count = deflater.deflate(chunk);
            buffer.write(chunk, 0, count);
        }
        deflater.end();
        return buffer.toByteArray();
    }

    private byte[] decompress(byte[] bytes) throws Exception {
        var inflater = new Inflater(true);
        inflater.setInput(bytes);
        var buffer = new ByteArrayOutputStream();
        var chunk = new byte[256];
        while (!inflater.finished()) {
            var count = inflater.inflate(chunk);
            if (count == 0 && inflater.needsInput()) {
                throw new IllegalArgumentException("Failed to decompress token");
            }
            buffer.write(chunk, 0, count);
        }
        inflater.end();
        return buffer.toByteArray();
    }

    private SecretKeySpec deriveKey(String secretKey) throws Exception {
        var keyBytes = MessageDigest.getInstance("SHA-256")
                .digest(secretKey.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    private int packFlags(int urlType, int traceIdType, int spanIdType, int newSpanIdType) {
        return (urlType & 0x03) |
                ((traceIdType & 0x03) << 2) |
                ((spanIdType & 0x03) << 4) |
                ((newSpanIdType & 0x03) << 6);
    }

    private int determineUrlPrefixType(String value) {
        if (value.startsWith("https://")) {
            return URL_PREFIX_HTTPS;
        }
        if (value.startsWith("http://")) {
            return URL_PREFIX_HTTP;
        }
        return STRING_LITERAL_FLAG;
    }

    private int determineTraceFieldType(String value, int expectedHexLength) {
        if (isHex(value, expectedHexLength)) {
            return FLAG_HEX;
        }
        if (isDecimalLong(value)) {
            return FLAG_LONG;
        }
        return FLAG_TEXT;
    }

    private void writeCompactStringData(DataOutputStream output, String value, int urlType) throws IOException {
        switch (urlType) {
            case URL_PREFIX_HTTPS:
                writeString(output, value.substring(8));
                break;
            case URL_PREFIX_HTTP:
                writeString(output, value.substring(7));
                break;
            default:
                writeString(output, value);
        }
    }

    private String readCompactStringData(DataInputStream input, int urlType) throws IOException {
        return switch (urlType) {
            case URL_PREFIX_HTTPS -> "https://" + readString(input);
            case URL_PREFIX_HTTP -> "http://" + readString(input);
            default -> readString(input);
        };
    }

    private void writeTraceFieldData(DataOutputStream output, String value, int fieldType, int expectedHexLength)
            throws IOException {
        switch (fieldType) {
            case FLAG_HEX:
                output.write(hexToBytes(value));
                break;
            case FLAG_LONG:
                output.writeLong(Long.parseLong(value));
                break;
            default:
                writeString(output, value);
        }
    }

    private String readTraceFieldData(DataInputStream input, int fieldType, int expectedHexLength) throws IOException {
        switch (fieldType) {
            case FLAG_HEX: {
                var bytes = new byte[expectedHexLength / 2];
                input.readFully(bytes);
                return bytesToHex(bytes);
            }
            case FLAG_LONG:
                return String.valueOf(input.readLong());
            default:
                return readString(input);
        }
    }

    private void writeTraceparent(DataOutputStream output, String value) throws IOException {
        var parts = value.split("-");
        if (parts.length == 4 &&
                isHex(parts[0], VERSION_HEX_LENGTH) &&
                isHex(parts[1], TRACE_ID_HEX_LENGTH) &&
                isHex(parts[2], SPAN_ID_HEX_LENGTH) &&
                isHex(parts[3], FLAGS_HEX_LENGTH)) {
            output.writeByte(FLAG_HEX);
            output.writeByte(Integer.parseInt(parts[0], 16));
            output.write(hexToBytes(parts[1]));
            output.write(hexToBytes(parts[2]));
            output.writeByte(Integer.parseInt(parts[3], 16));
        } else {
            output.writeByte(FLAG_TEXT);
            writeString(output, value);
        }
    }

    private String readTraceparent(DataInputStream input) throws IOException {
        if (input.readUnsignedByte() == FLAG_HEX) {
            var version = input.readUnsignedByte();
            var traceIdBytes = new byte[TRACE_ID_HEX_LENGTH / 2];
            input.readFully(traceIdBytes);
            var spanIdBytes = new byte[SPAN_ID_HEX_LENGTH / 2];
            input.readFully(spanIdBytes);
            int flags = input.readUnsignedByte();

            return String.format(Locale.ROOT, "%02x-%s-%s-%02x",
                    version, bytesToHex(traceIdBytes), bytesToHex(spanIdBytes), flags);
        }
        return readString(input);
    }

    private boolean isHex(String value, int expectedLength) {
        if (value.length() != expectedLength) {
            return false;
        }
        for (var ch : value.toCharArray()) {
            if (HEX_CHARS.indexOf(ch) == -1) {
                return false;
            }
        }
        return true;
    }

    private boolean isDecimalLong(String value) {
        if (value.isEmpty() || value.length() > 19) {
            return false;
        }
        try {
            Long.parseLong(value);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private byte[] hexToBytes(String hex) {
        var len = hex.length();
        var data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private String bytesToHex(byte[] bytes) {
        var sb = new StringBuilder();
        for (var b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
