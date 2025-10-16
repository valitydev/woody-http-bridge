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

/**
 * Performs authenticated encryption and decryption for {@link TokenPayload} values while shaping the payload into a
 * compact binary structure optimised for transmission inside HTTP headers. The cipher uses AES/GCM with a derived key,
 * encodes the payload into a versioned byte layout, compresses it, and then applies Base64 URL encoding. The reverse
 * path validates inputs, restores the byte layout, and rehydrates {@link TokenPayload} instances.
 */
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

    /**
     * Serialises the payload, compresses it and encrypts the result using AES/GCM. The IV is prepended to the cipher
     * text so that callers can transmit a single Base64 string. The provided secret is hashed to 256 bits to match the
     * AES key size and every invocation uses a fresh IV to guarantee semantic security.
     */
    public String encrypt(TokenPayload payload, String secretKey) {
        try {
            log.info("encrypt {}", payload);
            var iv = new byte[IV_LENGTH_BYTES];
            // Random IV per token ensures GCM ciphertexts are non-deterministic even with identical payloads.
            secureRandom.nextBytes(iv);

            var cipher = Cipher.getInstance(TRANSFORMATION);
            var keySpec = deriveKey(secretKey);
            // GCMParameterSpec bundles the IV and authentication tag length passed to the cipher.
            var parameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, parameterSpec);

            var cipherBytes = cipher.doFinal(compress(serialize(payload)));
            var result = new byte[iv.length + cipherBytes.length];
            // We prepend the IV so the decryptor can recover it without out-of-band state.
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(cipherBytes, 0, result, iv.length, cipherBytes.length);

            return Base64.getUrlEncoder().withoutPadding().encodeToString(result);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to encrypt token", ex);
        }
    }

    /**
     * Reverses the {@link #encrypt(TokenPayload, String)} pipeline: decodes the Base64 token, extracts and reuses the
     * IV, decrypts with AES/GCM, decompresses the payload bytes, and deserialises them into a {@link TokenPayload}.
     * Decryption failures caused by an incorrect secret are mapped to a clear {@link IllegalArgumentException}.
     */
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
            // The IV that was prepended during encryption is reused here to satisfy AES/GCM requirements.
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

    /**
     * Packs the domain object into a deterministic byte representation. Bit flags compactly encode which fast-path
     * encodings are used for each field (e.g. URL prefix trimming or hex trace identifiers) so that the decoder can
     * recover the data without emitting redundant metadata. The timestamp is stored as minutes since a fixed epoch to
     * balance resolution and payload size.
     */
    private byte[] serialize(TokenPayload payload) throws IOException {
        var buffer = new ByteArrayOutputStream();
        try (var data = new DataOutputStream(buffer)) {
            var urlPrefixType = determineUrlPrefixType(payload.termUrl());
            var traceIdType = determineTraceFieldType(payload.traceId(), TRACE_ID_HEX_LENGTH);
            var spanIdType = determineTraceFieldType(payload.spanId(), SPAN_ID_HEX_LENGTH);
            var newSpanIdType = determineTraceFieldType(payload.newSpanId(), SPAN_ID_HEX_LENGTH);

            var packedFlags = packFlags(urlPrefixType, traceIdType, spanIdType, newSpanIdType);
            // First byte advertises how subsequent variable-length fields are encoded.
            data.writeByte(packedFlags);

            writeCompactStringData(data, payload.termUrl(), urlPrefixType);

            var timestamp = payload.timestamp();
            var secondsSinceEpoch = timestamp.toEpochSecond(ZoneOffset.UTC);
            // Minutes since offset compresses a 64-bit epoch second into three bytes with minute precision.
            var minutesSinceEpoch = (int) ((secondsSinceEpoch - EPOCH_OFFSET_SECONDS) / 60);
            data.writeByte((minutesSinceEpoch >> 16) & 0xFF);
            data.writeByte((minutesSinceEpoch >> 8) & 0xFF);
            data.writeByte(minutesSinceEpoch & 0xFF);

            writeString(data, payload.invoiceFormatPaymentId());
            writeTraceFieldData(data, payload.traceId(), traceIdType, TRACE_ID_HEX_LENGTH);
            writeTraceFieldData(data, payload.spanId(), spanIdType, SPAN_ID_HEX_LENGTH);
            writeTraceFieldData(data, payload.newSpanId(), newSpanIdType, SPAN_ID_HEX_LENGTH);
            writeTraceparent(data, payload.traceparent());
            writeString(data, payload.tracestate() == null ? "" : payload.tracestate());
        }
        return buffer.toByteArray();
    }

    /**
     * Expands the binary representation emitted by {@link #serialize(TokenPayload)}. The method mirrors the write
     * ordering exactly, reconstructing compacted URLs, trace identifiers, and optional state while converting encoded
     * minutes back into a {@link LocalDateTime} in UTC.
     */
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
            // Reconstruct the 24-bit integer containing the minute delta from the custom epoch.
            var minutesSinceEpoch = (byte1 << 16) | (byte2 << 8) | byte3;
            var epochSeconds = (minutesSinceEpoch * 60L) + EPOCH_OFFSET_SECONDS;

            var invoiceFormatPaymentId = readString(data);
            var traceId = readTraceFieldData(data, traceIdType, TRACE_ID_HEX_LENGTH);
            var spanId = readTraceFieldData(data, spanIdType, SPAN_ID_HEX_LENGTH);
            var newSpanId = readTraceFieldData(data, newSpanIdType, SPAN_ID_HEX_LENGTH);
            var traceparent = readTraceparent(data);
            var tracestateRaw = readString(data);

            return new TokenPayload(
                    termUrl,
                    LocalDateTime.ofEpochSecond(epochSeconds, 0, ZoneOffset.UTC),
                    invoiceFormatPaymentId,
                    traceId,
                    spanId,
                    newSpanId,
                    traceparent,
                    tracestateRaw.isEmpty() ? null : tracestateRaw
            );
        }
    }

    /**
     * Writes a UTF-8 string preceded by a compact length prefix (single byte for short strings, two bytes otherwise)
     * so that the decoder can read variable-length fields without delimiters.
     */
    private void writeString(DataOutputStream output, String value) throws IOException {
        var bytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (bytes.length > MAX_STRING_LENGTH) {
            throw new IllegalArgumentException("String too long for token serialization");
        }
        if (bytes.length < 128) {
            output.writeByte(bytes.length);
        } else {
            // High bit flags the two-byte length encoding to support up to 64KiB UTF-8 payloads.
            output.writeByte(0x80 | (bytes.length >> 8));
            output.writeByte(bytes.length & 0xFF);
        }
        output.write(bytes);
    }

    /**
     * Reads a string produced by {@link #writeString(DataOutputStream, String)} by first restoring its encoded length
     * and then consuming the corresponding byte span.
     */
    private String readString(DataInputStream input) throws IOException {
        var firstByte = input.readUnsignedByte();
        var length = ((firstByte & 0x80) != 0)
                ? (((firstByte & 0x7F) << 8) | input.readUnsignedByte())
                : firstByte;
        var bytes = new byte[length];
        input.readFully(bytes);
        return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * Compresses the serialized payload with the raw (nowrap) DEFLATE format. Compression shrinks repetitive text
     * fields significantly while keeping the operation symmetric with {@link #decompress(byte[])}.
     */
    private byte[] compress(byte[] bytes) {
        var deflater = new Deflater(Deflater.BEST_COMPRESSION, true);
        // 'true' enables raw DEFLATE (no zlib header) so inflater must mirror this setup.
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

    /**
     * Decompresses bytes previously generated by {@link #compress(byte[])}. The method ensures the inflater does not
     * silently loop forever by checking for progress and throws when the input is invalid.
     */
    private byte[] decompress(byte[] bytes) throws Exception {
        var inflater = new Inflater(true);
        // The inflater must be configured with nowrap=true to match the raw DEFLATE produced by compress().
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

    /**
     * Derives a fixed-size AES key from the caller supplied secret by hashing with SHA-256. This approach eliminates
     * the need for callers to manage binary keys while still producing a uniformly distributed key for AES/GCM.
     */
    private SecretKeySpec deriveKey(String secretKey) throws Exception {
        var keyBytes = MessageDigest.getInstance("SHA-256")
                .digest(secretKey.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    /**
     * Packs four two-bit flag values into a single byte. Each pair of bits encodes how a particular field was stored,
     * keeping metadata overhead minimal.
     */
    private int packFlags(int urlType, int traceIdType, int spanIdType, int newSpanIdType) {
        return (urlType & 0x03) |
                ((traceIdType & 0x03) << 2) |
                ((spanIdType & 0x03) << 4) |
                ((newSpanIdType & 0x03) << 6);
    }

    /**
     * Detects whether the URL starts with a known scheme and returns a flag that allows the serializer to omit the
     * repeated prefix while keeping reconstructability on the decode path.
     */
    private int determineUrlPrefixType(String value) {
        if (value.startsWith("https://")) {
            return URL_PREFIX_HTTPS;
        }
        if (value.startsWith("http://")) {
            return URL_PREFIX_HTTP;
        }
        return STRING_LITERAL_FLAG;
    }

    /**
     * Determines the most efficient encoding for trace identifiers: raw hex bytes, parsed long, or plain text when no
     * optimisation applies. The decoder reads the companion flag to choose the matching read path.
     */
    private int determineTraceFieldType(String value, int expectedHexLength) {
        if (isHex(value, expectedHexLength)) {
            return FLAG_HEX;
        }
        if (isDecimalLong(value)) {
            return FLAG_LONG;
        }
        return FLAG_TEXT;
    }

    /**
     * Serialises the URL using the scheme inferred by {@link #determineUrlPrefixType(String)}. For known schemes only
     * the suffix is written to conserve bytes.
     */
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

    /**
     * Restores a URL compressed by {@link #writeCompactStringData(DataOutputStream, String, int)} by reattaching the
     * stripped prefix when necessary.
     */
    private String readCompactStringData(DataInputStream input, int urlType) throws IOException {
        return switch (urlType) {
            case URL_PREFIX_HTTPS -> "https://" + readString(input);
            case URL_PREFIX_HTTP -> "http://" + readString(input);
            default -> readString(input);
        };
    }

    /**
     * Writes trace-related identifiers using the format indicated by the flag: raw bytes for hex, packed long, or the
     * full string for custom formats. This avoids unnecessary expansions for spans and trace IDs.
     */
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

    /**
     * Reads trace identifiers emitted by {@link #writeTraceFieldData(DataOutputStream, String, int, int)} by branching
     * on the stored flag.
     */
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

    /**
     * Optimises the W3C traceparent header by storing its canonical four-part form as binary when the value matches
     * the expected hex structure; otherwise falls back to a raw string.
     */
    private void writeTraceparent(DataOutputStream output, String value) throws IOException {
        var parts = value.split("-");
        if (parts.length == 4
                && isHex(parts[0], VERSION_HEX_LENGTH)
                && isHex(parts[1], TRACE_ID_HEX_LENGTH)
                && isHex(parts[2], SPAN_ID_HEX_LENGTH)
                && isHex(parts[3], FLAGS_HEX_LENGTH)) {
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

    /**
     * Rehydrates a traceparent previously compacted by {@link #writeTraceparent(DataOutputStream, String)}.
     */
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

    /**
     * Validates that a string strictly consists of hexadecimal characters and matches the expected length.
     */
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

    /**
     * Checks whether the supplied value fits within a signed 64-bit integer. Used to decide whether a compact long
     * representation is possible for trace identifiers.
     */
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

    /**
     * Converts a hexadecimal string into a byte array without relying on slower library helpers to keep the hot path
     * allocation friendly.
     */
    private byte[] hexToBytes(String hex) {
        var len = hex.length();
        var data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) +
                    Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Converts bytes to a lower-case hexadecimal string. Used on the decode path for trace identifiers.
     */
    private String bytesToHex(byte[] bytes) {
        var sb = new StringBuilder();
        for (var b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
