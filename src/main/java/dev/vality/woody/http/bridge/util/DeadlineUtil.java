package dev.vality.woody.http.bridge.util;

import jakarta.annotation.Nullable;
import lombok.experimental.UtilityClass;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@UtilityClass
@SuppressWarnings("ParameterName")
public class DeadlineUtil {

    private static final Pattern MINUTES_PATTERN = Pattern.compile("([-]?[0-9]+(?:\\.[0-9]+)?m(?!s))");
    private static final Pattern SECONDS_PATTERN = Pattern.compile("([-]?[0-9]+(?:\\.[0-9]+)?s)");
    private static final Pattern MILLISECONDS_PATTERN = Pattern.compile("([-]?[0-9]+(?:\\.[0-9]+)?ms)");
    private static final Pattern NUMBER_PATTERN = Pattern.compile("[-]?[0-9]+(?:\\.[0-9]+)?");

    public static void checkDeadline(@Nullable String xRequestDeadline, String xRequestId) {
        if (xRequestDeadline == null) {
            return;
        }
        if (containsRelativeValues(xRequestDeadline, xRequestId)) {
            return;
        }
        Instant instant = Instant.parse(xRequestDeadline);
        if (Instant.now().isAfter(instant)) {
            throw new IllegalArgumentException(String.format("Deadline has expired, xRequestId=%s ", xRequestId));
        }
    }

    public static boolean containsRelativeValues(String xRequestDeadline, String xRequestId) {
        return extractMinutesAsMillis(xRequestDeadline, xRequestId) +
                extractSecondsAsMillis(xRequestDeadline, xRequestId) +
                extractMillisecondsAsMillis(xRequestDeadline, xRequestId) > 0;
    }

    public static Long extractMinutesAsMillis(String xRequestDeadline, String xRequestId) {
        var format = "minutes";

        var number = extractSingleNumber(xRequestDeadline, MINUTES_PATTERN, xRequestId, format);

        if (number == null) {
            return 0L;
        }

        var minutes = Double.parseDouble(number);
        if (minutes < 0) {
            throw new IllegalArgumentException(
                    String.format("Deadline '%s' parameter has negative value, xRequestId=%s ", format, xRequestId));
        }

        return Double.valueOf(minutes * 60000.0).longValue();
    }

    public static Long extractSecondsAsMillis(String xRequestDeadline, String xRequestId) {
        var format = "seconds";

        var number = extractSingleNumber(xRequestDeadline, SECONDS_PATTERN, xRequestId, format);

        if (number == null) {
            return 0L;
        }

        var seconds = Double.parseDouble(number);
        if (seconds < 0) {
            throw new IllegalArgumentException(
                    String.format("Deadline '%s' parameter has negative value, xRequestId=%s ", format, xRequestId));
        }

        return Double.valueOf(seconds * 1000.0).longValue();
    }

    public static Long extractMillisecondsAsMillis(String xRequestDeadline, String xRequestId) {
        var format = "milliseconds";

        var number = extractSingleNumber(xRequestDeadline, MILLISECONDS_PATTERN, xRequestId, format);

        if (number == null) {
            return 0L;
        }

        if (number.contains(".")) {
            throw new IllegalArgumentException(
                    String.format("Deadline 'milliseconds' parameter can have only integer value, xRequestId=%s ",
                            xRequestId));
        }

        var milliseconds = Double.parseDouble(number);
        if (milliseconds < 0) {
            throw new IllegalArgumentException(
                    String.format("Deadline '%s' parameter has negative value, xRequestId=%s ", format, xRequestId));
        }

        return Double.valueOf(milliseconds).longValue();
    }

    private static String extractSingleNumber(String xRequestDeadline,
                                              Pattern formatPattern,
                                              String xRequestId,
                                              String format) {
        var doubles = new ArrayList<String>();
        for (String string : match(formatPattern, xRequestDeadline)) {
            doubles.addAll(match(NUMBER_PATTERN, string));
        }
        if (doubles.size() > 1) {
            throw new IllegalArgumentException(
                    String.format("Deadline '%s' parameter has a few relative value, xRequestId=%s ", format,
                            xRequestId));
        }
        return doubles.isEmpty() ? null : doubles.getFirst();
    }

    private static List<String> match(Pattern pattern, String data) {
        var matcher = pattern.matcher(data);
        var strings = new ArrayList<String>();
        while (matcher.find()) {
            strings.add(matcher.group());
        }
        return strings;
    }
}
