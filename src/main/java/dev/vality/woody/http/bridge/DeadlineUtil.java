package dev.vality.woody.http.bridge;

import jakarta.annotation.Nullable;
import lombok.experimental.UtilityClass;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

@UtilityClass
@SuppressWarnings("ParameterName")
public class DeadlineUtil {

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
        return (extractMinutes(xRequestDeadline, xRequestId) + extractSeconds(xRequestDeadline, xRequestId) +
                extractMilliseconds(xRequestDeadline, xRequestId)) > 0;
    }

    public static Long extractMinutes(String xRequestDeadline, String xRequestId) {
        var format = "minutes";

        checkNegativeValues(xRequestDeadline, xRequestId, "([-][0-9]+([.][0-9]+)?(?!ms)[m])", format);

        var minutes = extractValue(xRequestDeadline, "([0-9]+([.][0-9]+)?(?!ms)[m])", xRequestId, format);

        return Optional.ofNullable(minutes).map(min -> min * 60000.0).map(Double::longValue).orElse(0L);
    }

    public static Long extractSeconds(String xRequestDeadline, String xRequestId) {
        var format = "seconds";

        checkNegativeValues(xRequestDeadline, xRequestId, "([-][0-9]+([.][0-9]+)?[s])", format);

        var seconds = extractValue(xRequestDeadline, "([0-9]+([.][0-9]+)?[s])", xRequestId, format);

        return Optional.ofNullable(seconds).map(s -> s * 1000.0).map(Double::longValue).orElse(0L);
    }

    public static Long extractMilliseconds(String xRequestDeadline, String xRequestId) {
        var format = "milliseconds";

        checkNegativeValues(xRequestDeadline, xRequestId, "([-][0-9]+([.][0-9]+)?[m][s])", format);

        var milliseconds = extractValue(xRequestDeadline, "([0-9]+([.][0-9]+)?[m][s])", xRequestId, format);

        if (milliseconds != null && Math.ceil(milliseconds % 1) > 0) {
            throw new IllegalArgumentException(
                    String.format("Deadline 'milliseconds' parameter can have only integer value, xRequestId=%s ",
                            xRequestId));
        }

        return Optional.ofNullable(milliseconds).map(Double::longValue).orElse(0L);
    }

    private static void checkNegativeValues(String xRequestDeadline, String xRequestId, String regex, String format) {
        if (!match(regex, xRequestDeadline).isEmpty()) {
            throw new IllegalArgumentException(
                    String.format("Deadline '%s' parameter has negative value, xRequestId=%s ", format, xRequestId));
        }
    }

    private static Double extractValue(String xRequestDeadline, String formatRegex, String xRequestId, String format) {
        var numberRegex = "([0-9]+([.][0-9]+)?)";

        var doubles = new ArrayList<String>();
        for (String string : match(formatRegex, xRequestDeadline)) {
            doubles.addAll(match(numberRegex, string));
        }
        if (doubles.size() > 1) {
            throw new IllegalArgumentException(
                    String.format("Deadline '%s' parameter has a few relative value, xRequestId=%s ", format,
                            xRequestId));
        }
        if (doubles.isEmpty()) {
            return null;
        }
        return Double.valueOf(doubles.getFirst());
    }

    private static List<String> match(String regex, String data) {
        var pattern = Pattern.compile(regex);
        var matcher = pattern.matcher(data);
        var strings = new ArrayList<String>();
        while (matcher.find()) {
            strings.add(matcher.group());
        }
        return strings;
    }
}
