package io.snyk.sdk.util;

import javax.annotation.Nonnull;
import java.util.List;

import io.snyk.sdk.model.Issue;
import io.snyk.sdk.model.Severity;

import static io.snyk.sdk.util.Predicates.distinctByKey;
import static java.lang.String.format;

public final class Formatter {

  public static String getIssuesAsFormattedString(@Nonnull List<? extends Issue> issues) {
    long countHighSeverities = issues.stream()
                                     .filter(issue -> issue.severity == Severity.HIGH)
                                     .filter(distinctByKey(issue -> issue.id))
                                     .count();
    long countMediumSeverities = issues.stream()
                                       .filter(issue -> issue.severity == Severity.MEDIUM)
                                       .filter(distinctByKey(issue -> issue.id))
                                       .count();
    long countLowSeverities = issues.stream()
                                    .filter(issue -> issue.severity == Severity.LOW)
                                    .filter(distinctByKey(issue -> issue.id))
                                    .count();

    return format("%d high, %d medium, %d low", countHighSeverities, countMediumSeverities, countLowSeverities);
  }
}
