/**
 * @name Log entries created from user input, outside log/slog
 * @description Building log entries from user-controlled sources is vulnerable to
 *              insertion of forged log entries by a malicious user. This is
 *              go/log-injection, less the calls into log/slog.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision medium
 * @id howsmyssl/go/log-injection-outside-slog
 * @tags security
 *       external/cwe/cwe-117
 */

// This replaces the stock go/log-injection query, which codeql-config.yml
// turns off. It is the same query except that it doesn't count calls into
// log/slog as sinks.
//
// The only slog handlers howsmyssl hands its loggers outside of tests are
// slog.NewTextHandler and slog.NewJSONHandler, and those quote and escape
// every value they write, so a newline or carriage return in a client's value
// can't start a new log line. The stock query doesn't model the handler and
// flags every slog call with a client's value in it. (The stock query also
// can't be taught this with a data extension: go/log-injection doesn't read
// barrierModel rows.)
//
// If you add a hand-written slog.Handler that writes values out as-is, this
// query will not see it. Escape in that handler, or take this file and its
// lines in codeql-config.yml back out.
import go
import semmle.go.security.LogInjection

/** Holds if `sink` is a value given to a function or method of log/slog. */
predicate isSlogArgument(DataFlow::Node sink) {
  exists(LoggerCall call |
    sink = call.getAValueFormattedMessageComponent() and
    call.(DataFlow::CallNode).getTarget().getPackage().getPath() = "log/slog"
  )
}

module OutsideSlogConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof LogInjection::Source }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof LogInjection::Sink and not isSlogArgument(sink)
  }

  predicate isBarrier(DataFlow::Node node) { node instanceof LogInjection::Sanitizer }
}

module OutsideSlogFlow = TaintTracking::Global<OutsideSlogConfig>;

import OutsideSlogFlow::PathGraph

from OutsideSlogFlow::PathNode source, OutsideSlogFlow::PathNode sink
where OutsideSlogFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This log entry depends on a $@.", source.getNode(),
  "user-provided value"
