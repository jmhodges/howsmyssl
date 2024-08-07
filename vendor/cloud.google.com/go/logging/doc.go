// Copyright 2016 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package logging contains a Cloud Logging client suitable for writing logs.
For reading logs, and working with sinks, metrics and monitored resources,
see package cloud.google.com/go/logging/logadmin.

This client uses Logging API v2.
See https://cloud.google.com/logging/docs/api/v2/ for an introduction to the API.

# Creating a Client

Use a Client to interact with the Cloud Logging API.

	// Create a Client
	ctx := context.Background()
	client, err := logging.NewClient(ctx, "my-project")
	if err != nil {
		// TODO: Handle error.
	}

# Basic Usage

For most use cases, you'll want to add log entries to a buffer to be periodically
flushed (automatically and asynchronously) to the Cloud Logging service.

	// Initialize a logger
	lg := client.Logger("my-log")

	// Add entry to log buffer
	lg.Log(logging.Entry{Payload: "something happened!"})

# Closing your Client

You should call Client.Close before your program exits to flush any buffered log entries to the Cloud Logging service.

	// Close the client when finished.
	err = client.Close()
	if err != nil {
		// TODO: Handle error.
	}

# Synchronous Logging

For critical errors, you may want to send your log entries immediately.
LogSync is slow and will block until the log entry has been sent, so it is
not recommended for normal use.

	err = lg.LogSync(ctx, logging.Entry{Payload: "ALERT! Something critical happened!"})
	if err != nil {
		// TODO: Handle error.
	}

# Redirecting log ingestion

For cases when runtime environment supports out-of-process log ingestion,
like logging agent, you can opt-in to write log entries to io.Writer instead of
ingesting them to Cloud Logging service. Usually, you will use os.Stdout or os.Stderr as
writers because Google Cloud logging agents are configured to capture logs from standard output.
The entries will be Jsonified and wrote as one line strings following the structured logging format.
See https://cloud.google.com/logging/docs/structured-logging#special-payload-fields for the format description.
To instruct Logger to redirect log entries add RedirectAsJSON() LoggerOption`s.

	// Create a logger to print structured logs formatted as a single line Json to stdout
	loggger := client.Logger("test-log", RedirectAsJSON(os.Stdout))

# Payloads

An entry payload can be a string, as in the examples above. It can also be any value
that can be marshaled to a JSON object, like a map[string]interface{} or a struct:

	type MyEntry struct {
		Name  string
		Count int
	}
	lg.Log(logging.Entry{Payload: MyEntry{Name: "Bob", Count: 3}})

If you have a []byte of JSON, wrap it in json.RawMessage:

	j := []byte(`{"Name": "Bob", "Count": 3}`)
	lg.Log(logging.Entry{Payload: json.RawMessage(j)})

If you have proto.Message and want to send it as a protobuf payload, marshal it to anypb.Any:

		// import
	    func logMessage (m proto.Message) {
			var payload anypb.Any
			err := anypb.MarshalFrom(&payload, m)
			if err != nil {
				lg.Log(logging.Entry{Payload: payload})
			}
		}

# The Standard Logger

You may want use a standard log.Logger in your program.

	// stdlg is an instance of *log.Logger.
	stdlg := lg.StandardLogger(logging.Info)
	stdlg.Println("some info")

# Log Levels

An Entry may have one of a number of severity levels associated with it.

	logging.Entry{
		Payload: "something terrible happened!",
		Severity: logging.Critical,
	}

# Viewing Logs

You can view Cloud logs for projects at
https://console.cloud.google.com/logs/viewer. Use the dropdown at the top left. When
running from a Google Cloud Platform VM, select "GCE VM Instance". Otherwise, select
"Google Project" and then the project ID. Logs for organizations, folders and billing
accounts can be viewed on the command line with the "gcloud logging read" command.

# Grouping Logs by Request

To group all the log entries written during a single HTTP request, create two
Loggers, a "parent" and a "child," with different log IDs. Both should be in the same
project, and have the same MonitoredResource type and labels.

  - Parent entries must have HTTPRequest.Request (strictly speaking, only Method and URL are necessary),
    and HTTPRequest.Status populated.

- A child entry's timestamp must be within the time interval covered by the parent request. (i.e., before
the parent.Timestamp and after the parent.Timestamp - parent.HTTPRequest.Latency. This assumes the
parent.Timestamp marks the end of the request.)

- The trace field must be populated in all of the entries and match exactly.

You should observe the child log entries grouped under the parent on the console. The
parent entry will not inherit the severity of its children; you must update the
parent severity yourself.

# Automatic Trace/Span ID Extraction

You can automatically populate the Trace, SpanID, and TraceSampled fields of an Entry object by providing an [http.Request] object
within the Entry's HTTPRequest field:

	logging.Entry{
		HTTPRequest: &logging.HTTPRequest{
			Request: // Reference to your http.Request here
		}
	}

When Entry with an [http.Request] is logged, its Trace, SpanID, and TraceSampled fields may be automatically populated as follows:

 1. If you are instrumenting your application with [OpenTelemetry], more specifically [otelhttp],
    the Entry's Trace, SpanID, and TraceSampled will be populated with information from the [http.Request]'s span context.
 2. Trace, SpanID, and TraceSampled fields will be populated from information from the http.Request's [W3C Traceparent]
    or [X-Cloud-Trace-Context] headers, if those headers exist.

Note that if Trace, SpanID, or TraceSampled are explicitly provided within an Entry object, then those values take precedence over values automatically
extracted values.

[http.Request]: https://pkg.go.dev/net/http#Request
[OpenTelemetry]: https://opentelemetry.io/docs/languages/go/
[otelhttp]: https://pkg.go.dev/go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp
[W3C Traceparent]: https://www.w3.org/TR/trace-context
[X-Cloud-Trace-Context]: https://cloud.google.com/trace/docs/trace-context#legacy-http-header

[OpenTelemetry span context]: https://pkg.go.dev/go.opentelemetry.io/otel/trace#SpanContext
*/
package logging // import "cloud.google.com/go/logging"
