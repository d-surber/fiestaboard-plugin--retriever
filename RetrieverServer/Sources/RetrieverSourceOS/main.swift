import RetrieverSourceKit

// A source module: a separate signed program that serves one source to the
// server over XPC. This is all a module's entry point needs.
SourceHost.run(OSSource())
