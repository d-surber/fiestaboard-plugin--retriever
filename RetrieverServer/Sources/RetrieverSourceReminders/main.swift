import RetrieverSourceKit

// A source module: a separate signed program that serves one source to the
// server over XPC. The permission this source needs is asked of, and
// granted to, this program alone.
SourceHost.run(RemindersSource())
