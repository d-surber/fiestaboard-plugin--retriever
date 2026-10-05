import Foundation

// Just enough HTTP/1.1 request framing for this server: a request line,
// headers, and a body whose length is given by Content-Length. A request may
// arrive in more than one segment, so `parse` is called on everything
// received so far until it stops answering `.incomplete`.
enum HTTPRequest: Equatable {
    case incomplete                          // not all here yet
    case complete(line: String, body: Data)
    case invalid                             // can never become a request this server accepts

    static let maxBytes = 16384              // headers and body together

    static func parse(_ buffer: Data) -> HTTPRequest {
        guard let headEnd = buffer.range(of: Data("\r\n\r\n".utf8)) else {
            return buffer.count > maxBytes ? .invalid : .incomplete
        }
        let lines = String(decoding: buffer[..<headEnd.lowerBound], as: UTF8.self).components(separatedBy: "\r\n")
        var length = 0
        for header in lines.dropFirst() {
            let parts = header.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            switch parts[0].lowercased() {
            case "content-length":
                let value = parts[1].trimmingCharacters(in: .whitespaces)
                guard !value.isEmpty, value.allSatisfy(\.isASCIIDigit), let declared = Int(value) else { return .invalid }
                length = declared
            case "transfer-encoding":
                return .invalid   // chunked bodies are not supported
            default:
                break
            }
        }
        let body = buffer[headEnd.upperBound...]
        guard buffer.count - body.count + length <= maxBytes else { return .invalid }
        guard body.count >= length else { return .incomplete }
        return .complete(line: lines[0], body: Data(body.prefix(length)))
    }
}

private extension Character {
    var isASCIIDigit: Bool { isASCII && isNumber }
}
