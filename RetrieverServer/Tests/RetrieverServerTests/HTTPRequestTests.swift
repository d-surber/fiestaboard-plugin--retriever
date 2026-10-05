import Foundation
import Testing
@testable import RetrieverServer
@testable import RetrieverSourceKit

private let body = Data([0x00, 0xff, 0x0d, 0x0a, 0x0d, 0x0a, 0x7f, 0x80])   // binary, with a blank line in it

private func post(_ headers: String = "Content-Length: 8", body: Data = body) -> Data {
    Data("POST /retrieve HTTP/1.1\r\nHost: example\r\n\(headers)\r\n\r\n".utf8) + body
}

@Test func parsesARequestWithABody() {
    #expect(HTTPRequest.parse(post()) == .complete(line: "POST /retrieve HTTP/1.1", body: body))
}

@Test func parsesARequestWithoutABody() {
    let request = Data("GET /retrieve HTTP/1.1\r\nHost: example\r\n\r\n".utf8)
    #expect(HTTPRequest.parse(request) == .complete(line: "GET /retrieve HTTP/1.1", body: Data()))
}

@Test func isIncompleteAtEverySplitPoint() {
    let request = post()
    for count in 0..<request.count {
        #expect(HTTPRequest.parse(request.prefix(count)) == .incomplete, "after \(count) bytes")
    }
}

@Test func parsesABufferBuiltUpSegmentBySegment() {
    let request = post()
    for split in 1..<request.count {
        let buffer = Data(request.prefix(split)) + request.suffix(from: split)
        #expect(HTTPRequest.parse(buffer) == .complete(line: "POST /retrieve HTTP/1.1", body: body), "split at \(split)")
    }
}

@Test func parsesASliceThatDoesNotStartAtZero() {
    let padded = Data("xxxx".utf8) + post()
    #expect(HTTPRequest.parse(padded.dropFirst(4)) == .complete(line: "POST /retrieve HTTP/1.1", body: body))
}

@Test(arguments: ["content-length: 8", "CONTENT-LENGTH:8", "Content-Length:   8  "])
func readsContentLengthHoweverItIsWritten(header: String) {
    #expect(HTTPRequest.parse(post(header)) == .complete(line: "POST /retrieve HTTP/1.1", body: body))
}

@Test func ignoresBytesBeyondTheDeclaredLength() {
    let request = post(body: body + Data("extra".utf8))
    #expect(HTTPRequest.parse(request) == .complete(line: "POST /retrieve HTTP/1.1", body: body))
}

@Test(arguments: ["Content-Length: abc", "Content-Length: -1", "Content-Length:", "Content-Length: 8 8", "Content-Length: +8"])
func refusesAMalformedContentLength(header: String) {
    #expect(HTTPRequest.parse(post(header)) == .invalid)
}

@Test func refusesChunkedBodies() {
    #expect(HTTPRequest.parse(post("Transfer-Encoding: chunked")) == .invalid)
}

@Test func refusesADeclaredLengthThatIsTooLarge() {
    #expect(HTTPRequest.parse(post("Content-Length: \(HTTPRequest.maxBytes)", body: Data())) == .invalid)
    #expect(HTTPRequest.parse(post("Content-Length: 99999999999999999999", body: Data())) == .invalid)
}

@Test func acceptsARequestOfExactlyTheMaximumSize() {
    let head = post("Content-Length: 00000", body: Data())   // as many digits as the real length
    let length = HTTPRequest.maxBytes - head.count
    let request = post("Content-Length: \(length)", body: Data(repeating: 1, count: length))
    #expect(request.count == HTTPRequest.maxBytes)
    #expect(HTTPRequest.parse(request) == .complete(line: "POST /retrieve HTTP/1.1", body: Data(repeating: 1, count: length)))
}

@Test func refusesHeadersThatNeverEnd() {
    let endless = Data("POST /retrieve HTTP/1.1\r\n".utf8) + Data(repeating: 0x41, count: HTTPRequest.maxBytes)
    #expect(HTTPRequest.parse(endless) == .invalid)
    #expect(HTTPRequest.parse(endless.prefix(HTTPRequest.maxBytes)) == .incomplete)
}
