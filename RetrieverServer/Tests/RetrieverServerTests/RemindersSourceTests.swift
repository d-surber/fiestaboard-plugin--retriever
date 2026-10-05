import Foundation
import Testing
@testable import RetrieverSourceReminders
@testable import RetrieverSourceKit

@Test func remindersPayloadFitsItsSchema() throws {
    let source = RemindersSource()
    let item = RemindersSource.Item(title: "Water plants now please", list: "Home", due: Date(), priority: 0)
    let payload = RemindersSource.Payload(items: [item, item, item, item])
    #expect(payload.count == 4)
    #expect(payload.items.first?.title == "Water plants now please")   // as written: the server does no formatting
    let data = try #require(JSON(encoding: payload))
    #expect(matches(data, source.schema))
    guard case .object(let object) = data, case .array(let items)? = object["items"], let first = items.first,
          case .object(let itemsSchema)? = properties(of: source.schema)["items"], let itemSchema = itemsSchema["items"]
    else {
        Issue.record("payload or schema is not shaped as expected")
        return
    }
    #expect(matches(first, itemSchema))
    #expect(try JSONDecoder().decode(RemindersSource.Payload.self, from: JSONEncoder().encode(source.defaultData)).items.isEmpty)
}

@Test func remindersReportsDataNotAPresentationOfIt() {
    let source = RemindersSource()
    #expect(Set(properties(of: source.schema).keys) == ["count", "items"])
    #expect(source.defaultData == ["count": 0, "items": []])
}

@Test func remindersSourceFitsTheSourceContract() {
    #expect(fitsTheSourceContract(RemindersSource()))
}
