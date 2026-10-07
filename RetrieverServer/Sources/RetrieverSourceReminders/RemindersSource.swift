import EventKit
import Foundation
import RetrieverSourceKit

/// Incomplete reminders due today, from the Reminders app.
final class RemindersSource: Source {
    /// One reminder.
    struct Item: Codable {
        let title: String
        let list: String
        let due: Date?
        let priority: Int
    }

    // Top-level object rather than a bare array: many JSON-path consumers expect one.
    struct Payload: Codable {
        let count: Int
        let items: [Item]

        init(items: [Item]) {
            self.count = items.count
            self.items = items
        }
    }

    let name = "reminders"

    /// The shape of `Payload`.
    let schema: JSON = [
        "type": "object",
        "properties": [
            "count": ["type": "integer"],
            "items": [
                "type": "array",
                "items": [
                    "type": "object",
                    "properties": [
                        "title": ["type": "string"],
                        "list": ["type": "string"],
                        "due": ["type": "string", "format": "date-time"],
                        "priority": ["type": "integer"],
                    ],
                ],
            ],
        ],
        "default": ["count": 0, "items": []],
    ]

    private let store = EKEventStore()

    func fetch(parameters: SourceParameters, _ done: @escaping (Entry) -> Void) {
        // Asks the user the first time; answers at once after that.
        store.requestFullAccessToReminders { granted, error in
            guard granted else {
                log("Reminders access denied: \(error?.localizedDescription ?? "no error given")")
                return done(self.failed("Reminders access denied"))
            }
            self.read(done)
        }
    }

    /// Reads the reminders, access having been granted.
    private func read(_ done: @escaping (Entry) -> Void) {
        let calendar = Calendar.current
        store.refreshSourcesIfNecessary()
        // Fetch incomplete incomplete reminders and filter locally: EventKit's date-range
        // predicate can miss date-only ("incomplete-day") reminders. A repeating reminder
        // is one EKReminder whose due date is its next incomplete occurrence.
        let allIncomplete = store.predicateForIncompleteReminders(withDueDateStarting: nil, ending: nil, calendars: nil)
        store.fetchReminders(matching: allIncomplete) { reminders in
            guard let incomplete = reminders else {
                log("Reminders could not be read")
                return done(self.failed("Reminders could not be read"))
            }
            let items = incomplete.compactMap { reminder -> Item? in
                guard let dueComponents = reminder.dueDateComponents,
                      let due = calendar.date(from: dueComponents),
                      calendar.isDateInToday(due) else { return nil }
                return Item(title: reminder.title ?? "", list: reminder.calendar.title, due: due, priority: reminder.priority)
            }
            log(.debug, "Fetched \(incomplete.count) incomplete, \(items.count) due today")
            done(self.succeeded(Payload(items: items.sorted { ($0.due ?? .distantFuture) < ($1.due ?? .distantFuture) })))
        }
    }
}
