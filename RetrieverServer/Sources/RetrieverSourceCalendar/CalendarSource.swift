import EventKit
import Foundation
import RetrieverSourceKit

/// Today's events and tomorrow's, from the Calendar app, with the reminders
/// due on each day, from the Reminders app.
///
/// Which calendars and reminder lists is a parameter. Each is named as its
/// app shows it, and the name stands for every calendar and list so called,
/// whichever account it is in. Two names are kept for the whole of each:
/// `_Calendars_` and `_Reminders_`.
///
/// A reminder is an incomplete one, due that day; today's include those
/// overdue. It is given as an event that starts and ends when it is due,
/// all day if it is due on a date with no time.
///
/// A request may also leave out today's events that started some while ago,
/// so that a board shows what is on now and next and not what is over.
final class CalendarSource: Source {
    /// What an event is: an event in a calendar, or a reminder in a list.
    enum Kind: String, Codable {
        case event, reminder
    }

    /// One event or reminder. Times are moments, not text laid out for a display.
    struct Event: Codable, Equatable {
        let title: String
        /// The calendar's name, or the reminder list's.
        let calendar: String
        let start: Date
        let end: Date
        let all_day: Bool
        let location: String
        let kind: Kind
        /// A reminder's priority as Reminders keeps it: 0 none, 1 high to 9 low. 0 for an event.
        let priority: Int

        init(title: String, calendar: String, start: Date, end: Date, all_day: Bool, location: String, kind: Kind = .event, priority: Int = 0) {
            self.title = title
            self.calendar = calendar
            self.start = start
            self.end = end
            self.all_day = all_day
            self.location = location
            self.kind = kind
            self.priority = priority
        }
    }

    /// One day's events.
    struct Day: Codable, Equatable {
        /// The day, as its date in this Mac's time zone: "2026-10-08".
        let date: String
        let count: Int
        let events: [Event]

        init(date: String, events: [Event]) {
            self.date = date
            self.count = events.count
            self.events = events
        }
    }

    struct Payload: Codable, Equatable {
        let today: Day
        let tomorrow: Day
    }

    let name = "calendar"

    /// The shape of `Day`.
    static let daySchema: JSON = [
        "type": "object",
        "properties": [
            "date": ["type": "string", "format": "date"],
            "count": ["type": "integer"],
            "events": [
                "type": "array",
                "items": [
                    "type": "object",
                    "properties": [
                        "title": ["type": "string"],
                        "calendar": ["type": "string"],
                        "start": ["type": "string", "format": "date-time"],
                        "end": ["type": "string", "format": "date-time"],
                        "all_day": ["type": "boolean"],
                        "location": ["type": "string"],
                        "kind": ["type": "string", "enum": ["event", "reminder"]],
                        "priority": ["type": "integer"],
                    ],
                ],
            ],
        ],
        "default": ["date": "", "count": 0, "events": []],
    ]

    /// The shape of `Payload`.
    let schema: JSON = [
        "type": "object",
        "properties": ["today": daySchema, "tomorrow": daySchema],
        "default": [
            "today": ["date": "", "count": 0, "events": []],
            "tomorrow": ["date": "", "count": 0, "events": []],
        ],
    ]

    let parametersSchema: JSON = [
        "type": "object",
        "properties": [
            "calendars": [
                "type": "string", "requestOnly": true,
                "description": "Only these calendars and reminder lists, by the names the Calendar and Reminders apps show, separated by commas. _Calendars_ is every calendar and _Reminders_ every reminder list. Left out, both.",
            ],
            "started_after": [
                "type": "string", "format": "date-time", "requestOnly": true,
                "description": "Leave out today's events that started before this moment, written with its offset from UTC, as 2026-11-13T09:15:00-08:00; all-day events stay, and so do reminders and tomorrow's events. In the plugin's request body, an hour ago is {{= DATEADD(NOW(), -1, \"hours\") }}.",
            ],
        ],
    ]

    /// Which calendars and reminder lists are wanted, each by name.
    enum Wanted: Equatable {
        case every
        case only([String])
    }

    /// The name that stands for every calendar.
    static let everyCalendar = "_Calendars_"
    /// The name that stands for every reminder list.
    static let everyReminderList = "_Reminders_"

    /// Some of one kind of list, calendars or reminder lists.
    enum Lists<Item> {
        case every
        case these([Item])

        /// The lists, or nil for every one, as EventKit takes them.
        var items: [Item]? {
            if case .these(let items) = self { return items }
            return nil
        }

        /// Whether any list at all is wanted.
        var any: Bool { items.map { !$0.isEmpty } ?? true }
    }

    /// The calendars and reminder lists a choice comes to, or the names it
    /// gives that no calendar or list has.
    enum Chosen<Item> {
        case lists(calendars: Lists<Item>, reminderLists: Lists<Item>)
        case missing([String])
    }

    /// What one fetch is asked for.
    struct Asked: Equatable {
        let wanted: Wanted
        /// The moment before which a timed event today that started is left out; nil to leave none out.
        let startedAfter: Date?
    }

    /// What a set of parameters asks for, with the defaults for what it leaves out.
    static func asked(by parameters: SourceParameters) -> Asked {
        var only: [String] = [], startedAfter: Date?
        if case .string(let list)? = parameters["calendars"] { only = names(in: list) }
        if case .string(let text)? = parameters["started_after"] { startedAfter = moment(from: text) }
        return Asked(wanted: only.isEmpty ? .every : .only(only), startedAfter: startedAfter)
    }

    /// A moment written as in RFC 3339, "2026-11-13T09:15:00-08:00" or
    /// "...Z"; nil without its offset from UTC, which would leave the moment
    /// to be guessed from this Mac's time zone.
    static func moment(from text: String) -> Date? {
        ISO8601DateFormatter().date(from: text)
    }

    /// The events left once those that started before `startedAfter` are
    /// left out. One that started at that moment stays, and so does every
    /// all-day event, which starts at midnight but is not over until the
    /// day is, and every reminder, which is still to be done.
    static func events(_ events: [Event], startedAfter: Date?) -> [Event] {
        guard let startedAfter else { return events }
        return events.filter { $0.all_day || $0.kind == .reminder || $0.start >= startedAfter }
    }

    /// A reminder as an event, if it is due at all: it starts and ends when
    /// it is due, and is all day if it is due on a date with no time.
    static func event(reminder title: String?, list: String, due: DateComponents?, priority: Int, in calendar: Calendar) -> Event? {
        guard let due, let moment = calendar.date(from: due) else { return nil }
        return Event(title: title ?? "", calendar: list, start: moment, end: moment, all_day: due.hour == nil,
                     location: "", kind: .reminder, priority: priority)
    }

    /// The reminders due in `day`, with those due before it if `overdueToo`.
    static func reminders(_ reminders: [Event], dueIn day: DateInterval, overdueToo: Bool) -> [Event] {
        reminders.filter { $0.start < day.end && (overdueToo || $0.start >= day.start) }
    }

    /// Earliest first, and by title when two are at one time.
    static func inOrder(_ events: [Event]) -> [Event] {
        events.sorted { ($0.start, $0.title) < ($1.start, $1.title) }
    }

    /// The names in a list written with commas between them: without the
    /// space around each, and each once however it is capitalised.
    static func names(in list: String) -> [String] {
        var names: [String] = []
        for name in list.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) }) where !name.isEmpty {
            if !names.contains(where: { same($0, name) }) { names.append(name) }
        }
        return names
    }

    /// Whether two names name the same calendar: capitals do not matter.
    static func same(_ one: String, _ other: String) -> Bool {
        one.caseInsensitiveCompare(other) == .orderedSame
    }

    /// Which calendars and reminder lists are wanted, going by the title of
    /// each. A name is looked for among both. A name that is neither a
    /// calendar's nor a list's is a mistake, so that one renamed or misspelt
    /// does not go unnoticed.
    static func choose<Item>(_ wanted: Wanted, calendars: [Item], reminderLists: [Item], title: (Item) -> String) -> Chosen<Item> {
        guard case .only(let named) = wanted else { return .lists(calendars: .every, reminderLists: .every) }
        let everyCalendar = named.contains { same($0, Self.everyCalendar) }
        let everyReminderList = named.contains { same($0, Self.everyReminderList) }
        let plain = named.filter { !same($0, Self.everyCalendar) && !same($0, Self.everyReminderList) }
        let missing = plain.filter { name in !(calendars + reminderLists).contains { same(title($0), name) } }
        guard missing.isEmpty else { return .missing(missing) }
        func lists(_ all: [Item], every: Bool) -> Lists<Item> {
            every ? .every : .these(all.filter { item in plain.contains { same(title(item), $0) } })
        }
        return .lists(calendars: lists(calendars, every: everyCalendar), reminderLists: lists(reminderLists, every: everyReminderList))
    }

    func problem(with parameters: SourceParameters) -> String? {
        if let problem = ParametersSchema.problem(with: parameters, against: parametersSchema) { return problem }
        if case .string(let list)? = parameters["calendars"], !list.isEmpty, Self.names(in: list).isEmpty {
            return "the parameter \"calendars\" names no calendar"
        }
        if case .string(let text)? = parameters["started_after"], Self.moment(from: text) == nil {
            return "the parameter \"started_after\" must be a moment with its offset from UTC, as 2026-11-13T09:15:00-08:00, not \"\(text)\""
        }
        return nil
    }

    /// The day that is `daysFromToday` after the day `now` falls in, from its
    /// first moment to the first moment of the day after, as `calendar`
    /// reckons days. Nil only for a date the calendar cannot reach.
    static func day(_ daysFromToday: Int, from now: Date, in calendar: Calendar) -> DateInterval? {
        guard let start = calendar.date(byAdding: .day, value: daysFromToday, to: calendar.startOfDay(for: now)),
              let end = calendar.date(byAdding: .day, value: 1, to: start) else { return nil }
        return DateInterval(start: start, end: end)
    }

    /// A day's date as year, month and day in `calendar`'s time zone: "2026-10-08".
    static func dateText(of day: Date, in calendar: Calendar) -> String {
        let parts = calendar.dateComponents([.year, .month, .day], from: day)
        return String(format: "%04d-%02d-%02d", parts.year ?? 0, parts.month ?? 0, parts.day ?? 0)
    }

    private let store = EKEventStore()

    func fetch(parameters: SourceParameters, _ done: @escaping (Entry) -> Void) {
        // Each asks the user the first time, and answers at once after that.
        store.requestFullAccessToEvents { calendarsAllowed, error in
            if !calendarsAllowed { log("Calendar access denied: \(error?.localizedDescription ?? "no error given")") }
            self.store.requestFullAccessToReminders { remindersAllowed, error in
                if !remindersAllowed { log("Reminders access denied: \(error?.localizedDescription ?? "no error given")") }
                self.read(Self.asked(by: parameters), calendarsAllowed: calendarsAllowed, remindersAllowed: remindersAllowed, done)
            }
        }
    }

    /// Reads today's and tomorrow's events and reminders, from what access allows.
    private func read(_ asked: Asked, calendarsAllowed: Bool, remindersAllowed: Bool, _ done: @escaping (Entry) -> Void) {
        let calendar = Calendar.current
        let now = Date()
        guard let today = Self.day(0, from: now, in: calendar), let tomorrow = Self.day(1, from: now, in: calendar) else {
            return done(failed("today or tomorrow cannot be reckoned"))
        }
        store.refreshSourcesIfNecessary()

        // Whether a calendar or list of a name exists can change while the
        // server runs, so it is found out here and not when the server starts.
        let denied = [calendarsAllowed ? nil : "Calendar access denied", remindersAllowed ? nil : "Reminders access denied"].compactMap { $0 }
        let calendars: Lists<EKCalendar>, reminderLists: Lists<EKCalendar>
        switch Self.choose(asked.wanted, calendars: calendarsAllowed ? store.calendars(for: .event) : [],
                           reminderLists: remindersAllowed ? store.calendars(for: .reminder) : [], title: \.title) {
        case .lists(let chosenCalendars, let chosenLists):
            (calendars, reminderLists) = (chosenCalendars, chosenLists)
        case .missing(let names):
            let reason = (names.count == 1 ? "no calendar or list named " : "no calendars or lists named ") + names.map { "\"\($0)\"" }.joined(separator: ", ")
            return done(failed(([reason] + denied).joined(separator: "; ")))
        }
        if calendars.any && !calendarsAllowed { return done(failed("Calendar access denied")) }
        if reminderLists.any && !remindersAllowed { return done(failed("Reminders access denied")) }

        let todaysEvents = events(on: today, in: calendars), tomorrowsEvents = events(on: tomorrow, in: calendars)
        let answer = { (reminders: [Event]) in
            let payload = Payload(
                today: Day(date: Self.dateText(of: today.start, in: calendar),
                           events: Self.inOrder(Self.events(todaysEvents, startedAfter: asked.startedAfter)
                                                + Self.reminders(reminders, dueIn: today, overdueToo: true))),
                tomorrow: Day(date: Self.dateText(of: tomorrow.start, in: calendar),
                              events: Self.inOrder(tomorrowsEvents + Self.reminders(reminders, dueIn: tomorrow, overdueToo: false))))
            log(.debug, "Fetched \(payload.today.count) for today and \(payload.tomorrow.count) for tomorrow")
            done(self.succeeded(payload))
        }
        guard reminderLists.any else { return answer([]) }

        // Every incomplete reminder, filtered here: EventKit's date-range
        // predicate can miss reminders due on a date with no time. A
        // repeating reminder is one EKReminder, due at its next occurrence.
        let incomplete = store.predicateForIncompleteReminders(withDueDateStarting: nil, ending: nil, calendars: reminderLists.items)
        store.fetchReminders(matching: incomplete) { found in
            guard let found else {
                log("Reminders could not be read")
                return done(self.failed("Reminders could not be read"))
            }
            answer(found.compactMap {
                Self.event(reminder: $0.title, list: $0.calendar.title, due: $0.dueDateComponents, priority: $0.priority, in: calendar)
            })
        }
    }

    /// The events of these calendars that fall in `day`.
    private func events(on day: DateInterval, in calendars: Lists<EKCalendar>) -> [Event] {
        // Asked for the events of no calendars, EventKit gives those of all of them.
        guard calendars.any else { return [] }
        let onThatDay = store.predicateForEvents(withStart: day.start, end: day.end, calendars: calendars.items)
        return store.events(matching: onThatDay)
            .map { Event(title: $0.title ?? "", calendar: $0.calendar.title, start: $0.startDate, end: $0.endDate, all_day: $0.isAllDay, location: $0.location ?? "") }
    }
}
