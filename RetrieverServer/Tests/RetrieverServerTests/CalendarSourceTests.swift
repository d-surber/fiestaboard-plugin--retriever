import Foundation
import Testing
@testable import RetrieverSourceCalendar
@testable import RetrieverSourceKit

/// A calendar that reckons days as Los Angeles does, where a day may have 23 or 25 hours.
private var losAngeles: Calendar {
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = TimeZone(identifier: "America/Los_Angeles")!
    return calendar
}

/// A moment in Los Angeles, from its date and time there.
private func moment(_ year: Int, _ month: Int, _ day: Int, _ hour: Int = 12) -> Date {
    losAngeles.date(from: DateComponents(year: year, month: month, day: day, hour: hour))!
}

@Test func calendarFitsTheSourceContract() {
    #expect(fitsTheSourceContract(CalendarSource()))
}

@Test func todaysAndTomorrowsEventsFitTheSchema() throws {
    let event = CalendarSource.Event(title: "Dentist", calendar: "Home", start: moment(2026, 10, 8, 9), end: moment(2026, 10, 8, 10), all_day: false, location: "")
    let reminder = CalendarSource.Event(title: "Call", calendar: "Reminders", start: moment(2026, 10, 8, 11), end: moment(2026, 10, 8, 11),
                                        all_day: false, location: "", kind: .reminder, priority: 1)
    let payload = CalendarSource.Payload(today: CalendarSource.Day(date: "2026-10-08", events: [event, reminder]),
                                         tomorrow: CalendarSource.Day(date: "2026-10-09", events: []))
    #expect(payload.today.count == 2)
    #expect(payload.tomorrow.count == 0)
    #expect(matches(try #require(JSON(encoding: payload)), CalendarSource().schema))
}

@Test func whenItCannotBeReadItGivesTwoEmptyDays() {
    #expect(CalendarSource().failed("Calendar access denied").data == [
        "today": ["date": "", "count": 0, "events": []],
        "tomorrow": ["date": "", "count": 0, "events": []],
    ])
}

@Test func itSaysWhatItsParametersAreFor() {
    #expect(ParametersSchema.summary(of: CalendarSource().parametersSchema) == [
        "calendars: text, set only by a request. Only these calendars and reminder lists, by the names the Calendar and Reminders apps show, separated by commas. _Calendars_ is every calendar and _Reminders_ every reminder list. Left out, both.",
        "started_after: text, set only by a request. Leave out today's events that started before this moment, written with its offset from UTC, as 2026-11-13T09:15:00-08:00; all-day events stay, and so do reminders and tomorrow's events. In the plugin's request body, an hour ago is {{= DATEADD(NOW(), -1, \"hours\") }}.",
    ])
}

@Test func withNoParametersItIsEveryCalendar() {
    let asked = CalendarSource.asked(by: [:])
    #expect(asked.wanted == .every)
    #expect(asked.startedAfter == nil)
    #expect(CalendarSource.asked(by: ["calendars": ""]).wanted == .every)
}

@Test func itIsAskedForCalendarsByName() {
    #expect(CalendarSource.asked(by: ["calendars": "Work, Family"]).wanted == .only(["Work", "Family"]))
}

@Test(arguments: [
    ("Work", ["Work"]),
    ("Work,Family", ["Work", "Family"]),
    ("  Work ,  US Holidays  ", ["Work", "US Holidays"]),
    ("Work,,Family,", ["Work", "Family"]),
    ("Work, work, WORK, Family", ["Work", "Family"]),
    ("", []),
    (" , ", []),
])
func aListOfNamesIsWrittenWithCommas(list: String, names: [String]) {
    #expect(CalendarSource.names(in: list) == names)
}

/// The calendars of a Mac with two accounts, each with a calendar called Home.
private let calendarsHere = ["Home", "Work", "Birthdays", "Home", "Family"]
/// Its reminder lists, one of them called as a calendar is.
private let reminderListsHere = ["Reminders", "Shopping", "Family"]

private func described(_ lists: CalendarSource.Lists<String>) -> String {
    switch lists {
    case .every: return "every"
    case .these(let names): return "\(names)"
    }
}

private func chosen(_ names: String) -> String {
    let wanted = CalendarSource.asked(by: names.isEmpty ? [:] : ["calendars": .string(names)]).wanted
    switch CalendarSource.choose(wanted, calendars: calendarsHere, reminderLists: reminderListsHere, title: { $0 }) {
    case .lists(let calendars, let reminderLists): return "calendars \(described(calendars)), lists \(described(reminderLists))"
    case .missing(let names): return "missing \(names)"
    }
}

@Test func leftOutItIsEveryCalendarAndEveryReminderList() {
    #expect(chosen("") == "calendars every, lists every")
}

@Test func onlyTheNamedCalendarsAreChosenInWhicheverAccountTheyAre() {
    #expect(chosen("Work") == "calendars [\"Work\"], lists []")
    #expect(chosen("home") == "calendars [\"Home\", \"Home\"], lists []")
}

@Test func aReminderListIsNamedAsACalendarIs() {
    #expect(chosen("Shopping") == "calendars [], lists [\"Shopping\"]")
    #expect(chosen("Work, Reminders") == "calendars [\"Work\"], lists [\"Reminders\"]")
}

@Test func aNameIsEveryCalendarAndListSoCalled() {
    #expect(chosen("family") == "calendars [\"Family\"], lists [\"Family\"]")
}

@Test func twoNamesStandForEveryCalendarAndEveryList() {
    #expect(chosen("_Calendars_") == "calendars every, lists []")
    #expect(chosen("_Reminders_") == "calendars [], lists every")
    #expect(chosen("_reminders_, Work") == "calendars [\"Work\"], lists every")
    #expect(chosen("_Calendars_, Shopping") == "calendars every, lists [\"Shopping\"]")
    #expect(chosen("_Calendars_,_Reminders_") == "calendars every, lists every")
}

@Test func aNameThatIsNoCalendarsOrListsIsAMistake() {
    #expect(chosen("Work, Wrok, Holidays") == "missing [\"Wrok\", \"Holidays\"]")
    #expect(chosen("_Calendars_, Groceries") == "missing [\"Groceries\"]")
}

@Test func whatIsChosenSaysWhetherAnyIsWanted() {
    #expect(CalendarSource.Lists<String>.every.any)
    #expect(CalendarSource.Lists<String>.every.items == nil)
    #expect(CalendarSource.Lists.these(["Work"]).any)
    #expect(!CalendarSource.Lists<String>.these([]).any)
}

@Test(arguments: [
    (["calendars": "Work, Family"] as SourceParameters, nil as String?),
    (["calendars": "_Calendars_, _Reminders_"], nil),
    (["calendars": ""], nil),
    (["calendars": " , "], "the parameter \"calendars\" names no calendar"),
    (["calendars": 7], "the parameter \"calendars\" must be text, not 7"),
    (["calendar": "Work"], "takes no parameter named \"calendar\" (it takes: calendars, started_after)"),
    (["except": "Birthdays"], "takes no parameter named \"except\" (it takes: calendars, started_after)"),
    (["days_from_today": 1], "takes no parameter named \"days_from_today\" (it takes: calendars, started_after)"),
])
func itsParametersAreChecked(parameters: SourceParameters, problem: String?) {
    #expect(CalendarSource().problem(with: parameters) == problem)
}

@Test(arguments: [(0, "2026-10-08"), (1, "2026-10-09"), (24, "2026-11-01"), (365, "2027-10-08")])
func aDayIsCountedFromToday(daysFromToday: Int, date: String) throws {
    let day = try #require(CalendarSource.day(daysFromToday, from: moment(2026, 10, 8, 15), in: losAngeles))
    #expect(CalendarSource.dateText(of: day.start, in: losAngeles) == date)
    #expect(losAngeles.component(.hour, from: day.start) == 0)
}

@Test func aDayRunsFromItsFirstMomentToTheNextDaysWhateverTheTimeNow() throws {
    let early = try #require(CalendarSource.day(0, from: moment(2026, 10, 8, 0), in: losAngeles))
    let late = try #require(CalendarSource.day(0, from: moment(2026, 10, 8, 23), in: losAngeles))
    #expect(early == late)
    #expect(early.start == moment(2026, 10, 8, 0))
    #expect(early.end == moment(2026, 10, 9, 0))
}

@Test func aDayIsADayEvenWhenTheClocksChange() throws {
    // In Los Angeles 1 November 2026 has 25 hours and 8 March 2026 has 23.
    let long = try #require(CalendarSource.day(0, from: moment(2026, 11, 1), in: losAngeles))
    #expect(long.duration == 25 * 3600)
    let short = try #require(CalendarSource.day(1, from: moment(2026, 3, 7), in: losAngeles))
    #expect(short.duration == 23 * 3600)
    #expect(CalendarSource.dateText(of: short.start, in: losAngeles) == "2026-03-08")
}

@Test func aRequestCanSayWhenTheEventsItWantsStarted() {
    // As the plugin sends it: an hour before 10:15 in Los Angeles.
    let asked = CalendarSource.asked(by: ["started_after": "2026-11-13T09:15:00-08:00"])
    #expect(asked.startedAfter == moment(2026, 11, 13, 9).addingTimeInterval(15 * 60))
    #expect(CalendarSource.asked(by: ["started_after": "2026-11-13T17:15:00Z"]).startedAfter == asked.startedAfter)
}

@Test(arguments: [
    ("2026-11-13T09:15:00-08:00", true),
    ("2026-11-13T17:15:00Z", true),
    ("2026-11-13T09:15:00", false),
    ("2026-11-13", false),
    ("an hour ago", false),
])
func whenTheEventsStartedIsAMomentWithItsOffsetFromUTC(text: String, taken: Bool) {
    let problem = "the parameter \"started_after\" must be a moment with its offset from UTC, as 2026-11-13T09:15:00-08:00, not \"\(text)\""
    #expect(CalendarSource().problem(with: ["started_after": .string(text)]) == (taken ? nil : problem))
}

@Test func onlyARequestMaySayWhichCalendarsOrWhenTheEventsStarted() {
    #expect(ParametersSchema.requestOnly(in: CalendarSource().parametersSchema) == ["calendars", "started_after"])
}

/// A timed event on 13 November 2026 in Los Angeles, from its hours there.
private func timed(_ title: String, from startHour: Int, to endHour: Int) -> CalendarSource.Event {
    CalendarSource.Event(title: title, calendar: "Home", start: moment(2026, 11, 13, startHour), end: moment(2026, 11, 13, endHour), all_day: false, location: "")
}

private let holiday = CalendarSource.Event(title: "Holiday", calendar: "Home", start: moment(2026, 11, 13, 0), end: moment(2026, 11, 14, 0), all_day: true, location: "")

@Test func eventsThatStartedBeforeTheMomentAreLeftOutButAllDayEventsStay() {
    let day = [holiday, timed("Breakfast", from: 7, to: 8), timed("Meeting", from: 9, to: 11), timed("Lunch", from: 12, to: 13)]
    let titles = CalendarSource.events(day, startedAfter: moment(2026, 11, 13, 9)).map(\.title)
    // Meeting started at the moment itself, and stays.
    #expect(titles == ["Holiday", "Meeting", "Lunch"])
}

@Test func remindersStayWhenEarlierEventsAreLeftOut() throws {
    let due = try #require(CalendarSource.event(reminder: "Call", list: "Reminders", due: DateComponents(year: 2026, month: 11, day: 13, hour: 8),
                                                priority: 0, in: losAngeles))
    let titles = CalendarSource.events([due, timed("Breakfast", from: 7, to: 8)], startedAfter: moment(2026, 11, 13, 9)).map(\.title)
    #expect(titles == ["Call"])
}

@Test func withNoMomentNoEventIsLeftOut() {
    let day = [holiday, timed("Breakfast", from: 7, to: 8)]
    #expect(CalendarSource.events(day, startedAfter: nil) == day)
}

@Test func aReminderDueAtATimeIsAnEventThatStartsAndEndsThen() throws {
    let event = try #require(CalendarSource.event(reminder: "Call", list: "Shopping", due: DateComponents(year: 2026, month: 11, day: 13, hour: 15, minute: 30),
                                                  priority: 1, in: losAngeles))
    #expect(event == CalendarSource.Event(title: "Call", calendar: "Shopping", start: moment(2026, 11, 13, 15).addingTimeInterval(30 * 60),
                                          end: moment(2026, 11, 13, 15).addingTimeInterval(30 * 60), all_day: false, location: "",
                                          kind: .reminder, priority: 1))
}

@Test func aReminderDueOnADateIsAllDay() throws {
    let event = try #require(CalendarSource.event(reminder: nil, list: "Reminders", due: DateComponents(year: 2026, month: 11, day: 13),
                                                  priority: 0, in: losAngeles))
    #expect(event.title == "")
    #expect(event.all_day)
    #expect(event.start == moment(2026, 11, 13, 0))
    #expect(event.kind == .reminder)
}

@Test func aReminderWithNoDueDateIsNoEvent() {
    #expect(CalendarSource.event(reminder: "Someday", list: "Reminders", due: nil, priority: 0, in: losAngeles) == nil)
}

/// A reminder due at an hour on a day of November 2026 in Los Angeles.
private func reminder(_ title: String, day: Int, hour: Int) -> CalendarSource.Event {
    CalendarSource.event(reminder: title, list: "Reminders", due: DateComponents(year: 2026, month: 11, day: day, hour: hour), priority: 0, in: losAngeles)!
}

@Test func todayHasTheRemindersDueTodayAndThoseOverdue() throws {
    let today = try #require(CalendarSource.day(0, from: moment(2026, 11, 13), in: losAngeles))
    let tomorrow = try #require(CalendarSource.day(1, from: moment(2026, 11, 13), in: losAngeles))
    let all = [reminder("Last week", day: 6, hour: 9), reminder("This morning", day: 13, hour: 8), reminder("Tonight", day: 13, hour: 23),
               reminder("Tomorrow", day: 14, hour: 0), reminder("Later", day: 15, hour: 9)]
    #expect(CalendarSource.reminders(all, dueIn: today, overdueToo: true).map(\.title) == ["Last week", "This morning", "Tonight"])
    #expect(CalendarSource.reminders(all, dueIn: tomorrow, overdueToo: false).map(\.title) == ["Tomorrow"])
}

@Test func eventsAndRemindersAreInOrderOfTimeThenTitle() {
    let all = [timed("Lunch", from: 12, to: 13), reminder("Call", day: 13, hour: 12), reminder("Bills", day: 6, hour: 9), holiday]
    #expect(CalendarSource.inOrder(all).map(\.title) == ["Bills", "Holiday", "Call", "Lunch"])
}
