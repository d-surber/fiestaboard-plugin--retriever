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

@Test func aDaysEventsFitTheSchema() throws {
    let event = CalendarSource.Event(title: "Dentist", calendar: "Home", start: moment(2026, 10, 8, 9), end: moment(2026, 10, 8, 10), all_day: false, location: "")
    let payload = CalendarSource.Payload(date: "2026-10-08", events: [event])
    #expect(payload.count == 1)
    #expect(matches(try #require(JSON(encoding: payload)), CalendarSource().schema))
}

@Test func itSaysWhatItsParametersAreFor() {
    #expect(ParametersSchema.summary(of: CalendarSource().parametersSchema) == [
        "calendar: text, \"\" if left out. The calendar's name as the Calendar app shows it; empty for every calendar.",
        "days_from_today: a whole number, at least -3660, at most 3660, 0 if left out. 0 is today, 1 tomorrow, -1 yesterday.",
    ])
}

@Test func withNoParametersItIsEveryCalendarToday() {
    let asked = CalendarSource.asked(by: [:])
    #expect(asked.calendarName == "")
    #expect(asked.daysFromToday == 0)
}

@Test func itIsAskedForACalendarByNameAndADayByItsDistanceFromToday() {
    let asked = CalendarSource.asked(by: ["calendar": "Work", "days_from_today": -1])
    #expect(asked.calendarName == "Work")
    #expect(asked.daysFromToday == -1)
}

@Test(arguments: [
    (["calendar": "Work", "days_from_today": 1] as SourceParameters, nil as String?),
    (["days_from_today": "tomorrow"], "the parameter \"days_from_today\" must be a whole number, not \"tomorrow\""),
    (["days_from_today": .double(0.5)], "the parameter \"days_from_today\" must be a whole number, not 0.5"),
    (["days_from_today": 4000], "the parameter \"days_from_today\" must be at most 3660, not 4000"),
    (["calendar": 7], "the parameter \"calendar\" must be text, not 7"),
    (["date": "2026-10-08"], "takes no parameter named \"date\" (it takes: calendar, days_from_today)"),
])
func itsParametersAreChecked(parameters: SourceParameters, problem: String?) {
    #expect(CalendarSource().problem(with: parameters) == problem)
}

@Test(arguments: [(0, "2026-10-08"), (1, "2026-10-09"), (-1, "2026-10-07"), (24, "2026-11-01"), (-8, "2026-09-30"), (365, "2027-10-08")])
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
