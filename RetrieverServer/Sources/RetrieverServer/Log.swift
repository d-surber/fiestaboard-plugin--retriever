import Foundation

func log(_ s: String) { print("\(ISO8601DateFormatter().string(from: Date())) \(s)") }
