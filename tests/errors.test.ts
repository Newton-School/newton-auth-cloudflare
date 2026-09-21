import { describe, expect, it } from "vitest"
import {
  ConfigError,
  InvalidCallbackAssertionError,
  InvalidSessionError,
  InvalidStateError,
  NewtonAuthError,
} from "../src/errors.js"

describe("errors", () => {
  it("subclasses NewtonAuthError with proper names and default messages", () => {
    const cases: Array<[NewtonAuthError, string, string]> = [
      [new InvalidSessionError(), "InvalidSessionError", "invalid session"],
      [new InvalidStateError(), "InvalidStateError", "invalid state"],
      [new InvalidCallbackAssertionError(), "InvalidCallbackAssertionError", "invalid callback assertion"],
      [new ConfigError("bad config"), "ConfigError", "bad config"],
    ]
    for (const [err, name, message] of cases) {
      expect(err).toBeInstanceOf(NewtonAuthError)
      expect(err).toBeInstanceOf(Error)
      expect(err.name).toBe(name)
      expect(err.message).toBe(message)
    }
  })
})
