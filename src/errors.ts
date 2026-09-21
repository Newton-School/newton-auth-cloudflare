export class NewtonAuthError extends Error {
  constructor(message: string) {
    super(message)
    this.name = new.target.name
  }
}

export class ConfigError extends NewtonAuthError {}

export class InvalidSessionError extends NewtonAuthError {
  constructor(message = "invalid session") {
    super(message)
  }
}

export class InvalidStateError extends NewtonAuthError {
  constructor(message = "invalid state") {
    super(message)
  }
}

export class InvalidCallbackAssertionError extends NewtonAuthError {
  constructor(message = "invalid callback assertion") {
    super(message)
  }
}
