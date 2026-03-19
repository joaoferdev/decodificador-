export class ToolkitException extends Error {
  constructor(public code: string, message: string, public httpStatus = 400) {
    super(message);
  }
}