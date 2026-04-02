import pino from "pino";
import { env } from "../config/env.js";

const level = env.LOG_LEVEL;
const isProduction = env.NODE_ENV === "production";

export const logger = pino(
  isProduction
    ? { level }
    : {
        level,
        transport: {
          target: "pino-pretty",
          options: {
            colorize: true,
            translateTime: "SYS:standard",
            ignore: "pid,hostname"
          }
        }
      }
);
