import { createApp } from "./server.js";
import { env } from "./config/env.js";
import { logger } from "./lib/logger.js";

const app = createApp();
const port = env.PORT;

app.listen(port, () => {
  logger.info({ port, env: env.NODE_ENV }, `Toolkit rodando na porta ${port}`);
});
