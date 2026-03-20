import { createApp } from "./server.js";

const app = createApp();

const port = process.env.PORT ? Number(process.env.PORT) : 3000;
app.listen(port, () => {
  console.log(`Toolkit rodando em http://localhost:${port}`);
});
