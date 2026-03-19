import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { routes } from "./api/routes.js";

const app = express();

app.use(cors());
app.use(helmet());
app.use(express.json({ limit: "5mb" }));
app.use(express.text({ type: ["text/plain"], limit: "5mb" }));

app.use(
  rateLimit({
    windowMs: 60_000,
    limit: 120
  })
);

app.get("/health", (_req, res) => res.json({ ok: true }));
app.get("/debug/runtime", (_req, res) => {
  res.json({
    entry: process.argv[1],
    argv: process.argv,
    cwd: process.cwd()
  });
});
app.use(routes);



const port = process.env.PORT ? Number(process.env.PORT) : 3000;
app.listen(port, () => {
  console.log(`Toolkit rodando em http://localhost:${port}`);
});