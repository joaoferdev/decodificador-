import assert from "node:assert/strict";
import { describe, it } from "node:test";
import request from "supertest";
import { createApp } from "../src/server.js";

const SAMPLE_CSR = `-----BEGIN CERTIFICATE REQUEST-----
MIIC6DCCAdACAQAwgaIxGTAXBgNVBAMTEHRlc3Rlam9hby5nb3YuYnIxETAPBgNV
BAoTCFhESUdJVEFMMQswCQYDVQQLEwJUSTEWMBQGA1UEBxMNRkxPUklBTk9QT0xJ
UzELMAkGA1UECBMCU0MxCzAJBgNVBAYTAkJSMTMwMQYJKoZIhvcNAQkBEyRqb2Fv
LmZlcm5hbmRlc0B4ZGlnaXRhbGJyYXNpbC5jb20uYnIwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCsM7cQHkRQ+hOt59fGBBcbINgGboRz5DaFcf+H+jJB
yzfTvAy4tBLqCQxRiuSgYIjiaPqYxfA1vJnCcRl0ZVn8O+ZRlYLLi8rWGDtX/HqE
qqvp/LXd/UrMMzid2929AC4NoRRtc+sWP+r9F4OqtzipFnZfG+6+Id+CUUbqEfJQ
Eg5jshhNdgZDnuq0RZI/yK1PoJ/SO42S446io+hJWxWzbzo60fRVJePOutV3o8k1
nsOpUuVH7srqbmPE9x9mS+P8nGq/ljj1nW8NvjAbsJ1C3dK6ucw3uL6EjDg/wtyV
0/kr9nc3U6CoDbVavEhAtt5K82qBv5VRy+Dkzl9mbkgvAgMBAAGgADANBgkqhkiG
9w0BAQUFAAOCAQEAk7XvA6jaLHhO4L1NgS++Penc3M5DQp2S0qc7CxfcnZlqyaBn
SgS39rczmli02atJ4m0HOhJ2SWw0tmLVYTUQVnb3/qs6kaDgf8fIeDAAqLe12MJj
M3etEOxh50YKaUBYQGUxemL9RcgtFFxikE7wwcztBkK+wGUEqDRncJZvaMlvEZea
gYobFtgMuw2D2WuAk8TyOqWKXuUHZioUpksdt8+TUcjYH/vlZz0rp3VRrhfaNSyH
4jlGTXp13HYOfdBfiyGELTrGq6I7R5hRsGILRMDcRm6YNRVr6ntoshq+gwGh+5qr
qRYbEEOgct/YvAddxocsBuzcZ1q7QYy9V5bOPw==
-----END CERTIFICATE REQUEST-----`;

describe("API", () => {
  const app = createApp();

  it("responde health", async () => {
    const res = await request(app).get("/health");

    assert.equal(res.status, 200);
    assert.deepEqual(res.body, { ok: true });
  });

  it("decodifica CSR enviado em JSON", async () => {
    const res = await request(app).post("/toolkit/csr/decode").send({ pem: SAMPLE_CSR });

    assert.equal(res.status, 200);
    assert.equal(res.body.decoded.type, "csr");
    assert.match(res.body.decoded.subjectString, /CN=/);
    assert.equal(Array.isArray(res.body.warnings), true);
  });

  it("retorna 400 quando decode nao recebe input", async () => {
    const res = await request(app).post("/toolkit/csr/decode").send({});

    assert.equal(res.status, 400);
    assert.equal(res.body.error, "BAD_REQUEST");
  });

  it("cria job via upload e aceita recipe invalida com 400", async () => {
    const createRes = await request(app)
      .post("/toolkit/jobs")
      .attach("files", Buffer.from(SAMPLE_CSR, "utf8"), "sample.csr.pem");

    assert.equal(createRes.status, 200);
    assert.equal(typeof createRes.body.jobId, "string");

    const recipeRes = await request(app)
      .post(`/toolkit/jobs/${createRes.body.jobId}/recipes/unknown_recipe`)
      .send({});

    assert.equal(recipeRes.status, 400);
  });
});
