import assert from "node:assert/strict";
import request from "supertest";
import * as forgeNs from "node-forge";
import { createApp } from "../dist/server.js";
import { detectEncoding, detectType } from "../dist/services/detector.js";
import { normalizeInputs } from "../dist/services/normalizer.js";

const forge = forgeNs.default ?? forgeNs;

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

function buildSamplePkcs12(password) {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date("2025-01-01T00:00:00Z");
  cert.validity.notAfter = new Date("2027-01-01T00:00:00Z");

  const attrs = [
    { name: "commonName", value: "teste.local" },
    { name: "countryName", value: "BR" },
    { shortName: "ST", value: "SP" },
    { name: "localityName", value: "Sao Paulo" },
    { name: "organizationName", value: "Atlas Toolkit" }
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [cert], password, {
    generateLocalKeyId: true,
    friendlyName: "atlas-test"
  });

  return Buffer.from(forge.asn1.toDer(p12Asn1).getBytes(), "binary");
}

async function run() {
  const app = createApp();

  const health = await request(app).get("/health");
  assert.equal(health.status, 200);
  assert.deepEqual(health.body, { ok: true });

  const decoded = await request(app).post("/toolkit/csr/decode").send({ pem: SAMPLE_CSR });
  assert.equal(decoded.status, 200);
  assert.equal(decoded.body.decoded.type, "csr");
  assert.match(decoded.body.decoded.subjectString, /CN=/);
  assert.equal(Array.isArray(decoded.body.warnings), true);

  const missing = await request(app).post("/toolkit/csr/decode").send({});
  assert.equal(missing.status, 400);
  assert.equal(missing.body.error, "BAD_REQUEST");

  const createJob = await request(app)
    .post("/toolkit/jobs")
    .attach("files", Buffer.from(SAMPLE_CSR, "utf8"), "sample.csr.pem");
  assert.equal(createJob.status, 200);
  assert.equal(typeof createJob.body.jobId, "string");

  const badRecipe = await request(app)
    .post(`/toolkit/jobs/${createJob.body.jobId}/recipes/unknown_recipe`)
    .send({});
  assert.equal(badRecipe.status, 400);

  const derLike = Buffer.from([0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01]);
  const encoding = detectEncoding(derLike);
  assert.equal(encoding, "der");
  assert.equal(detectType(derLike, encoding), "unknown");
  const normalizedDer = normalizeInputs([
    {
      id: "in_der",
      originalName: "certificate.der",
      mimeType: "application/octet-stream",
      size: derLike.length,
      sha256: "unused",
      bytes: derLike
    }
  ]);
  assert.equal(normalizedDer[0]?.detectedType, "unknown");

  const brokenPkcs12Bytes = Buffer.from([0x30, 0x82, 0x01, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x05]);
  const invalidPfxJob = await request(app)
    .post("/toolkit/jobs")
    .attach("files", brokenPkcs12Bytes, "broken.pfx");
  assert.equal(invalidPfxJob.status, 200);

  const invalidPfxExport = await request(app)
    .post(`/toolkit/jobs/${invalidPfxJob.body.jobId}/recipes/export_formats`)
    .send({ formats: ["pem"], sourcePassword: "123456" });
  assert.equal(invalidPfxExport.status, 400);
  assert.equal(invalidPfxExport.body.error, "PKCS12_INVALID");

  const validPfx = buildSamplePkcs12("secret123");
  const validPfxJob = await request(app)
    .post("/toolkit/jobs")
    .attach("files", validPfx, "valid.pfx");
  assert.equal(validPfxJob.status, 200);

  const wrongPassword = await request(app)
    .post(`/toolkit/jobs/${validPfxJob.body.jobId}/recipes/extract_pkcs12`)
    .send({ password: "senha-errada" });
  assert.equal(wrongPassword.status, 400);
  assert.equal(wrongPassword.body.error, "PASSWORD_INVALID");

  console.log("All tests passed.");
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
