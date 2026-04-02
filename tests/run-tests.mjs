import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import assert from "node:assert/strict";
import request from "supertest";
import * as forgeNs from "node-forge";

import { createApp } from "../dist/server.js";
import { FsJobRepository } from "../dist/storage/fsJobRepository.js";
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

function buildPkcs12WithChain(password, commonName = "servidor.local") {
  const chain = buildServerCertificateChain(commonName);
  const certs = [
    forge.pki.certificateFromPem(chain.certPem),
    forge.pki.certificateFromPem(chain.intermediatePem)
  ];
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(forge.pki.privateKeyFromPem(chain.keyPem), certs, password, {
    generateLocalKeyId: true,
    friendlyName: commonName
  });

  return {
    bytes: Buffer.from(forge.asn1.toDer(p12Asn1).getBytes(), "binary"),
    certPem: chain.certPem,
    keyPem: chain.keyPem,
    intermediatePem: chain.intermediatePem
  };
}

function buildCertificateAndKeyPair(commonName) {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = Math.floor(Math.random() * 100000).toString(16);
  cert.validity.notBefore = new Date("2025-01-01T00:00:00Z");
  cert.validity.notAfter = new Date("2027-01-01T00:00:00Z");
  const attrs = [
    { name: "commonName", value: commonName },
    { name: "countryName", value: "BR" },
    { shortName: "ST", value: "SP" },
    { name: "localityName", value: "Sao Paulo" },
    { name: "organizationName", value: "Atlas Toolkit" }
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey)
  };
}

function buildServerCertificateChain(commonName) {
  const rootKeys = forge.pki.rsa.generateKeyPair(1024);
  const rootCert = forge.pki.createCertificate();
  rootCert.publicKey = rootKeys.publicKey;
  rootCert.serialNumber = Math.floor(Math.random() * 100000).toString(16);
  rootCert.validity.notBefore = new Date("2025-01-01T00:00:00Z");
  rootCert.validity.notAfter = new Date("2027-01-01T00:00:00Z");
  const rootAttrs = [
    { name: "commonName", value: `${commonName} Root CA` },
    { name: "countryName", value: "BR" },
    { shortName: "ST", value: "SP" },
    { name: "localityName", value: "Sao Paulo" },
    { name: "organizationName", value: "Atlas Toolkit Root CA" }
  ];
  rootCert.setSubject(rootAttrs);
  rootCert.setIssuer(rootAttrs);
  rootCert.setExtensions([
    { name: "basicConstraints", cA: true, pathLenConstraint: 1 },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, digitalSignature: true }
  ]);
  rootCert.sign(rootKeys.privateKey, forge.md.sha256.create());

  const intermediateKeys = forge.pki.rsa.generateKeyPair(1024);
  const intermediateCert = forge.pki.createCertificate();
  intermediateCert.publicKey = intermediateKeys.publicKey;
  intermediateCert.serialNumber = Math.floor(Math.random() * 100000).toString(16);
  intermediateCert.validity.notBefore = new Date("2025-01-01T00:00:00Z");
  intermediateCert.validity.notAfter = new Date("2027-01-01T00:00:00Z");
  const intermediateAttrs = [
    { name: "commonName", value: `${commonName} Intermediate CA` },
    { name: "countryName", value: "BR" },
    { shortName: "ST", value: "SP" },
    { name: "localityName", value: "Sao Paulo" },
    { name: "organizationName", value: "Atlas Toolkit CA" }
  ];
  intermediateCert.setSubject(intermediateAttrs);
  intermediateCert.setIssuer(rootAttrs);
  intermediateCert.setExtensions([
    { name: "basicConstraints", cA: true, pathLenConstraint: 0 },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, digitalSignature: true }
  ]);
  intermediateCert.sign(rootKeys.privateKey, forge.md.sha256.create());

  const leafKeys = forge.pki.rsa.generateKeyPair(1024);
  const leafCert = forge.pki.createCertificate();
  leafCert.publicKey = leafKeys.publicKey;
  leafCert.serialNumber = Math.floor(Math.random() * 100000).toString(16);
  leafCert.validity.notBefore = new Date("2025-01-01T00:00:00Z");
  leafCert.validity.notAfter = new Date("2027-01-01T00:00:00Z");
  const leafAttrs = [
    { name: "commonName", value: commonName },
    { name: "countryName", value: "BR" },
    { shortName: "ST", value: "SP" },
    { name: "localityName", value: "Sao Paulo" },
    { name: "organizationName", value: "Atlas Toolkit" }
  ];
  leafCert.setSubject(leafAttrs);
  leafCert.setIssuer(intermediateAttrs);
  leafCert.sign(intermediateKeys.privateKey, forge.md.sha256.create());

  return {
    certPem: forge.pki.certificateToPem(leafCert),
    keyPem: forge.pki.privateKeyToPem(leafKeys.privateKey),
    intermediatePem: forge.pki.certificateToPem(intermediateCert),
    rootPem: forge.pki.certificateToPem(rootCert)
  };
}

function buildEncryptedPrivateKeyPem(commonName, password) {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = Math.floor(Math.random() * 100000).toString(16);
  cert.validity.notBefore = new Date("2025-01-01T00:00:00Z");
  cert.validity.notAfter = new Date("2027-01-01T00:00:00Z");
  const attrs = [
    { name: "commonName", value: commonName },
    { name: "countryName", value: "BR" },
    { shortName: "ST", value: "SP" },
    { name: "localityName", value: "Sao Paulo" },
    { name: "organizationName", value: "Atlas Toolkit" }
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    certPem: forge.pki.certificateToPem(cert),
    encryptedKeyPem: forge.pki.encryptRsaPrivateKey(keys.privateKey, password)
  };
}

function buildCertificateAuthority(commonName, issuerName, selfSigned = false) {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = Math.floor(Math.random() * 100000).toString(16);
  cert.validity.notBefore = new Date("2025-01-01T00:00:00Z");
  cert.validity.notAfter = new Date("2027-01-01T00:00:00Z");
  const subjectAttrs = [
    { name: "commonName", value: commonName },
    { name: "countryName", value: "BR" },
    { shortName: "ST", value: "SP" },
    { name: "localityName", value: "Sao Paulo" },
    { name: "organizationName", value: "Atlas Toolkit" }
  ];
  const issuerAttrs = selfSigned
    ? subjectAttrs
    : [
        { name: "commonName", value: issuerName },
        { name: "countryName", value: "BR" },
        { shortName: "ST", value: "SP" },
        { name: "localityName", value: "Sao Paulo" },
        { name: "organizationName", value: "Atlas Toolkit CA" }
      ];

  cert.setSubject(subjectAttrs);
  cert.setIssuer(issuerAttrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: true, pathLenConstraint: selfSigned ? 1 : 0 },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, digitalSignature: true }
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return forge.pki.certificateToPem(cert);
}

async function run() {
  const app = createApp();

  const health = await request(app).get("/health");
  assert.equal(health.status, 200);
  assert.equal(health.body.ok, true);
  assert.equal(typeof health.body.jobTtlMs, "number");
  assert.equal(typeof health.body.metrics?.jobsCreated, "number");

  const decoded = await request(app).post("/toolkit/csr/decode").send({ pem: SAMPLE_CSR });
  assert.equal(decoded.status, 200);
  assert.equal(decoded.body.decoded.type, "csr");
  assert.match(decoded.body.decoded.subjectString, /CN=/);
  assert.equal(Array.isArray(decoded.body.warnings), true);

  const missing = await request(app).post("/toolkit/csr/decode").send({});
  assert.equal(missing.status, 400);
  assert.equal(missing.body.error, "BAD_REQUEST");

  const createRes = await request(app)
    .post("/toolkit/jobs")
    .attach("files", Buffer.from(SAMPLE_CSR, "utf8"), "sample.csr.pem");
  assert.equal(createRes.status, 200);
  assert.equal(typeof createRes.body.jobId, "string");

  const createdJob = await request(app).get(`/toolkit/jobs/${createRes.body.jobId}`);
  assert.equal(createdJob.status, 200);
  assert.equal(typeof createdJob.body.expiresAt, "string");

  const badRecipe = await request(app)
    .post(`/toolkit/jobs/${createRes.body.jobId}/recipes/unknown_recipe`)
    .send({});
  assert.equal(badRecipe.status, 400);
  assert.equal(badRecipe.body.error, "BAD_REQUEST");

  const derLike = Buffer.from([0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01]);
  const encoding = detectEncoding(derLike);
  assert.equal(encoding, "der");
  assert.equal(detectType(derLike, encoding), "unknown");

  const derCertificatePair = buildCertificateAndKeyPair("der.local");
  const derCertificateBytes = Buffer.from(
    forge.asn1.toDer(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(derCertificatePair.certPem))).getBytes(),
    "binary"
  );
  const normalizedDer = normalizeInputs([
    {
      id: "in_der",
      originalName: "certificate.der",
      mimeType: "application/octet-stream",
      size: derCertificateBytes.length,
      sha256: "unused",
      bytes: derCertificateBytes
    }
  ]);
  assert.equal(normalizedDer[0]?.detectedType, "x509_certificate");
  assert.equal(normalizedDer[0]?.encoding, "der");

  const validPfx = buildSamplePkcs12("secret123");
  const normalizedPkcs12 = normalizeInputs([
    {
      id: "in_p12",
      originalName: "arquivo.bin",
      mimeType: "application/octet-stream",
      size: validPfx.length,
      sha256: "unused",
      bytes: validPfx
    }
  ]);
  assert.equal(normalizedPkcs12[0]?.detectedType, "pkcs12");

  const pfxJob = await request(app).post("/toolkit/jobs").attach("files", validPfx, "valid.p12");
  assert.equal(pfxJob.status, 200);

  const invalidExtract = await request(app)
    .post(`/toolkit/jobs/${pfxJob.body.jobId}/recipes/extract_pkcs12`)
    .send({});
  assert.equal(invalidExtract.status, 400);
  assert.equal(invalidExtract.body.error, "BAD_REQUEST");

  const exportRes = await request(app)
    .post(`/toolkit/jobs/${pfxJob.body.jobId}/recipes/export_formats`)
    .send({ formats: ["pem", "key"], sourcePassword: "secret123" });
  assert.equal(exportRes.status, 200);
  assert.equal(exportRes.body.artifacts.length, 2);
  assert.match(String(exportRes.body.artifacts[0]?.filename ?? ""), /valid|teste-local/i);

  const artifactId = exportRes.body.artifacts[0]?.id;
  const download = await request(app).get(`/toolkit/jobs/${pfxJob.body.jobId}/download/${artifactId}`);
  assert.equal(download.status, 200);
  assert.match(String(download.header["content-type"] ?? ""), /application\/x-pem-file/);

  const pfxChain = buildPkcs12WithChain("secret456", "srv-pfx.local");
  const pfxChainJob = await request(app).post("/toolkit/jobs").attach("files", pfxChain.bytes, "srv-pfx.p12");
  assert.equal(pfxChainJob.status, 200);

  const pfxExtract = await request(app)
    .post(`/toolkit/jobs/${pfxChainJob.body.jobId}/recipes/extract_pkcs12`)
    .send({ password: "secret456" });
  assert.equal(pfxExtract.status, 200);
  assert.match(JSON.stringify(pfxExtract.body.artifacts), /\.key|\.crt|-chain\.pem|-fullchain\.pem/i);

  const pairA = buildCertificateAndKeyPair("pair-a.local");
  const pairB = buildCertificateAndKeyPair("pair-b.local");
  const mismatchJob = await request(app)
    .post("/toolkit/jobs")
    .attach("files", Buffer.from(pairA.certPem, "utf8"), "pair-a.crt")
    .attach("files", Buffer.from(pairB.keyPem, "utf8"), "pair-b.key");
  assert.equal(mismatchJob.status, 200);

  const mismatchRes = await request(app)
    .post(`/toolkit/jobs/${mismatchJob.body.jobId}/recipes/export_formats`)
    .send({ formats: ["pfx"], outputPassword: "novaSenha123" });
  assert.equal(mismatchRes.status, 400);
  assert.equal(mismatchRes.body.error, "KEY_CERT_MISMATCH");
  assert.match(
    mismatchRes.body.message,
    /arquivos enviados nao formam um par valido|certificado e a chave privada correspondentes/i
  );

  const missingIntermediateJob = await request(app)
    .post("/toolkit/jobs")
    .attach("files", Buffer.from(pairA.certPem, "utf8"), "pair-a.crt")
    .attach("files", Buffer.from(pairA.keyPem, "utf8"), "pair-a.key");
  assert.equal(missingIntermediateJob.status, 200);

  const missingIntermediatePfx = await request(app)
    .post(`/toolkit/jobs/${missingIntermediateJob.body.jobId}/recipes/export_formats`)
    .send({ formats: ["pfx"], outputPassword: "novaSenha123" });
  assert.equal(missingIntermediatePfx.status, 400);
  assert.equal(missingIntermediatePfx.body.error, "INTERMEDIATE_CERT_REQUIRED");

  const extraCert = buildCertificateAndKeyPair("pair-c.local");
  const ambiguousCertJob = await request(app)
    .post("/toolkit/jobs")
    .attach("files", Buffer.from(pairA.certPem, "utf8"), "pair-a.crt")
    .attach("files", Buffer.from(extraCert.certPem, "utf8"), "pair-c.crt")
    .attach("files", Buffer.from(pairA.keyPem, "utf8"), "pair-a.key");
  assert.equal(ambiguousCertJob.status, 200);

  const ambiguousCrt = await request(app)
    .post(`/toolkit/jobs/${ambiguousCertJob.body.jobId}/recipes/export_formats`)
    .send({ formats: ["crt"] });
  assert.equal(ambiguousCrt.status, 400);
  assert.equal(ambiguousCrt.body.error, "AMBIGUOUS_CERTIFICATES");

  const ambiguousPfx = await request(app)
    .post(`/toolkit/jobs/${ambiguousCertJob.body.jobId}/recipes/export_formats`)
    .send({ formats: ["pfx"], outputPassword: "novaSenha123" });
  assert.equal(ambiguousPfx.status, 400);
  assert.equal(ambiguousPfx.body.error, "AMBIGUOUS_CERT_KEY_PAIR");

  const extraKey = buildCertificateAndKeyPair("pair-d.local");
  const ambiguousKeyJob = await request(app)
    .post("/toolkit/jobs")
    .attach("files", Buffer.from(pairA.certPem, "utf8"), "pair-a.crt")
    .attach("files", Buffer.from(pairA.keyPem, "utf8"), "pair-a.key")
    .attach("files", Buffer.from(extraKey.keyPem, "utf8"), "pair-d.key");
  assert.equal(ambiguousKeyJob.status, 200);

  const ambiguousKeyExport = await request(app)
    .post(`/toolkit/jobs/${ambiguousKeyJob.body.jobId}/recipes/export_formats`)
    .send({ formats: ["key"] });
  assert.equal(ambiguousKeyExport.status, 400);
  assert.equal(ambiguousKeyExport.body.error, "AMBIGUOUS_CERT_KEY_PAIR");

  const encryptedPair = buildEncryptedPrivateKeyPem("encrypted.local", "segredo123");
  const encryptedKeyJob = await request(app)
    .post("/toolkit/jobs")
    .attach("files", Buffer.from(encryptedPair.certPem, "utf8"), "encrypted.crt")
    .attach("files", Buffer.from(encryptedPair.encryptedKeyPem, "utf8"), "encrypted.key");
  assert.equal(encryptedKeyJob.status, 200);

  const encryptedPfx = await request(app)
    .post(`/toolkit/jobs/${encryptedKeyJob.body.jobId}/recipes/export_formats`)
    .send({ formats: ["pfx"], outputPassword: "novaSenha123" });
  assert.equal(encryptedPfx.status, 400);
  assert.equal(encryptedPfx.body.error, "KEY_ENCRYPTED");

  const validServerChain = buildServerCertificateChain("pair-chain.local");
  const intermediatePem = validServerChain.intermediatePem;
  const completeChainJob = await request(app)
    .post("/toolkit/jobs")
    .attach("files", Buffer.from(validServerChain.certPem, "utf8"), "pair-chain.crt")
    .attach("files", Buffer.from(validServerChain.keyPem, "utf8"), "pair-chain.key")
    .attach("files", Buffer.from(intermediatePem, "utf8"), "r36.crt");
  assert.equal(completeChainJob.status, 200);

  const completePfx = await request(app)
    .post(`/toolkit/jobs/${completeChainJob.body.jobId}/recipes/export_formats`)
    .send({ formats: ["pfx"], outputPassword: "novaSenha123" });
  assert.equal(completePfx.status, 200);
  assert.equal(completePfx.body.artifacts.length, 1);

  const completeCrt = await request(app)
    .post(`/toolkit/jobs/${completeChainJob.body.jobId}/recipes/export_formats`)
    .send({ formats: ["crt", "der", "pem"] });
  assert.equal(completeCrt.status, 200);
  assert.ok(completeCrt.body.artifacts.length >= 4);
  assert.match(JSON.stringify(completeCrt.body.artifacts), /\.crt|\.der|\.pem/i);

  const fullchainRes = await request(app)
    .post(`/toolkit/jobs/${completeChainJob.body.jobId}/recipes/build_bundle`)
    .send({});
  assert.equal(fullchainRes.status, 200);
  assert.ok(fullchainRes.body.artifacts.length >= 6);
  assert.match(JSON.stringify(fullchainRes.body.artifacts), /fullchain/i);

  const intermediateJob = await request(app)
    .post("/toolkit/jobs")
    .attach("files", Buffer.from(intermediatePem, "utf8"), "r36.crt");
  assert.equal(intermediateJob.status, 200);

  const intermediateDetails = await request(app).get(`/toolkit/jobs/${intermediateJob.body.jobId}`);
  assert.equal(intermediateDetails.status, 200);
  assert.equal(Array.isArray(intermediateDetails.body.analysis?.warnings), true);
  assert.match(
    JSON.stringify(intermediateDetails.body.analysis?.warnings ?? []),
    /intermediario da cadeia/i
  );

  const wrongIntermediatePem = buildCertificateAuthority(
    "Unrelated Intermediate CA",
    "Other Root CA",
    false
  );
  const invalidChainJob = await request(app)
    .post("/toolkit/jobs")
    .attach("files", Buffer.from(pairA.certPem, "utf8"), "pair-a.crt")
    .attach("files", Buffer.from(pairA.keyPem, "utf8"), "pair-a.key")
    .attach("files", Buffer.from(wrongIntermediatePem, "utf8"), "wrong-intermediate.crt");
  assert.equal(invalidChainJob.status, 200);

  const invalidChainDetails = await request(app).get(`/toolkit/jobs/${invalidChainJob.body.jobId}`);
  assert.equal(invalidChainDetails.status, 200);
  assert.match(JSON.stringify(invalidChainDetails.body.analysis?.warnings ?? []), /cadeia valida|cadeia/i);

  const invalidChainPfx = await request(app)
    .post(`/toolkit/jobs/${invalidChainJob.body.jobId}/recipes/export_formats`)
    .send({ formats: ["pfx"], outputPassword: "novaSenha123" });
  assert.equal(invalidChainPfx.status, 400);
  assert.equal(invalidChainPfx.body.error, "CHAIN_INVALID");

  const rootPem = validServerChain.rootPem;
  const rootIncludedJob = await request(app)
    .post("/toolkit/jobs")
    .attach("files", Buffer.from(validServerChain.certPem, "utf8"), "pair-chain.crt")
    .attach("files", Buffer.from(validServerChain.keyPem, "utf8"), "pair-chain.key")
    .attach("files", Buffer.from(intermediatePem, "utf8"), "r36.crt")
    .attach("files", Buffer.from(rootPem, "utf8"), "root.crt");
  assert.equal(rootIncludedJob.status, 200);

  const rootIncludedDetails = await request(app).get(`/toolkit/jobs/${rootIncludedJob.body.jobId}`);
  assert.equal(rootIncludedDetails.status, 200);
  assert.match(JSON.stringify(rootIncludedDetails.body.analysis?.warnings ?? []), /certificado raiz/i);

  const storageRoot = path.join(os.tmpdir(), `atlas-toolkit-test-${Date.now()}`);
  fs.mkdirSync(storageRoot, { recursive: true });
  const expiredJobDir = path.join(storageRoot, "job_expired_manual");
  fs.mkdirSync(expiredJobDir, { recursive: true });
  fs.writeFileSync(
    path.join(expiredJobDir, "job-meta.json"),
    JSON.stringify({
      id: "job_expired_manual",
      createdAtMs: Date.now() - 120_000,
      expiresAtMs: Date.now() - 60_000
    }),
    "utf8"
  );

  const repository = new FsJobRepository({ storageRoot, ttlMs: 60_000 });
  assert.equal(fs.existsSync(expiredJobDir), false);

  const activeJob = repository.create([
    {
      id: "in_manual",
      originalName: "manual.csr",
      mimeType: "application/x-pem-file",
      size: Buffer.byteLength(SAMPLE_CSR, "utf8"),
      sha256: "manual",
      bytes: Buffer.from(SAMPLE_CSR, "utf8")
    }
  ]);
  assert.equal(typeof activeJob.job.expiresAt, "string");
  fs.rmSync(storageRoot, { recursive: true, force: true });

  console.log("All tests passed.");
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
