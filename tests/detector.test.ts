import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { detectEncoding, detectType } from "../src/services/detector.js";

describe("detector", () => {
  it("nao classifica DER arbitrario como pkcs12", () => {
    const derLike = Buffer.from([0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01]);
    const encoding = detectEncoding(derLike);

    assert.equal(encoding, "der");
    assert.equal(detectType(derLike, encoding), "unknown");
  });
});
