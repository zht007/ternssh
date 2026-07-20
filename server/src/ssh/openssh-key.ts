import bcryptPbkdf from "bcrypt-pbkdf";
import { readUint32 } from "./utils";

const OPENSSH_MAGIC = new TextEncoder().encode("openssh-key-v1\0");

const KEY_BYTES: Record<string, number> = {
  "aes128-ctr": 16,
  "aes192-ctr": 24,
  "aes256-ctr": 32,
};

function readCString(data: Uint8Array, offset: number): { value: string; next: number } {
  const len = readUint32(data, offset);
  const start = offset + 4;
  const end = start + len;
  if (end > data.length) {
    throw new Error("私钥格式损坏：字符串越界");
  }
  const value = new TextDecoder().decode(data.slice(start, end));
  return { value, next: end };
}

function normalizeCipherName(name: string): string {
  if (name === "none") return "none";
  if (name.startsWith("aes") && name.includes("-")) return name;
  const match = /^aes(\d+)(ctr|cbc)$/i.exec(name);
  if (match) return `aes${match[1]}-${match[2].toLowerCase()}`;
  throw new Error(`不支持的私钥加密算法: ${name}`);
}

export function getOpenSSHKeyCipher(pem: string): string | null {
  try {
    const raw = pemToRaw(pem);
    return readOpenSSHEnvelope(raw).cipher;
  } catch {
    return null;
  }
}

export function isEncryptedOpenSSHPrivateKey(pem: string): boolean {
  const cipher = getOpenSSHKeyCipher(pem);
  return cipher !== null && cipher !== "none";
}

function pemToRaw(pem: string): Uint8Array {
  const lines = pem.trim().split("\n");
  const b64 = lines.filter((line) => !line.startsWith("-----")).join("");
  return Uint8Array.from(atob(b64), (char) => char.charCodeAt(0));
}

function readOpenSSHEnvelope(raw: Uint8Array): {
  cipher: string;
  kdfName: string;
  kdfOptions: Uint8Array;
  publicSection: Uint8Array;
  privateSection: Uint8Array;
} {
  if (raw.length < OPENSSH_MAGIC.length) {
    throw new Error("私钥数据太短");
  }
  for (let i = 0; i < OPENSSH_MAGIC.length; i++) {
    if (raw[i] !== OPENSSH_MAGIC[i]) {
      throw new Error("不支持的私钥格式，仅支持 OpenSSH 密钥");
    }
  }

  let offset = OPENSSH_MAGIC.length;
  const cipherField = readCString(raw, offset);
  const cipher = normalizeCipherName(cipherField.value);
  offset = cipherField.next;

  const kdfField = readCString(raw, offset);
  const kdfName = kdfField.value;
  offset = kdfField.next;

  const kdfOptionsLen = readUint32(raw, offset);
  offset += 4;
  const kdfOptions = raw.slice(offset, offset + kdfOptionsLen);
  offset += kdfOptionsLen;

  const numKeys = readUint32(raw, offset);
  offset += 4;
  if (numKeys !== 1) throw new Error("仅支持单密钥文件");

  const pubSecLen = readUint32(raw, offset);
  offset += 4;
  const publicSection = raw.slice(offset, offset + pubSecLen);
  offset += pubSecLen;

  const privSecLen = readUint32(raw, offset);
  offset += 4;
  const privateSection = raw.slice(offset, offset + privSecLen);

  return { cipher, kdfName, kdfOptions, publicSection, privateSection };
}

function parseKdfOptions(data: Uint8Array): { salt: Uint8Array; rounds: number } {
  let offset = 0;
  const saltLen = readUint32(data, offset);
  offset += 4;
  const salt = data.slice(offset, offset + saltLen);
  offset += saltLen;
  const rounds = readUint32(data, offset);
  return { salt, rounds };
}

async function decryptPrivateSection(
  encrypted: Uint8Array,
  cipher: string,
  kdfName: string,
  kdfOptions: Uint8Array,
  passphrase: string,
): Promise<Uint8Array> {
  if (cipher === "none") return encrypted;

  const keyLen = KEY_BYTES[cipher];
  if (!keyLen) {
    throw new Error(`不支持的私钥加密算法: ${cipher}`);
  }
  if (kdfName !== "bcrypt") {
    throw new Error(`不支持的 KDF: ${kdfName}`);
  }
  if (!passphrase) {
    throw new Error("私钥已加密，请输入私钥密码");
  }

  const { salt, rounds } = parseKdfOptions(kdfOptions);
  const ivLen = 16;
  const keyIv = new Uint8Array(keyLen + ivLen);
  const passBytes = new TextEncoder().encode(passphrase);
  const result = bcryptPbkdf.pbkdf(
    passBytes,
    passBytes.length,
    salt,
    salt.length,
    keyIv,
    keyIv.length,
    rounds,
  );
  if (result !== 0) {
    throw new Error("私钥密码派生失败");
  }

  const key = keyIv.slice(0, keyLen);
  const iv = keyIv.slice(keyLen, keyLen + ivLen);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-CTR", length: keyLen * 8 },
    false,
    ["decrypt"],
  );
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-CTR", counter: iv, length: 128 },
    cryptoKey,
    encrypted,
  );
  const plain = new Uint8Array(decrypted);

  if (plain.length < 8) {
    throw new Error("私钥格式损坏：解密后数据太短");
  }
  const check1 = readUint32(plain, 0);
  const check2 = readUint32(plain, 4);
  if (check1 !== check2) {
    throw new Error("私钥密码错误");
  }

  return plain;
}

export async function prepareOpenSSHPrivateKey(
  pem: string,
  passphrase?: string,
): Promise<string> {
  const raw = pemToRaw(pem);
  const envelope = readOpenSSHEnvelope(raw);
  if (envelope.cipher === "none") {
    return pem.trim();
  }

  const decryptedPrivate = await decryptPrivateSection(
    envelope.privateSection,
    envelope.cipher,
    envelope.kdfName,
    envelope.kdfOptions,
    passphrase ?? "",
  );

  // Rebuild an unencrypted OpenSSH blob for downstream parsing.
  const parts: Uint8Array[] = [];
  parts.push(OPENSSH_MAGIC);
  parts.push(encodeString("none"));
  parts.push(encodeString("none"));
  parts.push(encodeString(""));
  parts.push(encodeUint32(1));
  parts.push(encodeString(envelope.publicSection));
  parts.push(encodeString(decryptedPrivate));

  const body = concatParts(parts);
  const b64 = btoa(String.fromCharCode(...body));
  const wrapped = b64.match(/.{1,64}/g)?.join("\n") ?? b64;
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${wrapped}\n-----END OPENSSH PRIVATE KEY-----`;
}

function encodeUint32(value: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (value >>> 24) & 0xff;
  buf[1] = (value >>> 16) & 0xff;
  buf[2] = (value >>> 8) & 0xff;
  buf[3] = value & 0xff;
  return buf;
}

function encodeString(value: string | Uint8Array): Uint8Array {
  const bytes =
    typeof value === "string" ? new TextEncoder().encode(value) : value;
  return concatParts([encodeUint32(bytes.length), bytes]);
}

function concatParts(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
