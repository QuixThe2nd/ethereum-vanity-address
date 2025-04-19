import os from 'os';
import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import { sha256 } from '@noble/hashes/sha256'
import { sha512 } from '@noble/hashes/sha512';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { hmac } from '@noble/hashes/hmac';
import { secp256k1 } from '@noble/curves/secp256k1';
import { mod } from '@noble/curves/abstract/modular';
import { keccak_256 } from '@noble/hashes/sha3';
import { wordlist } from '@scure/bip39/wordlists/english';

const encoder = new TextEncoder()
const uint32Buffer = new Uint8Array(4);
const uint32View = new DataView(uint32Buffer.buffer);
const zeroBuffer = new Uint8Array([0])

// Encoders/Decoders
function bytesToNumber(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8n) | BigInt(bytes[i]!);
  }
  return value;
}
function bytesToHex(bytes: Uint8Array): string {
  const hex = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    hex[i] = hexTable[bytes[i]!];
  }
  return hex.join('');
}
function hexToBytes(hex: string): Uint8Array {
  const len = hex.length >> 1;
  const bytes = new Uint8Array(len);

  for (let i = 0; i < len; i++) {
    const j = i << 1;
    bytes[i] = (BASE16_LOOKUP[hex.charCodeAt(j)]! << 4) | BASE16_LOOKUP[hex.charCodeAt(j + 1)]!;
  }

  return bytes;
}

function toU32(n: number) {
  uint32View.setUint32(0, n, false);
  return uint32Buffer;
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  
  return result;
}

// consts
const powers = [ 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728, 268435456, 536870912, 1073741824, 2147483648, 4294967296, 8589934592, 17179869184, 34359738368, 68719476736, 137438953472, 274877906944, 549755813888 ]
const hexTable = Array(256).fill(0).map((_, i) => i.toString(16).padStart(2, '0'));
const BASE16_LOOKUP = new Uint8Array(103);
for (let i = 0; i < 10; i++) BASE16_LOOKUP[48 + i] = i; // 0-9
for (let i = 0; i < 6; i++) BASE16_LOOKUP[65 + i] = 10 + i; // A-F
for (let i = 0; i < 6; i++) BASE16_LOOKUP[97 + i] = 10 + i; // a-f
const bitcoinSeed = encoder.encode('Bitcoin seed')

// Convert mnemonic to address
const mnemonicToSeed = (mnemonic: string) => pbkdf2(sha512, mnemonic, 'mnemonic', { c: 2048, dkLen: 64 })
function seedToPrivKey(seed: Uint8Array) {
  let I = hmac(sha512, bitcoinSeed, seed);
  let privateKey = bytesToNumber(I.slice(0, 32))
  for (const c of [ "44'", "60'", "0'", "0", "0" ]) {
    const hardened = c.endsWith("'");
    const index = parseInt(c.replace("'", "")) + (hardened ? 0x80000000 : 0);
    
    if (hardened) I = hmac(sha512, I.slice(32), concatBytes(zeroBuffer, hexToBytes(privateKey.toString(16).padStart(64, '0')), toU32(index)));
    else I = hmac(sha512, I.slice(32), concatBytes(secp256k1.getPublicKey(privateKey, true), toU32(index)));
    
    privateKey = mod(privateKey + bytesToNumber(I.slice(0, 32)), secp256k1.CURVE.n);
  }
  return privateKey.toString(16).padStart(64, '0');
}
const privateKeyToPublicKey = (privateKey: string) => bytesToHex(secp256k1.getPublicKey(privateKey, false)).substring(2)
const publicKeyToAddress = (publicKey: string) => bytesToHex(keccak_256(hexToBytes(publicKey))).substring(24).toLowerCase()
const mnemonicToAddress = (mnemonic: string) => publicKeyToAddress(privateKeyToPublicKey(seedToPrivKey(mnemonicToSeed(mnemonic))))

function generateMnemonic() {
  const rand = crypto.getRandomValues(new Uint8Array(16))
  const resR = new Uint8Array(17);
  resR.set(rand);
  resR.set(new Uint8Array([(sha256(rand)[0]! >> 4) << 4]).slice(0, 1), 16);

  let carry = 0;
  let pos = 0;
  const mask = powers[11]! - 1;
  const res: number[] = [];
  for (const n of Array.from(resR)) {
    carry = (carry << 8) | n;
    pos += 8;
    while (pos >= 11) {
      res.push(((carry >> (pos - 11)) & mask) >>> 0);
      pos -= 11
    }
    carry &= powers[pos]! - 1;
  }
  return res.map((i) => wordlist[i]!).join(' ');
}

const bestAddress: { phrase: string, zeroBytes: number, timeToFind: number } = { phrase: '', zeroBytes: 0, timeToFind: 0 }
const startTime = +new Date()

const sharedBuffer = new SharedArrayBuffer(4);
const sharedArray = new Int32Array(sharedBuffer);
Atomics.store(sharedArray, 0, 0);
sharedArray[0] = 0;

if (isMainThread) {
   for (let workerId = 0; workerId < os.cpus().length; workerId++) {
    const worker = new Worker(__filename, { workerData: { workerId, sharedBuffer }});
    
    worker.on('message', (result: { phrase: string, address: string, zeroBytes: number, workerId: number }) => {
      const { phrase, address, zeroBytes, workerId } = result;

      if (zeroBytes >= bestAddress.zeroBytes) {
        bestAddress.phrase = phrase;

        if (zeroBytes > bestAddress.zeroBytes) {
          bestAddress.zeroBytes = zeroBytes;
          bestAddress.timeToFind = +new Date() - startTime;
          Atomics.store(sharedArray, 0, zeroBytes);
        }

        console.log('----');
        console.log('Zero Bytes:', zeroBytes);
        console.log('Worker:', workerId);
        console.log('Mins Till Next Address:', Math.round(bestAddress.timeToFind/6000 * 256)/10);
        console.log('Address:', `0x${address}`);
        console.log('Seed Phrase:', phrase);
        console.log('----\n');
      }
    });
  }
} else doWork(workerData.workerId, new Int32Array(workerData.sharedBuffer));

function doWork(workerId: number, sharedBestZeroBytes: Int32Array) {
  while (true) {
    const phrase = generateMnemonic();
    const address = mnemonicToAddress(phrase);
    
    let zeroBytes = 0;
    for (let i = 0; i < 40; i += 2) {
      if (address.substring(i, i+2) === '00') zeroBytes++;
    }

    if (zeroBytes >= Atomics.load(sharedBestZeroBytes, 0)) parentPort?.postMessage({ phrase, address, zeroBytes, workerId });
  }
}
