import { sha256 } from '@noble/hashes/sha256'
import { sha512 } from '@noble/hashes/sha512';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { hmac } from '@noble/hashes/hmac';
import { secp256k1 } from '@noble/curves/secp256k1';
import { mod } from '@noble/curves/abstract/modular';
import { keccak_256 } from '@noble/hashes/sha3';
import { wordlist } from '@scure/bip39/wordlists/english';

const encoder = new TextEncoder()

// Encoders/Decoders
const bytesToHex = (value: Uint8Array) => Array.from(value).map(byte => hexes[byte]).join('')
const bytesToNumber = (value: Uint8Array) => BigInt(`0x${bytesToHex(value)}`)
const stringToBytes = (value: string) => encoder.encode(value)
const asciiToBase16 = (ch: number) => ch >= asciis._0 && ch <= asciis._9 ? ch - asciis._0 : (ch >= asciis.A && ch <= asciis.F ? ch - (asciis.A - 10) : (ch >= asciis.a && ch <= asciis.f ? ch - (asciis.a - 10) : 0));
function hexToBytes(hex: string) {
  const al = hex.length / 2;
  const array = new Uint8Array(al);
  for (let ai = 0; ai < al; ai++) {
    array[ai] = asciiToBase16(hex.charCodeAt(ai*2)) * 16 + asciiToBase16(hex.charCodeAt(ai*2 + 1));
  }
  return array;
}
function toU32(n: number) {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer, 0, 4).setUint32(0, n, false);
  return buf;
};
function concatBytes(...arrays: Uint8Array[]) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    sum += arrays[i]!.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i]!;
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}

// Depends
const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
const powers = [ 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728, 268435456, 536870912, 1073741824, 2147483648, 4294967296, 8589934592, 17179869184, 34359738368, 68719476736, 137438953472, 274877906944, 549755813888 ]
const hexes = ["00","01","02","03","04","05","06","07","08","09","0a","0b","0c","0d","0e","0f","10","11","12","13","14","15","16","17","18","19","1a","1b","1c","1d","1e","1f","20","21","22","23","24","25","26","27","28","29","2a","2b","2c","2d","2e","2f","30","31","32","33","34","35","36","37","38","39","3a","3b","3c","3d","3e","3f","40","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f","50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f","60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f","70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f","80","81","82","83","84","85","86","87","88","89","8a","8b","8c","8d","8e","8f","90","91","92","93","94","95","96","97","98","99","9a","9b","9c","9d","9e","9f","a0","a1","a2","a3","a4","a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af","b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba","bb","bc","bd","be","bf","c0","c1","c2","c3","c4","c5","c6","c7","c8","c9","ca","cb","cc","cd","ce","cf","d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db","dc","dd","de","df","e0","e1","e2","e3","e4","e5","e6","e7","e8","e9","ea","eb","ec","ed","ee","ef","f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc","fd","fe","ff"]
const bitcoinSeed = stringToBytes('Bitcoin seed')

// Conversion
const mnemonicToSeed = (mnemonic: string) => pbkdf2(sha512, mnemonic, 'mnemonic', { c: 2048, dkLen: 64 })
function seedToPrivKey(seed: Uint8Array) {
  let I = hmac(sha512, bitcoinSeed, seed);
  let privateKey = bytesToNumber(I.slice(0, 32))
  for (const c of [ "44'", "0'", "0'", "0", "0" ]) {
    const m = /^(\d+)('?)$/.exec(c)!;
    const idx = +m[1]! + (m[2] === "'" ? 0x80000000 : 0);
    I = hmac(sha512, I.slice(32), idx >= 0x80000000 ? concatBytes(new Uint8Array([0]), hexToBytes(privateKey.toString(16).padStart(64, '0')), toU32(idx)) : concatBytes(secp256k1.getPublicKey(privateKey, true), toU32(idx)))
    privateKey = mod(privateKey + bytesToNumber(I.slice(0, 32)), secp256k1.CURVE.n)
  }
  return privateKey.toString(16).padStart(64, '0');
}
const privateKeyToPublicKey = (privateKey: string) => bytesToHex(secp256k1.getPublicKey(privateKey, false)).substring(2)
const publicKeyToAddress = (publicKey: string) => `0x${bytesToHex(keccak_256(hexToBytes(publicKey)))}`.substring(26).toLowerCase()
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

const bestAddress: { phrase: string, length: number } = { phrase: '', length: 0 }
const startTime = +new Date()

while (true) {
  const phrase = generateMnemonic()
  const address = mnemonicToAddress(phrase);
  const firstChar = address[0]
  const lastChar = address[39]
  let length = 0;
  for (let i = 0; i < 40; i++) {
    if (address[i] !== firstChar) break
    length++;
  }
  if (length < bestAddress.length) {
    length = 0
    for (let i = 39; i > 0; i--) {
      if (address[i] !== lastChar) break
      length++;
    }
  }

  if (length >= bestAddress.length) {
    bestAddress.phrase = phrase;
    bestAddress.length = length;

    const runTime = +new Date() - startTime

    console.log('-----')
    console.log('Run Seconds:', Math.round(runTime/1000))
    console.log('Difficulty:', length)
    console.log('Mins Till Next Address:', Math.round((Math.pow(16, length))/(Math.pow(16, length-1)/runTime)/60000))
    console.log('Address:', `0x${address}`);
    console.log('Seed Phrase:', phrase)
    console.log('-----\n')
  }
}
