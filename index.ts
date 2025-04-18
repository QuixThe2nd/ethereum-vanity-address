import { sha256 } from '@noble/hashes/sha256'
import { sha512 } from '@noble/hashes/sha512';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { hmac } from '@noble/hashes/hmac';
import { secp256k1 } from '@noble/curves/secp256k1'
import { mod } from '@noble/curves/abstract/modular';
import { keccak_256 } from '@noble/hashes/sha3'
import { wordlist } from '@scure/bip39/wordlists/english';

const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
const powers = [ 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728, 268435456, 536870912, 1073741824, 2147483648, 4294967296, 8589934592, 17179869184, 34359738368, 68719476736, 137438953472, 274877906944, 549755813888 ]
const hexes = ["00","01","02","03","04","05","06","07","08","09","0a","0b","0c","0d","0e","0f","10","11","12","13","14","15","16","17","18","19","1a","1b","1c","1d","1e","1f","20","21","22","23","24","25","26","27","28","29","2a","2b","2c","2d","2e","2f","30","31","32","33","34","35","36","37","38","39","3a","3b","3c","3d","3e","3f","40","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f","50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f","60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f","70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f","80","81","82","83","84","85","86","87","88","89","8a","8b","8c","8d","8e","8f","90","91","92","93","94","95","96","97","98","99","9a","9b","9c","9d","9e","9f","a0","a1","a2","a3","a4","a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af","b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba","bb","bc","bd","be","bf","c0","c1","c2","c3","c4","c5","c6","c7","c8","c9","ca","cb","cc","cd","ce","cf","d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db","dc","dd","de","df","e0","e1","e2","e3","e4","e5","e6","e7","e8","e9","ea","eb","ec","ed","ee","ef","f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc","fd","fe","ff"]

const bytesToHex = (value: Uint8Array) => Array.from(value).map(byte => hexes[byte]).join('')

function asciiToBase16(ch: number) {
  if (ch >= asciis._0 && ch <= asciis._9) return ch - asciis._0;
  if (ch >= asciis.A && ch <= asciis.F) return ch - (asciis.A - 10);
  if (ch >= asciis.a && ch <= asciis.f) return ch - (asciis.a - 10);
  return 0
}

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

function seedToPrivKey(seed: Uint8Array) {
  let I = hmac(sha512, new Uint8Array(new TextEncoder().encode('Bitcoin seed')), seed);
  let privateKey = BigInt(`0x${bytesToHex(I.slice(0, 32))}`)

  for (const c of "m/44'/0'/0'/0/0".replace(/^[mM]'?\//, '').split('/')) {
    const m = /^(\d+)('?)$/.exec(c)!;
    const idx = +m[1]! + (m[2] === "'" ? 0x80000000 : 0);
    I = hmac(sha512, I.slice(32), idx >= 0x80000000 ? concatBytes(new Uint8Array([0]), hexToBytes(privateKey.toString(16).padStart(64, '0')), toU32(idx)) : concatBytes(secp256k1.getPublicKey(privateKey, true), toU32(idx)))
    privateKey = mod(privateKey + BigInt(`0x${bytesToHex(I.slice(0, 32))}`), secp256k1.CURVE.n)
  }
  return `0x${privateKey.toString(16).padStart(64, '0')}`;
}

function mnemonicToAddress(mnemonic: string) {
  const norm = mnemonic.normalize('NFKD');
  const hexAddress = `0x${bytesToHex(keccak_256(hexToBytes(bytesToHex(secp256k1.getPublicKey(seedToPrivKey(pbkdf2(sha512, norm, 'mnemonic', { c: 2048, dkLen: 64 })).slice(2), false)).substring(2))))}`.substring(26).toLowerCase()
  const hash = keccak_256(new TextEncoder().encode(hexAddress))

  const address = hexAddress.split('')
  for (let i = 0; i < 40; i += 2) {
    if (hash[i >> 1]! >> 4 >= 8 && address[i]) address[i] = address[i]!.toUpperCase()
    if ((hash[i >> 1]! & 0x0f) >= 8 && address[i + 1]) address[i + 1] = address[i + 1]!.toUpperCase()
  }
  return `0x${address.join('')}`
}

function convertRadix2(data: number[], from: number, to: number, padding: boolean) {
  let carry = 0;
  let pos = 0;
  const mask = powers[to]! - 1;
  const res: number[] = [];
  for (const n of data) {
    carry = (carry << from) | n;
    pos += from;
    for (; pos >= to; pos -= to) res.push(((carry >> (pos - to)) & mask) >>> 0);
    const pow = powers[pos]!;
    carry &= pow - 1;
  }
  carry = (carry << (to - pos)) & mask;
  if (padding && pos > 0) res.push(carry >>> 0);
  return res;
}

const bestAddress: { phrase: string, length: number } = { phrase: '', length: 0 }
const startTime = +new Date()

while (true) {
  const rand = crypto.getRandomValues(new Uint8Array(16))
  const res = new Uint8Array(17);
  res.set(rand);
  res.set(new Uint8Array([(sha256(rand)[0]! >> 4) << 4]).slice(0, 1), 16);

  const phrase = convertRadix2(Array.from(res), 8, 11, false).map((i) => wordlist[i]!).join(' ')
  
  const address = mnemonicToAddress(phrase).replace('0x', '');
  let length = 0;
  for (let i = 0; i < 40; i++) {
    if (address[i] != '0') break
    length++;
  }

  if (length >= bestAddress.length) {
    bestAddress.phrase = phrase;
    bestAddress.length = length;

    const runTime = +new Date() - startTime

    console.log('-----')
    console.log('Run Seconds:', Math.round(runTime/1000))
    console.log('Difficulty:', length)
    console.log('Mins Till Next Address:', Math.round((Math.pow(16, length+1))/(Math.pow(16, length)/runTime)/60000))
    console.log('Address:', `0x${address}`);
    console.log('Seed Phrase:', phrase)
    console.log('-----\n')
  }
}
