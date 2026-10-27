// Protocole FOO (Fujioka-Okamoto-Ohta) : phase de préparation, côté votant
// Node.js >= 18, aucune dépendance externe.
import { randomBytes, createHash, generateKeyPairSync, sign, verify } from 'node:crypto';

/* ---------- Utilitaires BigInt ---------- */

const bufToBig = (buf) => BigInt('0x' + buf.toString('hex'));
const b64uToBig = (s) => bufToBig(Buffer.from(s, 'base64url'));
const sha256 = (data) => createHash('sha256').update(data).digest();

function modPow(base, exp, mod) {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

function gcd(a, b) {
  while (b) [a, b] = [b, a % b];
  return a;
}

// Inverse modulaire par Euclide étendu
function modInv(a, m) {
  let [oldR, r] = [a % m, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error('pas inversible');
  return ((oldS % m) + m) % m;
}

// Entier aléatoire dans [2, n-1]
function randomBelow(n) {
  const bytes = Math.ceil(n.toString(16).length / 2) + 8; // marge pour limiter le biais
  return (bufToBig(randomBytes(bytes)) % (n - 2n)) + 2n;
}

/* ---------- Primitives du protocole ---------- */

// Étape 2 : engagement  x = H(k || v)
function commit(vote) {
  const k = randomBytes(32); // aléa d'engagement, à garder pour l'ouverture
  const x = sha256(Buffer.concat([k, Buffer.from(vote)]));
  return { x, k };
}

// Étape 3 : aveuglement RSA  e = m * r^E mod N, où m = H(x)
// (m est le "message" que l'administrateur signera à l'aveugle)
function blind(x, adminPub) {
  const { N, E } = adminPub;
  const m = bufToBig(sha256(x)); // hash court pour la démo, voir note plus bas
  let r;
  do { r = randomBelow(N); } while (gcd(r, N) !== 1n);
  const e = (m * modPow(r, E, N)) % N;
  return { e, r, m };
}

// Étape 4 : le votant signe e avec sa propre clé (ici Ed25519)
function signBlinded(e, voterPrivateKey) {
  return sign(null, Buffer.from(e.toString(16)), voterPrivateKey);
}

/* ---------- Phase de préparation complète (votant) ---------- */

function prepareBallot({ vote, voterId, voterPrivateKey, adminPub }) {
  const { x, k } = commit(vote);                       // étape 2
  const { e, r, m } = blind(x, adminPub);              // étape 3
  const s = signBlinded(e, voterPrivateKey);           // étape 4
  const request = { voterId, e: e.toString(16), s: s.toString('hex') }; // étape 5

  // `secret` reste chez le votant, seule `request` est envoyée
  return { request, secret: { vote, k, x, r, m } };
}

/* ---------- Démo : on simule aussi l'administrateur ---------- */

// Clés de l'administrateur (RSA 2048)
const adminKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = adminKeys.privateKey.export({ format: 'jwk' });
const adminPub = { N: b64uToBig(jwk.n), E: b64uToBig(jwk.e) };
const adminD = b64uToBig(jwk.d);

// Clés du votant (signature classique)
const voter = generateKeyPairSync('ed25519');

// Le votant prépare son bulletin
const { request, secret } = prepareBallot({
  vote: 'candidat A',
  voterId: 'alice',
  voterPrivateKey: voter.privateKey,
  adminPub,
});
console.log('Envoyé à l\'administrateur :', {
  voterId: request.voterId,
  e: request.e.slice(0, 24) + '...',
  s: request.s.slice(0, 24) + '...',
});

// --- Côté administrateur : vérifie la signature du votant, puis signe à l'aveugle
const sigOk = verify(null, Buffer.from(request.e), voter.publicKey, Buffer.from(request.s, 'hex'));
console.log('Signature du votant valide :', sigOk);
const eBig = BigInt('0x' + request.e);
const blindSig = modPow(eBig, adminD, adminPub.N);

// --- Retour côté votant : retire l'aveuglement (hors périmètre de la préparation,
// mais utile pour vérifier que tout fonctionne)
const y = (blindSig * modInv(secret.r, adminPub.N)) % adminPub.N;
const valid = modPow(y, adminPub.E, adminPub.N) === secret.m;
console.log('Signature de l\'administrateur sur x valide :', valid);

/* Note : en vrai, il faut un hachage "full-domain" (FDH) ou RSABSSA (RFC 9474)
   pour que m couvre tout l'espace [0, N), sinon la sécurité de la signature
   RSA "nue" est affaiblie. Ici on garde SHA-256 pour la lisibilité. */
