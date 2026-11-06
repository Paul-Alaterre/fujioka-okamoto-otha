const crypto = require('crypto'); // En navigateur, remplaçable par WebCrypto

// ============================================================================
// 1. OUTILS MATHÉMATIQUES (BigInt) POUR RSA & AVEUGLEMENT DE CHAUM
// ============================================================================

// Exponentiation modulaire rapide : calcule (base^exp) % mod
function modPow(base, exp, mod) {
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) result = (result * base) % mod;
    exp = exp / 2n;
    base = (base * base) % mod;
  }
  return result;
}

// Algorithme d'Euclide étendu : retourne [pgcd, x, y] tels que a*x + b*y = pgcd
function egcd(a, b) {
  if (a === 0n) return [b, 0n, 1n];
  const [g, x1, y1] = egcd(b % a, a);
  return [g, y1 - (b / a) * x1, x1];
}

// Inverse modulaire : trouve r^(-1) mod N (servira au désaveuglement à l'étape 3)
function modInverse(a, m) {
  const [g, x] = egcd(((a % m) + m) % m, m);
  if (g !== 1n) throw new Error("Pas d'inverse modulaire (r et N non premiers entre eux)");
  return ((x % m) + m) % m;
}

// Hash SHA-256 converti en grand entier (BigInt)
function sha256ToBigInt(texte) {
  const hashHex = crypto.createHash('sha256').update(texte, 'utf8').digest('hex');
  return BigInt('0x' + hashHex);
}

// Génère un facteur d'aveuglement aléatoire r_i premier avec N_Admin
function genererFacteurAveuglement(N) {
  while (true) {
    const randomHex = crypto.randomBytes(16).toString('hex');
    const r = BigInt('0x' + randomHex) % N;
    if (r > 1n && egcd(r, N)[0] === 1n) {
      return r;
    }
  }
}

module.exports = { modPow, egcd, modInverse, sha256ToBigInt, genererFacteurAveuglement };