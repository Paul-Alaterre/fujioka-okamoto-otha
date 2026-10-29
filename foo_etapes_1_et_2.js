const crypto = require('crypto'); // En navigateur, remplaçable par WebCrypto

// ============================================================================
// PARTIE 1 : LE CODE DU PROTOCOLE FOO (Outils, Acteurs, Étapes 1 & 2)
// ============================================================================

// --- 1.1 OUTILS MATHÉMATIQUES (BigInt) POUR RSA & AVEUGLEMENT DE CHAUM ---

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

// --- 1.2 CONFIGURATION DES CLÉS ET DES ACTEURS (Admin A et Votant V_i) ---

// Clé RSA de l'Autorité d'enregistrement (Administrateur A)
const P_ADMIN = 170141183460469231731687303715884105727n;
const Q_ADMIN = 20988936657440586486151264256610222593863921n;
const N_ADMIN = P_ADMIN * Q_ADMIN;
const PHI_ADMIN = (P_ADMIN - 1n) * (Q_ADMIN - 1n);
const E_ADMIN = 65537n;
const D_ADMIN = modInverse(E_ADMIN, PHI_ADMIN);

// Clé RSA du Votant V_i (Alice)
const P_VOTANT = 618970019642690137449562111n;
const Q_VOTANT = 162259276829213363391578010288127n;
const N_VOTANT = P_VOTANT * Q_VOTANT;
const PHI_VOTANT = (P_VOTANT - 1n) * (Q_VOTANT - 1n);
const E_VOTANT = 65537n;
const D_VOTANT = modInverse(E_VOTANT, PHI_VOTANT);

// Objet Votant (Alice)
const votantAlice = {
  id: "Votant_Alice_01",
  clePublique: { e: E_VOTANT, N: N_VOTANT },
  clePrivee: { d: D_VOTANT, N: N_VOTANT }
};

// Objet Autorité d'enregistrement (Administrateur A)
const autoriteEnregistrement = {
  clePublique: { e: E_ADMIN, N: N_ADMIN },
  clePrivee: { d: D_ADMIN, N: N_ADMIN },

  // Annuaire officiel des électeurs autorisés (ID -> Clé publique du votant)
  listeElectorale: new Map([
    ["Votant_Alice_01", { e: E_VOTANT, N: N_VOTANT }],
    ["Votant_Bob_02",   { e: E_VOTANT, N: N_VOTANT }]
  ]),

  // Registre public d'émargement : stocke qui a déjà reçu sa signature
  registreEmargement: new Map()
};

// --- 1.3 ÉTAPE 1 : PRÉPARATION DU VOTE PAR LE VOTANT (FOO - PREPARATION) ---

function preparerVote(votantObj, choixVote, pubAdmin) {
  // 1. Choix du vote (vote_vi) et génération de la clé secrète d'engagement (cleEngagement_ki)
  const vote_vi = choixVote;
  const cleEngagement_ki = "cle_secrete_" + crypto.randomBytes(8).toString('hex');

  // 2. Création de l'enveloppe / Engagement : enveloppe_xi = xi(vote_vi, cleEngagement_ki)
  const payloadEngagement = JSON.stringify({ vote: vote_vi, cle: cleEngagement_ki });
  const enveloppe_xi = sha256ToBigInt(payloadEngagement) % pubAdmin.N;

  // 3. Aveuglement : enveloppeAveuglee_ei = chi(enveloppe_xi, facteurAveuglement_ri)
  // Formule RSA : e_i = (x_i * (r_i ^ e_Admin)) mod N_Admin
  const facteurAveuglement_ri = genererFacteurAveuglement(pubAdmin.N);
  const r_puissance_e = modPow(facteurAveuglement_ri, pubAdmin.e, pubAdmin.N);
  const enveloppeAveuglee_ei = (enveloppe_xi * r_puissance_e) % pubAdmin.N;

  // 4. Signature de l'objet aveuglé par le votant : signatureVotant_si = sigma_i(enveloppeAveuglee_ei)
  const hash_ei = sha256ToBigInt(enveloppeAveuglee_ei.toString()) % votantObj.clePrivee.N;
  const signatureVotant_si = modPow(hash_ei, votantObj.clePrivee.d, votantObj.clePrivee.N);

  return {
    // Ce que le votant garde en mémoire locale (STRICTEMENT SECRET)
    secretsDuVotant: {
      vote_vi,               // Le choix du candidat
      cleEngagement_ki,      // Cadenas n°2 : clé pour ouvrir l'enveloppe à la fin
      enveloppe_xi,          // L'enveloppe scellée (engagement / bit-commitment)
      facteurAveuglement_ri  // Cadenas n°1 : masque pour désaveugler la signature de l'Admin
    },
    // Ce que le votant envoie à l'Autorité d'enregistrement : <ID_i, e_i, s_i>
    messagePourAdmin: {
      ID_i: votantObj.id,
      enveloppeAveuglee_ei,  // L'enveloppe masquée par r_i
      signatureVotant_si     // La signature du votant sur e_i
    }
  };
}

// --- 1.4 ÉTAPE 2 : ADMINISTRATION (Vérifications, blocages et signature) ---

function administrerDemandeVote(admin, requete) {
  const { ID_i, enveloppeAveuglee_ei, signatureVotant_si } = requete;

  // POINT DE BLOCAGE 1 : Vérification du droit de vote (Eligibility)
  if (!admin.listeElectorale.has(ID_i)) {
    return {
      succes: false,
      etapeBlocage: "VERIFICATION_DROIT_DE_VOTE",
      raison: `L'identifiant "${ID_i}" n'est pas inscrit sur la liste électorale.`
    };
  }

  // POINT DE BLOCAGE 2 : Vérification du double vote (Unreusability)
  if (admin.registreEmargement.has(ID_i)) {
    return {
      succes: false,
      etapeBlocage: "VERIFICATION_DEJA_VOTE",
      raison: `Le votant "${ID_i}" a DÉJÀ obtenu un certificat d'émargement.`
    };
  }

  // POINT DE BLOCAGE 3 : Vérification de la signature du votant (Anti-usurpation)
  const clePubVotant = admin.listeElectorale.get(ID_i);
  const hashAttendu = sha256ToBigInt(enveloppeAveuglee_ei.toString()) % clePubVotant.N;
  const hashVerifie = modPow(signatureVotant_si, clePubVotant.e, clePubVotant.N);

  if (hashAttendu !== hashVerifie) {
    return {
      succes: false,
      etapeBlocage: "VERIFICATION_SIGNATURE_VOTANT",
      raison: `La signature s_i ne correspond pas à la clé publique de "${ID_i}".`
    };
  }

  // TOUT EST VALIDE : Signature à l'aveugle par l'Administrateur
  // certificatAdmin_di = sigma_A(e_i) = (e_i ^ d_A) mod N_A
  const certificatAdmin_di = modPow(enveloppeAveuglee_ei, admin.clePrivee.d, admin.clePrivee.N);

  // Enregistrement dans la liste publique d'émargement
  admin.registreEmargement.set(ID_i, {
    ID_i,
    enveloppeAveuglee_ei,
    signatureVotant_si
  });

  return {
    succes: true,
    certificatAdmin_di: certificatAdmin_di
  };
}

// Publication officielle du registre à la fin de la phase d'Administration
function publierRegistreAdministration(admin) {
  return {
    nombreVotantsCertifies: admin.registreEmargement.size,
    listePubliqueEmargement: Array.from(admin.registreEmargement.values())
  };
}


// ============================================================================
// PARTIE 2 : LES TESTS ET SCÉNARIOS DE DÉMONSTRATION (Normal + Fraudes)
// ============================================================================

console.log("==================================================================");
console.log("   DÉMONSTRATEUR FOO - TESTS DES ÉTAPES 1 (PRÉP) & 2 (ADMIN)");
console.log("==================================================================\n");

// --- TEST 1 : Parcours légitime d'Alice (Préparation + Administration) ---
console.log("--- [TEST 1] : Parcours normal d'Alice (Votante autorisée) ---");
const prepAlice = preparerVote(votantAlice, "Candidat_A", autoriteEnregistrement.clePublique);

console.log("1. Préparation par Alice terminée :");
console.log("   - [Secret local] vote_vi               :", prepAlice.secretsDuVotant.vote_vi);
console.log("   - [Secret local] cleEngagement_ki      :", prepAlice.secretsDuVotant.cleEngagement_ki);
console.log("   - [Secret local] enveloppe_xi          :", prepAlice.secretsDuVotant.enveloppe_xi.toString().slice(0, 25) + "...");
console.log("   - [Secret local] facteurAveuglement_ri :", prepAlice.secretsDuVotant.facteurAveuglement_ri.toString().slice(0, 25) + "...");
console.log("   - [Envoyé Admin] enveloppeAveuglee_ei  :", prepAlice.messagePourAdmin.enveloppeAveuglee_ei.toString().slice(0, 25) + "...");

const reponseAdminAlice = administrerDemandeVote(autoriteEnregistrement, prepAlice.messagePourAdmin);
console.log("2. Réponse de l'Administrateur :", reponseAdminAlice.succes ? "✅ SUCCÈS" : "❌ ÉCHEC");
console.log("   - Certificat reçu (certificatAdmin_di) :", reponseAdminAlice.certificatAdmin_di.toString().slice(0, 25) + "...\n");

// --- TEST 2 : Tentative de vote par un intrus non inscrit ---
console.log("--- [TEST 2] : Tentative de vote sans autorisation (Intrus) ---");
const requeteIntrus = {
  ID_i: "Intrus_Mallory_99",
  enveloppeAveuglee_ei: prepAlice.messagePourAdmin.enveloppeAveuglee_ei,
  signatureVotant_si: prepAlice.messagePourAdmin.signatureVotant_si
};
const reponseIntrus = administrerDemandeVote(autoriteEnregistrement, requeteIntrus);
console.log("   - Résultat      :", reponseIntrus.succes ? "✅ SUCCÈS" : "❌ BLOQUÉ");
console.log("   - Point précis  :", reponseIntrus.etapeBlocage);
console.log("   - Raison        :", reponseIntrus.raison + "\n");

// --- TEST 3 : Tentative d'usurpation d'identité d'un électeur inscrit (Bob) ---
console.log("--- [TEST 3] : Tentative d'usurpation de l'identité de Bob ---");
const requeteUsurpationBob = {
  ID_i: "Votant_Bob_02",
  enveloppeAveuglee_ei: prepAlice.messagePourAdmin.enveloppeAveuglee_ei,
  signatureVotant_si: 9876543210123456789n // Fausse signature (le pirate n'a pas la clé privée de Bob)
};
const reponseUsurpation = administrerDemandeVote(autoriteEnregistrement, requeteUsurpationBob);
console.log("   - Résultat      :", reponseUsurpation.succes ? "✅ SUCCÈS" : "❌ BLOQUÉ");
console.log("   - Point précis  :", reponseUsurpation.etapeBlocage);
console.log("   - Raison        :", reponseUsurpation.raison + "\n");

// --- TEST 4 : Tentative de double vote par Alice ---
console.log("--- [TEST 4] : Alice tente de faire signer un 2e bulletin ---");
const deuxiemePrepAlice = preparerVote(votantAlice, "Candidat_B", autoriteEnregistrement.clePublique);
const reponseDoubleVote = administrerDemandeVote(autoriteEnregistrement, deuxiemePrepAlice.messagePourAdmin);
console.log("   - Résultat      :", reponseDoubleVote.succes ? "✅ SUCCÈS" : "❌ BLOQUÉ");
console.log("   - Point précis  :", reponseDoubleVote.etapeBlocage);
console.log("   - Raison        :", reponseDoubleVote.raison + "\n");

// --- BILAN DE FIN D'ADMINISTRATION ---
const publicationAdmin = publierRegistreAdministration(autoriteEnregistrement);
console.log("--- [BILAN FIN D'ADMINISTRATION] ---");
console.log("   - Nombre de votants certifiés :", publicationAdmin.nombreVotantsCertifies);
console.log("   - Électeurs ayant émargé      :", publicationAdmin.listePubliqueEmargement.map(e => e.ID_i).join(", "));
