const { modPow, egcd, modInverse, sha256ToBigInt, genererFacteurAveuglement  } = require('./maths')
const { preparerVote  } = require('./preparation');
const { administrerDemandeVote  } = require('./administration');

// Clé RSA de l'Autorité d'enregistrement (Administrateur A)
const P_ADMIN = 170141183460469231731687303715884105727n;
const Q_ADMIN = 20988936657440586486151264256610222593863921n;
const N_ADMIN = P_ADMIN * Q_ADMIN;
const PHI_ADMIN = (P_ADMIN - 1n) * (Q_ADMIN - 1n);
const E_ADMIN = 65537n;
const D_ADMIN = modInverse(E_ADMIN, PHI_ADMIN);

const clePubliqueAdmin = { e: E_ADMIN, N: N_ADMIN };

// Clé RSA du Votant V_i (pour signer sa demande s_i = sigma_i(e_i))
const P_VOTANT = 618970019642690137449562111n;
const Q_VOTANT = 162259276829213363391578010288127n;
const N_VOTANT = P_VOTANT * Q_VOTANT;
const PHI_VOTANT = (P_VOTANT - 1n) * (Q_VOTANT - 1n);
const E_VOTANT = 65537n;
const D_VOTANT = modInverse(E_VOTANT, PHI_VOTANT);

const votant = {
  id: "Votant_Alice_01",
  clePublique: { e: E_VOTANT, N: N_VOTANT },
  clePrivee: { d: D_VOTANT, N: N_VOTANT }
};

const autoriteEnregistrement = {
  clePublique: { e: E_ADMIN, N: N_ADMIN },
  clePrivee: { d: D_ADMIN, N: N_ADMIN },

  // Annuaire officiel des électeurs autorisés (ID -> Clé publique du votant)
  listeElectorale: new Map([
    ["Votant_Alice_01", { e: E_VOTANT, N: N_VOTANT }]
    // "Intrus_ Mallory_99" n'est PAS dans cette liste
  ]),

  // Registre public d'émargement : stocke qui a déjà reçu sa signature
  // Contient les entrées { ID_i, enveloppeAveuglee_ei, signatureVotant_si }
  registreEmargement: new Map()
};

// ============================================================================
// TEST D'EXÉCUTION DE L'ÉTAPE 1
// ============================================================================


const prepAlice = preparerVote(votant, "Candidat_A", clePubliqueAdmin);

console.log("\n🔒 [SECRETS DU VOTANT - Restent dans le navigateur d'Alice] :");
console.log("  vote_vi               :", prepAlice.secretsDuVotant.vote_vi);
console.log("  cleEngagement_ki      :", prepAlice.secretsDuVotant.cleEngagement_ki);
console.log("  enveloppe_xi          :", prepAlice.secretsDuVotant.enveloppe_xi.toString());
console.log("  facteurAveuglement_ri :", prepAlice.secretsDuVotant.facteurAveuglement_ri.toString());

console.log("\n📤 [MESSAGE ENVOYÉ À L'ADMIN - Paquet <ID_i, e_i, s_i>] :");
console.log("  ID_i                  :", prepAlice.messagePourAdmin.ID_i);
console.log("  enveloppeAveuglee_ei  :", prepAlice.messagePourAdmin.enveloppeAveuglee_ei.toString());
console.log("  signatureVotant_si    :", prepAlice.messagePourAdmin.signatureVotant_si.toString());

// ============================================================================
// CAS POUR TEST DE L'ETAPE 2
// ============================================================================

const reponseAdminAlice = administrerDemandeVote(autoriteEnregistrement, {
  ID_i: prepAlice.messagePourAdmin.ID_i,
  enveloppeAveuglee_ei: prepAlice.messagePourAdmin.enveloppeAveuglee_ei,
  signatureVotant_si: prepAlice.messagePourAdmin.signatureVotant_si
});
// -> ✅ Passe ! Alice reçoit reponseAdminAlice.certificatAdmin_di

// --- CAS 2 (FRAUDE) : Tentative de voter sans autorisation (Intrus non inscrit) ---
const reponseIntrus = administrerDemandeVote(autoriteEnregistrement, {
  ID_i: "Intrus_Mallory_99",
  enveloppeAveuglee_ei: prepAlice.messagePourAdmin.enveloppeAveuglee_ei,
  signatureVotant_si: prepAlice.messagePourAdmin.signatureVotant_si 
});
// -> ❌ Bloqué à l'étape "VERIFICATION_DROIT_DE_VOTE"

// --- CAS 3 (FRAUDE) : Tentative d'usurper l'identité d'un inscrit sans sa clé privée ---
// Supposons que Bob soit inscrit mais qu'un pirate envoie une fausse signature s_i = 12345n
autoriteEnregistrement.listeElectorale.set("Votant_Bob_02", { e: E_VOTANT, N: N_VOTANT });
const reponseUsurpation = administrerDemandeVote(autoriteEnregistrement, {
  ID_i: "Votant_Bob_02",
  enveloppeAveuglee_ei: prepAlice.messagePourAdmin.enveloppeAveuglee_ei,
  signatureVotant_si: 123456789n // Fausse signature !
});
// -> ❌ Bloqué à l'étape "VERIFICATION_SIGNATURE_VOTANT"

// --- CAS 4 (FRAUDE) : Alice tente de voter une deuxième fois ! ---
const deuxiemePrepAlice = preparerVote(votant, "Candidat_B", autoriteEnregistrement.clePublique);
const reponseDoubleVote = administrerDemandeVote(autoriteEnregistrement, {
  ID_i: deuxiemePrepAlice.messagePourAdmin.ID_i,
  enveloppeAveuglee_ei: deuxiemePrepAlice.messagePourAdmin.enveloppeAveuglee_ei,
  signatureVotant_si: deuxiemePrepAlice.messagePourAdmin.signatureVotant_si
});
// -> ❌ Bloqué à l'étape "VERIFICATION_DEJA_VOTE"