const crypto = require('crypto');
const { modPow, egcd, modInverse, sha256ToBigInt, genererFacteurAveuglement  } = require('./maths')

function preparerVote(votantObj, choixVote, pubAdmin) {
  console.log("=== ÉTAPE 1 : PRÉPARATION (Côté Votant) ===");

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
      vote_vi,               // Le choix du candidat (ex: "Candidat_A")
      cleEngagement_ki,      // Cadenas n°2 : clé pour ouvrir l'enveloppe à la fin
      enveloppe_xi,          // L'enveloppe scellée (engagement / bit-commitment)
      facteurAveuglement_ri  // Cadenas n°1 : masque pour désaveugler la signature de l'Admin
    },
    // Ce que le votant envoie à l'Autorité d'enregistrement : <ID_i, e_i, s_i>
    messagePourAdmin: {
      ID_i: votantObj.id,
      enveloppeAveuglee_ei,  // L'enveloppe masquée par r_i
      signatureVotant_si     // La signature d'Alice sur e_i
    }
  };
}


module.exports = { preparerVote};