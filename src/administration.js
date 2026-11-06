const { sha256ToBigInt, modPow  } = require('./maths')

// ============================================================================
// ÉTAPE 2 : ADMINISTRATION (Vérifications, blocages des fraudes et signature)
// ============================================================================

function administrerDemandeVote(admin, requete) {
  const { ID_i, enveloppeAveuglee_ei, signatureVotant_si } = requete;
  console.log(`\n=== ÉTAPE 2 : ADMINISTRATION (Requête reçue de ${ID_i}) ===`);

  // --------------------------------------------------------------------------
  // POINT DE BLOCAGE 1 : Vérification du droit de vote (Eligibility)
  // --------------------------------------------------------------------------
  if (!admin.listeElectorale.has(ID_i)) {
    console.log(`❌ [BLOCAGE PROTOCOLE - Éligibilité] : "${ID_i}" n'est pas inscrit sur la liste électorale.`);
    return {
      succes: false,
      etapeBlocage: "VERIFICATION_DROIT_DE_VOTE",
      raison: `L'identifiant ${ID_i} n'a pas le droit de voter.`
    };
  }

  // --------------------------------------------------------------------------
  // POINT DE BLOCAGE 2 : Vérification du double vote (Unreusability)
  // --------------------------------------------------------------------------
  if (admin.registreEmargement.has(ID_i)) {
    console.log(`❌ [BLOCAGE PROTOCOLE - Double Vote] : "${ID_i}" a DÉJÀ obtenu un certificat d'émargement !`);
    return {
      succes: false,
      etapeBlocage: "VERIFICATION_DEJA_VOTE",
      raison: `Le votant ${ID_i} tente de faire signer un deuxième bulletin.`
    };
  }

  // --------------------------------------------------------------------------
  // POINT DE BLOCAGE 3 : Vérification de la signature du votant (Anti-usurpation)
  // --------------------------------------------------------------------------
  const clePubVotant = admin.listeElectorale.get(ID_i);
  const hashAttendu = sha256ToBigInt(enveloppeAveuglee_ei.toString()) % clePubVotant.N;
  const hashVerifie = modPow(signatureVotant_si, clePubVotant.e, clePubVotant.N);

  if (hashAttendu !== hashVerifie) {
    console.log(`❌ [BLOCAGE PROTOCOLE - Usurpation d'identité] : Signature s_i invalide pour "${ID_i}".`);
    return {
      succes: false,
      etapeBlocage: "VERIFICATION_SIGNATURE_VOTANT",
      raison: `La signature s_i ne correspond pas à la clé publique de ${ID_i}.`
    };
  }

  // --------------------------------------------------------------------------
  // TOUT EST VALIDE : Signature à l'aveugle par l'Administrateur
  // certificatAdmin_di = sigma_A(e_i) = (e_i ^ d_A) mod N_A
  // --------------------------------------------------------------------------
  const certificatAdmin_di = modPow(enveloppeAveuglee_ei, admin.clePrivee.d, admin.clePrivee.N);

  // Enregistrement dans la liste publique d'émargement
  admin.registreEmargement.set(ID_i, {
    ID_i,
    enveloppeAveuglee_ei,
    signatureVotant_si
  });

  console.log(`✅ [SUCCÈS] : ${ID_i} est authentifié et autorisé. Certificat d_i généré.`);

  return {
    succes: true,
    certificatAdmin_di: certificatAdmin_di
  };
}

// Fonction de fin de phase d'Administration : publication de la liste officielle
function publierRegistreAdministration(admin) {
  console.log("\n📢 [PUBLICATION OFFICIELLE DE L'ADMINISTRATEUR] :");
  console.log(`Nombre de votants ayant obtenu une signature : ${admin.registreEmargement.size}`);
  return {
    nombreVotantsCertifies: admin.registreEmargement.size,
    listePubliqueEmargement: Array.from(admin.registreEmargement.values())
  };
}


module.exports = { administrerDemandeVote};