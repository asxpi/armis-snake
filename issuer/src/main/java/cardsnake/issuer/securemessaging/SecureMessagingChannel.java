package cardsnake.issuer.securemessaging;

import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvBuilder;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import com.payneteasy.tlv.HexUtil;
import cardsnake.issuer.helpers.Bytes;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

import static cardsnake.issuer.CommonAppletConstants.TAG_UNIVERSAL_OCTET_STRING;
import static cardsnake.issuer.CommonAppletConstants.TAG_UNIVERSAL_SEQUENCE;

@Slf4j
@RequiredArgsConstructor
public class SecureMessagingChannel {

    private static final byte PAD_INDICATOR_SM_DATA_EVEN_INS = (byte) 0x01;

    private static final BerTag TAG_SM_DATA_USE_IN_MAC_ODD_INS = new BerTag(0x85);
    private static final BerTag TAG_SM_DATA_USE_IN_MAC_EVEN_INS = new BerTag(0x87);
    private static final BerTag TAG_SM_LE = new BerTag(0x97);
    private static final BerTag TAG_SM_MAC = new BerTag(0x8E);
    private static final BerTag TAG_SM_STATUS_WORD = new BerTag(0x99);

    private static final int AES_KEY_SIZE_IN_BYTES = 256 / 8;

    private static final String ALGORITHM_AES = "AES";
    private static final String ALGORITHM_EC = "EC";
    private static final String ALGORITHM_ECDH = "ECDH";
    private static final String TRANSFORMATION_AES_CBC_ISO7816_4 = "AES/CBC/ISO7816-4Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA384withECDSA";

    @NonNull
    private final SecureMessagingKeyStore secureMessagingKeyStore;
    @NonNull
    private final SecureRandom secureRandom;
    @NonNull
    private final X509Certificate cardHolderCertificate;

    private AsymmetricCipherKeyPair issuerEphemeralKeyPair;
    private SecretKey secretKey;

    public byte[] internalAuthenticate() {
        // TODO Take keyPairCurveType from cardHolderCertificate or issuerPublicKey?
        issuerEphemeralKeyPair = generateKeyPair("secp384r1");

        ECPublicKeyParameters issuerEphemeralPublicKey = (ECPublicKeyParameters) issuerEphemeralKeyPair.getPublic();
        byte[] encodedKey = issuerEphemeralPublicKey.getQ().getEncoded(false);
        // Issuer ephemeral public key + its signature, signed with issuer private key:
        // SEQUENCE ::= {
        //      ecPubPoint OCTET STRING,
        //      ecdsaSignature SEQUENCE ::= { r INTEGER, s INTEGER }
        // }
        return new BerTlvBuilder().addBerTlv(
                new BerTlv(TAG_UNIVERSAL_SEQUENCE, List.of(
                        new BerTlv(TAG_UNIVERSAL_OCTET_STRING, encodedKey),
                        new BerTlvParser().parseConstructed(signWithIssuerPrivateKey(encodedKey))
                ))
        ).buildArray();
    }

    public void parseInternalAuthenticateResponseAndPerformKeyAgreement(byte[] initialResponseFromCard) {
        BerTlv responseTlv;
        try {
            responseTlv = new BerTlvParser().parseConstructed(initialResponseFromCard);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse INTERNAL AUTHENTICATE response", e);
        }

        if (!responseTlv.isTag(TAG_UNIVERSAL_SEQUENCE)) {
            throw new RuntimeException("INTERNAL AUTHENTICATE response is supposed to begin with SEQUENCE tag, but was: "
                    + HexUtil.toHexString(responseTlv.getTag().bytes));
        } else if (responseTlv.getValues().size() != 2) {
            throw new RuntimeException("INTERNAL AUTHENTICATE response SEQUENCE is supposed to have 2 elements, byt was: "
                    + responseTlv.getValues().size());
        }

        BerTlv responsePublicKey = responseTlv.getValues().get(0);
        BerTlv responseSignature = responseTlv.getValues().get(1);

        if (!responsePublicKey.isTag(TAG_UNIVERSAL_OCTET_STRING)) {
            throw new RuntimeException("The first element of INTERNAL AUTHENTICATE response SEQUENCE is supposed to be an OCTET STRING tag, but was: "
                    + HexUtil.toHexString(responseTlv.getTag().bytes));
        } else if (!responseSignature.isTag(TAG_UNIVERSAL_SEQUENCE)) {
            throw new RuntimeException("The second element of INTERNAL AUTHENTICATE response SEQUENCE is supposed to be a SEQUENCE tag, but was: "
                    + HexUtil.toHexString(responseTlv.getTag().bytes));
        }

        byte[] cardHolderEphemeralPublicKeyBytes = responsePublicKey.getBytesValue();
        byte[] cardHolderEphemeralPublicKeySignature = new BerTlvBuilder().addBerTlv(responseSignature).buildArray();

        if (!verifyWithCardHolderCertificate(cardHolderEphemeralPublicKeySignature, cardHolderEphemeralPublicKeyBytes)) {
            throw new RuntimeException("Applet ephemeral public key signature not valid");
        }

        performKeyAgreementAndInitializeSecretKey(cardHolderEphemeralPublicKeyBytes);
    }

    private void performKeyAgreementAndInitializeSecretKey(byte[] cardHolderEphemeralPublicKeyBytes) {
        if (issuerEphemeralKeyPair == null) {
            throw new RuntimeException("internalAuthenticate not performed yet");
        }
        try {
            ECPrivateKeyParameters issuerEphemeralPrivateKeyParameters = (ECPrivateKeyParameters) issuerEphemeralKeyPair.getPrivate();
            java.security.spec.ECParameterSpec ecParameterSpec = EC5Util.convertToSpec(issuerEphemeralPrivateKeyParameters.getParameters());
            java.security.spec.KeySpec privateKeySpec = new java.security.spec.ECPrivateKeySpec(issuerEphemeralPrivateKeyParameters.getD(), ecParameterSpec);
            ECPrivateKey issuerEphemeralPrivateKey = (ECPrivateKey) KeyFactory.getInstance(ALGORITHM_EC, BouncyCastleProvider.PROVIDER_NAME)
                    .generatePrivate(privateKeySpec);

            ECCurve ecCurve = issuerEphemeralPrivateKeyParameters.getParameters().getCurve();
            java.security.spec.ECPoint cardHolderEphemeralPublicKeyPoint = EC5Util.convertPoint(ecCurve.decodePoint(cardHolderEphemeralPublicKeyBytes));
            java.security.spec.KeySpec publicKeySpec = new java.security.spec.ECPublicKeySpec(cardHolderEphemeralPublicKeyPoint, ecParameterSpec);
            ECPublicKey cardHolderEphemeralPublicKey = (ECPublicKey) KeyFactory.getInstance(ALGORITHM_EC, BouncyCastleProvider.PROVIDER_NAME)
                    .generatePublic(publicKeySpec);

            KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM_ECDH);
            keyAgreement.init(issuerEphemeralPrivateKey);
            keyAgreement.doPhase(cardHolderEphemeralPublicKey, true);

            byte[] aesKeyBytes = new byte[AES_KEY_SIZE_IN_BYTES];

            ConcatenationKDFGenerator concatenationKDFGenerator = new ConcatenationKDFGenerator(DigestFactory.createSHA384());
            concatenationKDFGenerator.init(new KDFParameters(keyAgreement.generateSecret(), new byte[0]));
            concatenationKDFGenerator.generateBytes(aesKeyBytes, 0, AES_KEY_SIZE_IN_BYTES);

            secretKey = new SecretKeySpec(aesKeyBytes, ALGORITHM_AES);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to perform key-agreement", e);
        }
    }

    private byte[] signWithIssuerPrivateKey(byte[] dataToSign) {
        PrivateKey issuerPrivateKey = secureMessagingKeyStore.getIssuerPrivateKey();
        try {
            Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            signer.initSign(issuerPrivateKey);
            signer.update(dataToSign);
            return signer.sign();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to generate signature", e);
        }
    }

    private boolean verifyWithCardHolderCertificate(byte[] signature, byte[] signedData) {
        try {
            Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            verifier.initVerify(cardHolderCertificate);

            verifier.update(signedData);
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to verify signature", e);
        }
    }

    public byte[] wrap(byte ins, byte[] commandData, OptionalInt Le) {
        BerTlvBuilder berTlvBuilder = new BerTlvBuilder();

        if (commandData != null && commandData.length > 0) {
            byte[] encryptedData;
            try {
                encryptedData = createCipherFor(Cipher.ENCRYPT_MODE).doFinal(commandData);
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("Failed to encrypt payload", e);
            }
            if ((ins & 1) != 0) { // Odd instruction
                berTlvBuilder.addBerTlv(new BerTlv(TAG_SM_DATA_USE_IN_MAC_ODD_INS, encryptedData));
            } else { // Even instruction
                encryptedData = Arrays.concatenate(Bytes.asArray(PAD_INDICATOR_SM_DATA_EVEN_INS), encryptedData);
                berTlvBuilder.addBerTlv(new BerTlv(TAG_SM_DATA_USE_IN_MAC_EVEN_INS, encryptedData));
            }
        }

        if (Le.isPresent()) {
            byte[] LeBytes = BigInteger.valueOf(Le.getAsInt()).toByteArray();
            berTlvBuilder.addBerTlv(new BerTlv(TAG_SM_LE, LeBytes));
        }

        berTlvBuilder.addBerTlv(new BerTlv(TAG_SM_MAC, new byte[8])); // Signature TODO: implement MAC mechanism

        return berTlvBuilder.buildArray();
    }

    public byte[] unwrap(byte[] responseData, int responseSw) {
        BerTlvs responseDataTlvs;
        try {
            responseDataTlvs = new BerTlvParser().parse(responseData);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse protected response message", e);
        }

        BerTlv statusWordTlv = responseDataTlvs.find(TAG_SM_STATUS_WORD);
        if (statusWordTlv == null) {
            throw new RuntimeException("Status word not found in protected response");

        } else if (statusWordTlv.getIntValue() != responseSw) {
            throw new RuntimeException(String.format(
                    "Status word mismatch - response APDU status word '%d', protected response status word '%d'",
                    responseSw, statusWordTlv.getIntValue()
            ));
        }

        byte[] rawResponseData;
        BerTlv encryptedDataTlv = Optional
                .ofNullable(responseDataTlvs.find(TAG_SM_DATA_USE_IN_MAC_ODD_INS))
                .orElse(responseDataTlvs.find(TAG_SM_DATA_USE_IN_MAC_EVEN_INS));
        if (encryptedDataTlv != null) {
            byte[] encryptedResponseData = encryptedDataTlv.getBytesValue();
            if (encryptedDataTlv.isTag(TAG_SM_DATA_USE_IN_MAC_EVEN_INS)) {
                if (encryptedResponseData.length < 1 || encryptedResponseData[0] != PAD_INDICATOR_SM_DATA_EVEN_INS) {
                    throw new RuntimeException("No padding byte in even instruction response data cryptogram");
                }
                encryptedResponseData = Arrays.copyOfRange(encryptedResponseData, 1, encryptedResponseData.length);
            }
            try {
                rawResponseData = createCipherFor(Cipher.DECRYPT_MODE).doFinal(encryptedResponseData);
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("Failed to decrypt response data cryptogram", e);
            }
        } else {
            rawResponseData = new byte[0];
        }

        BerTlv macTlv = responseDataTlvs.find(TAG_SM_MAC);
        if (macTlv == null) {
            throw new RuntimeException("No MAC found in protected response");
        }
        // TODO: implement MAC mechanism

        return rawResponseData;
    }

    private Cipher createCipherFor(int cipherMode) {
        if (secretKey == null) {
            throw new RuntimeException("Key-agreement not performed yet");
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_AES_CBC_ISO7816_4, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(cipherMode, secretKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));
            return cipher;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to create cipher", e);
        }
    }

    private AsymmetricCipherKeyPair generateKeyPair(String keyPairCurveType) {
        ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec(keyPairCurveType);
        ECDomainParameters domainParameters = new ECNamedDomainParameters(
                ECUtil.getNamedCurveOid(ecParameterSpec),
                ecParameterSpec.getCurve(),
                ecParameterSpec.getG(),
                ecParameterSpec.getN(),
                ecParameterSpec.getH()
        );

        ECKeyGenerationParameters generationParameters = new ECKeyGenerationParameters(domainParameters, secureRandom);
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        keyPairGenerator.init(generationParameters);

        return keyPairGenerator.generateKeyPair();
    }

}
