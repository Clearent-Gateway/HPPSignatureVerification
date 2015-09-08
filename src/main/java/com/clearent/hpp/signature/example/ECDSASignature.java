package com.clearent.hpp.signature.example;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ECDSASignature {

    private static final String BOUNCY_CASTLE_SECURITY_PROVIDER = "BC";
    private static final String ELLIPTICAL_CURVE_DIGITAL_SIGNATURE_ALG = "ECDSA";
    private static final String SIGNATURE_ALG = "SHA384withECDSA";

    private static final Logger LOGGER = LoggerFactory.getLogger(ECDSASignature.class);

    private static final String INVALID_KEY_SPEC_OR_ALGORITH_MESSAGE = "InvalidKeySpec or Algorithm";
    private static final String DECODER_ERROR_MESSAGE = "Decoding Failure";
    private static final String SIGNATURE_ERROR_MESSAGE = "Invalid Key or Signature";

    private ECDSASignature(){}

    public static boolean isValid(String message, PublicKey publicKey, String signature) {
        Signature sig;
        boolean isValidSignature = false;
        try {
            sig = Signature.getInstance(SIGNATURE_ALG, BOUNCY_CASTLE_SECURITY_PROVIDER);
            sig.initVerify(publicKey);
            sig.update(message.getBytes());
            isValidSignature = sig.verify(Hex.decodeHex(signature.toCharArray()));
        } catch (NoSuchAlgorithmException | NoSuchProviderException ae) {
            handleSecuriyException(ae);
        } catch (InvalidKeyException | SignatureException se) {
            LOGGER.error(SIGNATURE_ERROR_MESSAGE, se);
            isValidSignature = false;
        } catch (DecoderException de) {
            LOGGER.error(DECODER_ERROR_MESSAGE, de);
            isValidSignature = false;
        }
        return isValidSignature;
    }

    public static PublicKey convertPublicKey(String publicKey) {
        PublicKey pubKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance(ELLIPTICAL_CURVE_DIGITAL_SIGNATURE_ALG);
            pubKey = kf.generatePublic(new X509EncodedKeySpec(Hex.decodeHex(publicKey.toCharArray())));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException ae) {
            handleSecuriyException(ae);
        } catch (DecoderException de) {
            handleDecoderException(de);
        }
        return pubKey;
    }

    private static void handleDecoderException(DecoderException de) {
        LOGGER.error(DECODER_ERROR_MESSAGE, de);
        throw new IllegalStateException(DECODER_ERROR_MESSAGE, de);
    }

    private static void handleSecuriyException(GeneralSecurityException ae) {
        LOGGER.error(INVALID_KEY_SPEC_OR_ALGORITH_MESSAGE, ae);
        throw new IllegalStateException(INVALID_KEY_SPEC_OR_ALGORITH_MESSAGE, ae);
    }

    private static void handleSignatureException(GeneralSecurityException se) {
        LOGGER.error(SIGNATURE_ERROR_MESSAGE, se);
        throw new IllegalStateException(SIGNATURE_ERROR_MESSAGE, se);
    }
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

}
