package com.clearent.hpp.signature.example;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.PublicKey;

import org.junit.Test;

public class ECDSASignatureTest {

    private static final String publicKey = "307a301406072a8648ce3d020106092b240303020801010c0362000461ce4bbdb546b4080503d04cf04d43bf542fb19f676dd9e2473a76b31af96509c514932cf5f256eec76a957d2d9bd16d668910e27508dcf04f8ac72dc8ff653b2084668068656e5184d454c39c7cb5c1b215e1179e9759eac864df4fc781f466";
    private static final String  message = "This is a test."; 
    private static final String  signature = "30650231008418584a5bb66f0875d473deb713d948de9e517c0423b404ea6fcae87d5cb5027d152262167eb2ce6dec8bd53d53ddf90230601533990bfe23cc2849cfd75f54ef0284c2dfafa4abc4b6c5f9f056236d44a144e1233eabb233a27dacfe3632ad6194"; 
    
    
    @Test
    public void signVerifySignature(){
        assertTrue(ECDSASignature.isValid(message, ECDSASignature.convertPublicKey(publicKey), signature));
    }
    
    @Test
    public void failWrongMessage(){
        assertFalse(ECDSASignature.isValid("Not the same message", ECDSASignature.convertPublicKey(publicKey), signature));
    }
    
    @Test
    public void failCorruptSignature(){
        assertFalse(ECDSASignature.isValid("Not the same message", ECDSASignature.convertPublicKey(publicKey), signature + "BadStuff"));
    }
    
    @Test (expected=IllegalStateException.class)
    public void failCorruptPublicKey(){
        final PublicKey convertedPublicKey = ECDSASignature.convertPublicKey(publicKey + "BadStuff");
    }
    
}
