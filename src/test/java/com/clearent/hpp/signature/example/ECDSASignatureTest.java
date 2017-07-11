package com.clearent.hpp.signature.example;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.PublicKey;

import org.junit.Test;

public class ECDSASignatureTest {


    private String publicKey = "307a301406072a8648ce3d020106092b240303020801010c0362000461ce4bbdb546b4080503d04cf04d43bf542fb19f676dd9e2473a76b31af96509c514932cf5f256eec76a957d2d9bd16d668910e27508dcf04f8ac72dc8ff653b2084668068656e5184d454c39c7cb5c1b215e1179e9759eac864df4fc781f466";
    private String  message = "This is a test.";
    private String  signature = "30650231008418584a5bb66f0875d473deb713d948de9e517c0423b404ea6fcae87d5cb5027d152262167eb2ce6dec8bd53d53ddf90230601533990bfe23cc2849cfd75f54ef0284c2dfafa4abc4b6c5f9f056236d44a144e1233eabb233a27dacfe3632ad6194";

    @Test
    public void signVerifySignatureSimpleMessage(){
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

    @Test
    public void signVerifySignatureTransaction1(){
        publicKey = "307a301406072a8648ce3d020106092b240303020801010c0362000422ffee50bdb73df2698df79b8f62fa06c005acfb5d8e92c3088053620da94eb1f8978c769ace34231b51e41394b873b07a673dfb08e14e975fb26355a639f1be4339e787390ca4c8dd6463c76bc8421457906aafa8b9981445276fde833c136b";
        message = "{\"transaction\":{\"amount\":\"64.50\",\"id\":\"248686\",\"type\":\"SALE\",\"result\":\"APPROVED\",\"card\":\"XXXXXXXXXXXX1111\",\"csc\":\"999\",\"authorization-code\":\"TAS231\",\"batch-string-id\":\"44\",\"display-message\":\"Transaction approved\",\"result-code\":\"000\",\"exp-date\":\"1218\"},\"payloadType\":\"transaction\"}";
        signature = "306402304f070f3cb570f92f573385880aaa58febc06b6842be59e8f56d196c63a5aacbb7124493bee84e0331c36eb9c4e3e27db0230628c89f28a53e4c2ed089abe2ada179cc64e3eb33204b0be07cdd34bd3cd5ed4d6f0aaf380cc0d436faee15509dadc14";
        assertTrue(ECDSASignature.isValid(message, ECDSASignature.convertPublicKey(publicKey), signature));
    }

    @Test
    public void signVerifySignatureTransaction2(){
        publicKey = "307a301406072a8648ce3d020106092b240303020801010c0362000422ffee50bdb73df2698df79b8f62fa06c005acfb5d8e92c3088053620da94eb1f8978c769ace34231b51e41394b873b07a673dfb08e14e975fb26355a639f1be4339e787390ca4c8dd6463c76bc8421457906aafa8b9981445276fde833c136b";
        message = "{\"transaction\":{\"amount\":\"4.50\",\"id\":\"262246\",\"type\":\"SALE\",\"result\":\"APPROVED\",\"card\":\"XXXXXXXXXXXX1111\",\"csc\":\"999\",\"authorization-code\":\"TAS955\",\"batch-string-id\":\"59\",\"display-message\":\"Transaction approved\",\"result-code\":\"000\",\"exp-date\":\"1119\"},\"payloadType\":\"transaction\"}";
        signature = "3064023045786078883501c81dc89e8fe262ea8e1251b9477fee776b567e09839ced2a906c0e327b59e335d2bd2963082b97ef4f02303958b4438c3a7d81e7647a5ae93b98618f18b61281487badfdcfffb3902db5deb9b6a23d0a3dbb33a1305ec31519b6de";
        assertTrue(ECDSASignature.isValid(message, ECDSASignature.convertPublicKey(publicKey), signature));
    }

    @Test
    public void signVerifySignatureTransaction3(){
        publicKey = "307a301406072a8648ce3d020106092b240303020801010c0362000474ce100cfdf0f3e15782c96b41f20522d5660e8474a753722e2b9c0d3a768a068c377b524750dd89163866caad1aba885fd34250d3e122b789499f87f262a0204c6e649617604bcebaa730bf6c2a74cf54a69abf9f6bf7ecfed3e44e463e31fc";
        message = "{\"transaction\":{\"amount\":\"3.50\",\"id\":\"1659915\",\"invoice\":\"carl88888\",\"created\":\"2016-10-25 14:43:44.483\",\"type\":\"SALE\",\"result\":\"APPROVED\",\"billing\":{},\"shipping\":{},\"card\":\"1111\",\"authorization-code\":\"TAS645\",\"original-amount\":\"3.50\",\"entry-method\":\"0\",\"batch-string-id\":\"000377\",\"order-id\":\"1659915\",\"display-message\":\"Transaction approved\",\"result-code\":\"000\",\"billing-is-shipping\":\"false\",\"tip-adjusted\":\"0\",\"exp-date\":\"1119\",\"voided\":\"false\",\"pending\":\"false\",\"voided-auth\":\"false\",\"settled\":\"false\",\"status\":\"Approved\",\"card-type\":\"VISA\"},\"payloadType\":\"transaction\"}";
        signature = "3064023066f69a0a29d4687a387ec3d741d35f1bbe3e1b1d1ed7c0ce8857ec795c5587b85f71e196c77fe00dbadea64566bf6eed02301323e508c68143954d6f5c5e7ec4ba77cb898bab4e2909f92cdcf70218974bf2249a608094f948bb31a53d9718b80816";
        assertTrue(ECDSASignature.isValid(message, ECDSASignature.convertPublicKey(publicKey), signature));
    }

}
