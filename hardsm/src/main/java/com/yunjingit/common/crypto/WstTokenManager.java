package com.yunjingit.common.crypto;

import com.yunjingit.common.HardSM;
import com.yunjingit.common.HardSMImpl;
import com.yunjingit.common.SMException;
import com.yunjingit.common.Sm;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;


public class WstTokenManager {

     int deviceCount;
     private int maxThreads;
     HardSM hardSM;

    public void initResource(String password, int threads) throws SMException {
        hardSM = new HardSMImpl();
        hardSM.apiInit();
        Sm.CtxInfo ctxInfo = hardSM.apiCtxInfo();
        deviceCount = ctxInfo.getDeviceCount();
        for (int i = 0; i < deviceCount; i++) {
            hardSM.apiLoginDevicePipe(i, password,threads);
        }
        printDeviceStatus();
        maxThreads = threads;
        return ;
    }

    @Override
    public void finalize() {

        try {
            printDeviceStatus();
            for (int i = 0; i < deviceCount; i++) {
                hardSM.apiLogoutDevice(i);
            }
            hardSM.apiFinal();
        } catch (Exception e) {
           e.printStackTrace();
        }

        return ;
    }

    private  int printDeviceStatus() throws SMException {
        int freepipes=0;
        for (int i = 0; i < deviceCount; i++) {
            Sm.DevStatus devStatus = hardSM.apiDeviceStatus(i);
            System.out.println("index: " + devStatus.getIndex());
            System.out.println("opened: " + devStatus.getOpened());
            System.out.println("logged_in: " + devStatus.getLoggedIn());
            System.out.println("pipes_count: " + devStatus.getPipesCount());
            System.out.println("free_pipes_count: " + devStatus.getFreePipesCount());
            System.out.println("secret_key_count: " + devStatus.getSecretKeyCount());
            System.out.println("public_key_count: " + devStatus.getPublicKeyCount());
            System.out.println("private_key_count: " + devStatus.getPrivateKeyCount());
            freepipes = freepipes + devStatus.getFreePipesCount();
        }
        return freepipes;
    }


    private int getDeviceIndex() {
        if (deviceCount > 0) {
            return (int) (Math.abs(getThreadId()) % deviceCount);
        } else {
            return 0;
        }
    }

    private int getPipeIndex() {
        if (deviceCount > 0) {
            return (int) (getThreadId() % maxThreads / deviceCount);
        } else  {
            return 0;
        }
    }

    private long getThreadId() {
        return Thread.currentThread().getId();
    }

    public byte[] getRandom(int length) throws  WstTokenException{
        try {
            int deviceindex = getDeviceIndex();
            int pipeindex = getPipeIndex();
            String s = hardSM.apiRandom(deviceindex, pipeindex,length);
            return ByteUtils.fromHexString(s);
        } catch (Exception e) {
            throw new WstTokenException(e);
        }
    }

    public Sm.KeyPair apiGenerateKeyPair() throws  WstTokenException{
        try {
            int deviceindex = getDeviceIndex();
            int pipeindex = getPipeIndex();
            Sm.KeyPair kp = hardSM.apiGenerateKeyPair(deviceindex, pipeindex);
            return kp;
        } catch (Exception e) {
            throw new WstTokenException(e);
        }
    }

    public String apiGenerateKey() throws  WstTokenException{
        try {
            int deviceindex = getDeviceIndex();
            int pipeindex = getPipeIndex();
            String kp = hardSM.apiGenerateKey(deviceindex, pipeindex);
            return kp;
        } catch (Exception e) {
            throw new WstTokenException(e);
        }
    }

    public String apiDigest( byte[] data) throws WstTokenException {
        try {
            int deviceindex = getDeviceIndex();
            int pipeindex = getPipeIndex();
            String digest = hardSM.apiDigest(deviceindex,pipeindex,data);
            return digest;
        } catch (Exception e) {
            throw new WstTokenException(e);
        }
    }

    public String apiSign(String privateKey, String hexData)
            throws WstTokenException {
        try {
            int deviceindex = getDeviceIndex();
            int pipeindex = getPipeIndex();
            return hardSM.apiSign(deviceindex,pipeindex,privateKey,hexData);

        } catch (Exception e) {
            throw new WstTokenException(e);
        }
    }


    public int apiVerify(String publicKey, String hexData, String signature)
            throws WstTokenException {
        try {
            int deviceindex = getDeviceIndex();
            int pipeindex = getPipeIndex();
            return hardSM.apiVerify(deviceindex,pipeindex,publicKey, hexData, signature);

        } catch (Exception e) {
            throw new WstTokenException(e);
        }
    }

    private  X9ECParameters ecParams = CustomNamedCurves.getByName("sm2p256v1");
    private  byte[] A = ecParams.getCurve().getA().getEncoded();
    private  byte[] B = ecParams.getCurve().getB().getEncoded();
    private  byte[] GX = ecParams.getG().getAffineXCoord().getEncoded();
    private  byte[] GY = ecParams.getG().getAffineYCoord().getEncoded();

    private static byte[] userID = Hex.decode("31323334353637383132333435363738");

    public byte[] sm2Sign(byte[] data, String privkey, String pubkey){
        byte[] z = getZ(userID,pubkey);
        byte[] indata = new byte[z.length + data.length];
        System.arraycopy(z,0,indata,0,z.length);
        System.arraycopy(data,0,indata,z.length,data.length);
        String s = apiDigest(indata);
        String sigHex = apiSign(privkey,s);
        return translateSigToRS(sigHex);
    }

    public boolean sm2Verify(byte[] data, byte[] sig,String pubkey){
        String sigHex = translateRSToSigHex(sig);
        byte[] z = getZ(userID,pubkey);
        byte[] indata = new byte[z.length + data.length];
        System.arraycopy(z,0,indata,0,z.length);
        System.arraycopy(data,0,indata,z.length,data.length);
        String s = apiDigest(indata);
        int value = apiVerify(pubkey,s,sigHex);
        if(value == 0){
            return true;
        }else{
            return false;
        }
    }

    final int SMMA_ECC_FP_256_PUBLIC_KEY_LEN = 32 * 2;
    private  SM2P256V1Curve curve =new SM2P256V1Curve();

    private byte[] getZ(byte[] userID, String pubkey)
    {
        byte[] zdata = new byte[256];
        int len = userID.length * 8;
        zdata[0] = (byte)(len >> 8 & 0xFF);
        zdata[1] = (byte)(len & 0xFF);
        System.arraycopy(userID,0,zdata,2,userID.length);
        int offset = 2 + userID.length;

        System.arraycopy(A,0,zdata,offset,A.length);
        offset = offset + A.length;
        System.arraycopy(B,0,zdata,offset,B.length);
        offset = offset + B.length;
        System.arraycopy(GX,0,zdata,offset,GX.length);
        offset = offset + GX.length;
        System.arraycopy(GY,0,zdata,offset,GY.length);
        offset = offset + GY.length;

        String stringx =pubkey.substring(0,SMMA_ECC_FP_256_PUBLIC_KEY_LEN);
        String stringy = pubkey.substring(SMMA_ECC_FP_256_PUBLIC_KEY_LEN);

        BigInteger x = new BigInteger(1, ByteUtils.fromHexString(stringx));
        BigInteger y = new BigInteger(1,ByteUtils.fromHexString(stringy));

        org.bouncycastle.math.ec.ECPoint q = curve.createPoint(x,y);
        byte[] tmp = q.getAffineXCoord().getEncoded();
        System.arraycopy(tmp,0,zdata,offset,tmp.length);
        offset = offset + tmp.length;
        tmp = q.getAffineYCoord().getEncoded();
        System.arraycopy(tmp,0,zdata,offset,tmp.length);
        offset = offset + tmp.length;
        tmp = Arrays.copyOf(zdata,offset);
        String s = apiDigest(tmp);
        return ByteUtils.fromHexString(s);
    }


    public int test(int length){
        int testOK = 0;

        byte[] random = getRandom(length);
        if(random.length!= length){
            testOK = testOK + 1;
            
        }

        String d = apiDigest(random);
        byte[] digest = ByteUtils.fromHexString(d);
        SM3Digest sm3 = new SM3Digest();
        sm3.reset();
        sm3.update(random,0,random.length);
        byte[] bouncyDigest = new byte[sm3.getDigestSize()];
        sm3.doFinal(bouncyDigest,0);
        if(!Arrays.equals(bouncyDigest,digest)){
            testOK = testOK + 2; 
            
        }

        Sm.KeyPair kp = apiGenerateKeyPair();
        byte[] sig = sm2Sign(random,kp.getPrivateKey(),kp.getPublicKey());
        if(!sm2Verify(random,sig,kp.getPublicKey())){
            testOK = testOK + 4;
            
        }

        TokenEccPublicKey publicKey= new TokenEccPublicKey(kp.getPublicKey());
        BCECPublicKey localECPublicKey = (BCECPublicKey)publicKey.getPublicKey();
        boolean result = verifySM2Bouncy(random, sig, localECPublicKey);
        if(!result){
            testOK = testOK + 8;
            
        }

        return testOK;
    }


    public byte[] translateSigToRS(String sigHex)throws WstTokenException {
        String stringr =sigHex.substring(0,sigHex.length()/2);
        String strings = sigHex.substring(sigHex.length()/2);

        BigInteger r = new BigInteger(1, ByteUtils.fromHexString(stringr));
        BigInteger s = new BigInteger(1,ByteUtils.fromHexString(strings));
        try {
            return derEncode(r, s);
        }catch (IOException ex)
        {
            throw new WstTokenException(ex);
        }
    }

    protected byte[] derEncode(BigInteger r, BigInteger s)
            throws IOException
    {

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    public String translateRSToSigHex(byte[] rs){
        try
        {
            BigInteger[] rss = derDecode(rs);
            if (rs != null)
            {
                String r = bigIntToHex(rss[0],64);
                String s = bigIntToHex(rss[1],64);
                return r+s;
            }
        }
        catch (IOException e)
        {
            throw new WstTokenException(e);
        }
        return null;
    }

    protected BigInteger[] derDecode(byte[] encoding)
            throws IOException
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encoding));
        if (seq.size() != 2)
        {
            return null;
        }

        BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();

        byte[] expectedEncoding = derEncode(r, s);
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(expectedEncoding, encoding))
        {
            return null;
        }

        return new BigInteger[]{ r, s };
    }

    private  String bigIntToHex(BigInteger bigInteger, int length){
        String s = bigInteger.toString(16);
        int left = length - s.length();
        if(left ==0){
            return s;
        }
        StringBuilder sb = new StringBuilder();
        for(int i=0;i<left;i++){
            sb.append("0");
        }
        sb.append(s);
        return sb.toString();

    }

    public boolean verifySM2Bouncy(byte[] data, byte[] sig, BCECPublicKey localECPublicKey) {
        ECParameterSpec localECParameterSpec = localECPublicKey.getParameters();
        ECDomainParameters localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(),
                localECParameterSpec.getG(), localECParameterSpec.getN());
        ECPublicKeyParameters param = new ECPublicKeyParameters(localECPublicKey.getQ(), localECDomainParameters);

        SM2Signer signer = new SM2Signer();
        signer.init(false, param);
        signer.update(data, 0, data.length);
        return signer.verifySignature(sig);
    }

}
