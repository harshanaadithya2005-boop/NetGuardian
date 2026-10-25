import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;

public final class SignApk {
    public static void main(String[] args) throws Exception {
        if(args.length==6 && args[0].equals("--export")) {
            java.security.KeyStore store=java.security.KeyStore.getInstance("PKCS12");
            char[] password=new String(Files.readAllBytes(Paths.get(args[2])),"UTF-8").toCharArray();
            try(java.io.InputStream input=Files.newInputStream(Paths.get(args[1]))) { store.load(input,password); }
            Files.write(Paths.get(args[3]),store.getKey(args[5],password).getEncoded());
            Files.write(Paths.get(args[4]),store.getCertificate(args[5]).getEncoded());
            System.out.println("Local APK signing material prepared.");return;
        }
        if(args.length==4) {
            PrivateKey key=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get(args[2]))));
            X509Certificate certificate=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(Files.newInputStream(Paths.get(args[3])));
            ApkSigner.SignerConfig signer=new ApkSigner.SignerConfig.Builder("netguardian-local",key,Collections.singletonList(certificate)).build();
            new ApkSigner.Builder(Collections.singletonList(signer)).setInputApk(new File(args[0])).setOutputApk(new File(args[1]))
                .setMinSdkVersion(26).setV1SigningEnabled(false).setV2SigningEnabled(true).setV3SigningEnabled(true).build().sign();
        }
        File apk=new File(args.length==4?args[1]:args[0]);
        ApkVerifier.Result result=new ApkVerifier.Builder(apk).setMinCheckedPlatformVersion(26).build().verify();
        if(!result.isVerified())throw new IllegalStateException("APK signature verification failed: "+result.getErrors());
        System.out.println("APK signature verified: v2="+result.isVerifiedUsingV2Scheme()+", v3="+result.isVerifiedUsingV3Scheme());
    }
}
