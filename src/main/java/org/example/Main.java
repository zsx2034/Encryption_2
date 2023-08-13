package org.example;

import com.alibaba.fastjson2.JSON;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

public class Main {
    public static void main(String[] args) {
        String pairingParametersPath = "a.properties";
        String pkPath = "data/pk.properties";
        String mskPath = "data/msk.properties";
        String skPath = "data/sk.properties";

        ArrayList<String> U = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            U.add("UID" + i);
        }

        ArrayList<String> S = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            S.add("UID" + i);
        }

        // setup
        setup(pairingParametersPath, 162, 512, U.size(), pkPath, mskPath);

        // extract
        extract(pairingParametersPath, mskPath, U, skPath);

        // sem_encrypt
        CT ct = sem_encrypt(pairingParametersPath, pkPath, S, U);
//        CT ct = eem_encrypt(pairingParametersPath, pkPath, S, U);

        // sem_decrypt
//        decrypt(pairingParametersPath, ct, skPath, 9);
        assert ct != null;
        Properties skProp = loadFromFile(skPath);
        int id = 0;
        String sk = (String) skProp.get("sk" + id);
        String uid = "UID" + id;

        decrypt(pairingParametersPath, ct.toCTString(), sk, uid);
    }

    public static void setup(String pairingParametersPath, int qbit, int rbit, int m, String pkPath, String mskPath) {
        TypeACurveGenerator pg = new TypeACurveGenerator(qbit, rbit);
        PairingParameters parameters = pg.generate();

        try (FileWriter out = new FileWriter(pairingParametersPath)) {
            out.write(parameters.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }

        Pairing pairing = PairingFactory.getPairing(parameters);

        // random generate g
        Element g = pairing.getG1().newRandomElement().getImmutable();

        // random generate a0, a1, ..., am
        ArrayList<Element> a = new ArrayList<>();
        for (int i = 0; i <= m; i++) {
            a.add(pairing.getZr().newRandomElement().getImmutable());
        }

        // calculate ga0, ga1, ..., gam as g^ai
        // set ga as public key
        ArrayList<Element> ga = new ArrayList<>();
        for (int i = 0; i <= m; i++) {
            ga.add(g.powZn(a.get(i)).getImmutable());
        }

        // save g, ga to public key file
        Properties pk = new Properties();
        pk.setProperty("g", Base64.getEncoder().encodeToString(g.toBytes()));
        pk.setProperty("m", Integer.toString(m));
        for (int i = 0; i <= m; i++) {
            pk.setProperty("ga" + i, Base64.getEncoder().encodeToString(ga.get(i).toBytes()));
        }
        writeToFile(pk, pkPath);

        // save a0, a1, ..., am to master secret key file
        Properties msk = new Properties();
        for (int i = 0; i <= m; i++) {
            msk.setProperty("a" + i, Base64.getEncoder().encodeToString(a.get(i).toBytes()));
        }
        writeToFile(msk, mskPath);
    }


    public static void extract(String pairingParametersPath, String mskPath, ArrayList<String> U, String skPath) {
        Pairing pairing = PairingFactory.getPairing(pairingParametersPath);

        // load a0, a1, ..., am from master secret key file
        Properties mskProp = loadFromFile(mskPath);
        ArrayList<Element> msk = new ArrayList<>();
        for (int i = 0; i < mskProp.size(); i++) {
            msk.add(pairing.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("a" + i))).getImmutable());
        }

        // calculate sk0, sk1, ..., skU
        ArrayList<Element> skU = new ArrayList<>();
        ArrayList<Element> xU = new ArrayList<>();
        for (int i = 0; i < U.size(); i++) {
            Element x = pairing.getZr().newElementFromHash(U.get(i).getBytes(), 0, U.get(i).length()).getImmutable();
            xU.add(x);
            Element ski = calculateFxi(msk, x, pairing).getImmutable();
            skU.add(ski);
        }

        // save sk0, sk1, ..., skU to secret key file
        Properties skProp = new Properties();
        for (int i = 0; i < skU.size(); i++) {
            skProp.setProperty("sk" + i, Base64.getEncoder().encodeToString(skU.get(i).toBytes()));
        }

        for (int i = 0; i < xU.size(); i++) {
            skProp.setProperty("x" + i, Base64.getEncoder().encodeToString(xU.get(i).toBytes()));
            skProp.setProperty("U" + i, U.get(i));
        }
        writeToFile(skProp, skPath);
    }

    private static Element calculateFxi(ArrayList<Element> a, Element x, Pairing pairing) {
        Element result = pairing.getZr().newZeroElement().getImmutable();
        for (int i = 0; i < a.size(); i++) {
            result = result.add(a.get(i).duplicate().mul(x.duplicate().pow(BigInteger.valueOf(i)))).getImmutable();
        }
        return result;
    }

    public static CT_S encrypt(String pairingParametersPath, String pkPath, String message, ArrayList<String> S_or_R, ArrayList<String> U, EncryptType mode) {
        CT ct = null;
        if (mode == EncryptType.SEM) {
            ct = sem_encrypt(pairingParametersPath, pkPath, S_or_R, U);
        } else {
            ct = eem_encrypt(pairingParametersPath, pkPath, S_or_R, U);
        }

        assert ct != null;
        return ct.toCTString();
    }

    private static CT sem_encrypt(String pairingParametersPath, String pkPath, ArrayList<String> S, ArrayList<String> U) {
        Pairing pairing = PairingFactory.getPairing(pairingParametersPath);
        // random generate s
        Element s = pairing.getZr().newRandomElement().getImmutable();
        // load ga0, ga1, ..., gam from public key file
        Properties pkProp = loadFromFile(pkPath);
        String mStr = pkProp.getProperty("m");
        int m = Integer.parseInt(mStr);
        Element g = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("g"))).getImmutable();

        if (S.size() > m) {
            System.out.println("to much users in SEM mode. user count: " + S.size() + ", m: " + m);
            return null;
        }

        ArrayList<Element> ga = new ArrayList<>();
        for (int i = 0; i <= m; i++) {
            ga.add(pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("ga" + i))).getImmutable());
        }

        // calculate x = H(U)
        ArrayList<Element> x = new ArrayList<>();
        for (int i = 0; i < S.size(); i++) {
            x.add(pairing.getZr().newElementFromHash(S.get(i).getBytes(), 0, S.get(i).length()).getImmutable());
        }

        // time
        long startTime = System.currentTimeMillis();

        // calculate T = ga0^x^0 * ga1^x^1 * ... * gam^x^m
        ArrayList<Element> T = new ArrayList<>();
        for (Element element : x) {
            T.add(calculateTi(ga, element, pairing).getImmutable());
        }

        x.add(0, pairing.getZr().newZeroElement().getImmutable());
        T.add(0, g.powZn(s).getImmutable());

        // random generate tao
        ArrayList<Element> tao = new ArrayList<>();
        Element tmp = null;
        for (int i = 0; i < S.size(); i++) {
            do {
                tmp = pairing.getZr().newRandomElement().getImmutable();
            } while (x.contains(tmp));
            tao.add(tmp);
        }

        // random generate alpha
        Element alpha = pairing.getZr().newRandomElement().getImmutable();

        // calculate g^hs(tao)
        Element gs = g.powZn(s).getImmutable();
        ArrayList<Element> gtao = new ArrayList<>();
        for (int i = 0; i < tao.size(); i++) {
            Element ghs = calculateLagrange(x, T, tao.get(i), gs, pairing).getImmutable();
            gtao.add(ghs.powZn(alpha).getImmutable());
        }

        // time
        long endTime = System.currentTimeMillis();
        System.out.println("SEM encrypt Time: " + (endTime - startTime) + "ms");

        // generate ct
        CT ct = new CT();
        ct.C0 = gs.powZn(alpha).getImmutable();
        ct.C1 = g.powZn(alpha).getImmutable();
        ct.Ci1 = tao;
        ct.Ci2 = gtao;
//        System.out.println("g = " + g);
//        System.out.println("g ^ (alpha * s) = " + ct.C0);

        CT_S _ct_s = ct.toCTString();
        CT _ct = _ct_s.toCT(pairing);

        return ct;
    }

    private static CT eem_encrypt(String pairingParametersPath, String pkPath, ArrayList<String> R, ArrayList<String> U) {
        Pairing pairing = PairingFactory.getPairing(pairingParametersPath);

        // random generate s
        Element s = pairing.getZr().newRandomElement().getImmutable();

        // load ga0, ga1, ..., gam from public key file
        Properties pkProp = loadFromFile(pkPath);
        String mStr = pkProp.getProperty("m");
        int m = Integer.parseInt(mStr);
        Element g = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("g"))).getImmutable();

        if (R.size() > U.size()) {
            System.out.println("to much users in EEM mode. user count: " + R.size() + ", m: " + m);
            return null;
        }

        ArrayList<Element> ga = new ArrayList<>();
        for (int i = 0; i <= m; i++) {
            ga.add(pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProp.getProperty("ga" + i))).getImmutable());
        }

        // calculate x = H(U)
        ArrayList<Element> x = new ArrayList<>();
        for (int i = 0; i < U.size(); i++) {
            x.add(pairing.getZr().newElementFromHash(U.get(i).getBytes(), 0, U.get(i).length()).getImmutable());
        }

        // calculate T = ga0^x^0 * ga1^x^1 * ... * gam^x^m
        ArrayList<Element> T = new ArrayList<>();
        for (Element element : x) {
            T.add(calculateTi(ga, element, pairing).getImmutable());
        }

        // Lagrange interpolation point
        x.add(0, pairing.getZr().newZeroElement().getImmutable());
        Element gs = g.powZn(s).getImmutable();
        T.add(0, gs.duplicate().getImmutable());


        // construct sigma
        ArrayList<Element> sigma = new ArrayList<>();
        for (int i = 0; i < R.size(); i++) {
            sigma.add(pairing.getZr().newElementFromHash(R.get(i).getBytes(), 0, R.get(i).length()).getImmutable());
        }

        for (int i = R.size(); i < m; i++) {
            Element tmp = null;
            do {
                tmp = pairing.getZr().newRandomElement().getImmutable();
            } while (sigma.contains(tmp) || x.contains(tmp));
            sigma.add(tmp);
        }

        // random generate alpha
        Element alpha = pairing.getZr().newRandomElement().getImmutable();

        // calculate g^hr(sigma)^alpha
        ArrayList<Element> gsigma = new ArrayList<>();
        for (int i = 0; i < sigma.size(); i++) {
            Element ghs = calculateLagrange(x, T, sigma.get(i), gs, pairing).getImmutable();
            gsigma.add(ghs.powZn(alpha).getImmutable());
        }

        // generate ct
        CT ct = new CT();
        ct.C0 = gs.powZn(alpha).getImmutable();
        ct.C1 = g.powZn(alpha).getImmutable();
        ct.Ci1 = sigma;
        ct.Ci2 = gsigma;

        return ct;
    }

    private static Element calculateTi(ArrayList<Element> ga, Element x, Pairing pairing) {
        Element result = pairing.getG1().newOneElement().getImmutable();
        for (int i = 0; i < ga.size(); i++) {
            result = result.mul(ga.get(i).duplicate().powZn(x.duplicate().pow(BigInteger.valueOf(i)))).getImmutable();
        }
        return result;
    }

    private static Element calculateLagrange(ArrayList<Element> x, ArrayList<Element> y, Element variable, Element gs, Pairing pairing) {
        Element result = pairing.getG1().newOneElement().getImmutable();
        result = result.mul(gs.duplicate().powZn(calculateLagrangeX(x, variable, 0, pairing))).getImmutable();

        for (int i = 1; i < x.size(); i++) {
            result = result.mul(y.get(i).duplicate().powZn(calculateLagrangeX(x, variable, i, pairing))).getImmutable();
        }

        return result;
    }

    private static Element calculateLagrangeX(ArrayList<Element> x, Element variable, int i, Pairing pairing) {
        Element result = pairing.getZr().newOneElement().getImmutable();
        for (int j = 0; j < x.size(); j++) {
            if (j != i) {
                result = result.mul(
                        variable.duplicate().sub(x.get(j)).div(
                                x.get(i).duplicate().sub(x.get(j)
                                )
                        )).getImmutable();
            }
        }
        return result;
    }


    /**
     *
     * @param pairingParametersPath
     * @param ct
     * @param sk should be base64 sk
     * @return
     */
    public static String decrypt(String pairingParametersPath, CT_S ct, String sk, String uid, EncryptType mode) {
        // TODO judge if uid is in U
        return null;
    }

    /**
     * @param pairingParametersPath
     * @param _ct
     */
    private static void decrypt(String pairingParametersPath, CT_S _ct, String _sk, String uid) {
        Pairing pairing = PairingFactory.getPairing(pairingParametersPath);

        // load sk from file
        Element sk = pairing.getZr().newElementFromBytes(Base64.getDecoder().decode(_sk)).getImmutable();
        Element x = pairing.getZr().newElementFromHash(uid.getBytes(), 0, uid.length()).getImmutable();

        CT ct = _ct.toCT(pairing);

        ArrayList<Element> Ci1 = ct.Ci1;
        Ci1.add(0, x);
        ArrayList<Element> Ci2 = ct.Ci2;
        Ci2.add(0, pairing.getG1().newOneElement().getImmutable());
        Element L0 = calculateLagrangeX(Ci1, pairing.getZr().newZeroElement(), 0, pairing).getImmutable();

        Element result = ct.C1.powZn(sk.mulZn(L0)).getImmutable();

        for (int i = 1; i < Ci1.size(); i++) {
            Element Li = calculateLagrangeX(Ci1, pairing.getZr().newZeroElement(), i, pairing).getImmutable();
            result = result.mul(Ci2.get(i).powZn(Li)).getImmutable();
        }

        // uncomment this line to check if the result is equal to C0 while no message
        if (result.isEqual(ct.C0)) {
            System.out.println("true");
        } else {
            System.out.println("false");
        }
        System.out.println("result = " + result);
    }

    public static Properties loadFromFile(String filepath) {
        Properties properties = new Properties();
        try (FileInputStream in = new FileInputStream(filepath)) {
            properties.load(in);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed to load properties from file: " + filepath);
            System.exit(-1);
        }
        return properties;
    }

    public static void writeToFile(Properties properties, String filepath) {
        try (FileOutputStream out = new FileOutputStream(filepath)) {
            properties.store(out, null);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed to write properties to file: " + filepath);
            System.exit(-1);
        }
    }


}

class CT {
    public Element C0;
    public Element C1;

    public ArrayList<Element> Ci1;
    public ArrayList<Element> Ci2;

    public String mode;

    public CT_S toCTString() {
        CT_S tmp = new CT_S();
        tmp.C0 = Base64.getEncoder().encodeToString(C0.toBytes());
        tmp.C1 = Base64.getEncoder().encodeToString(C1.toBytes());

        tmp.Ci1 = new ArrayList<>();
        for (int i = 0; i < Ci1.size(); i++) {
            tmp.Ci1.add(Base64.getEncoder().encodeToString(Ci1.get(i).toBytes()));
        }

        tmp.Ci2 = new ArrayList<>();
        for (int i = 0; i < Ci2.size(); i++) {
            tmp.Ci2.add(Base64.getEncoder().encodeToString(Ci2.get(i).toBytes()));
        }

        tmp.mode = mode;

        return tmp;
    }
}

class CT_S {
    public String C0;
    public String C1;

    public ArrayList<String> Ci1;
    public ArrayList<String> Ci2;

    public String mode;

    public CT toCT(Pairing pairing) {
        CT tmp = new CT();
        tmp.C0 = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(C0)).getImmutable();
        tmp.C1 = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(C1)).getImmutable();

        tmp.Ci1 = new ArrayList<>();
        for (int i = 0; i < Ci1.size(); i++) {
            tmp.Ci1.add(pairing.getZr().newElementFromBytes(Base64.getDecoder().decode(Ci1.get(i))).getImmutable());
        }

        tmp.Ci2 = new ArrayList<>();
        for (int i = 0; i < Ci2.size(); i++) {
            tmp.Ci2.add(pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(Ci2.get(i))).getImmutable());
        }

        tmp.mode = mode;

        return tmp;
    }
}

enum EncryptType {
    SEM,
    EEM
}