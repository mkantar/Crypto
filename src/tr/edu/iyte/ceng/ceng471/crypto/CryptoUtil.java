package tr.edu.iyte.ceng.ceng471.crypto;

import java.math.BigInteger;
import java.util.Random;

public class CryptoUtil {

    public static class BezoutPolynomial {
        private BigInteger a;
        private BigInteger b;
        private BigInteger x;
        private BigInteger y;

        public BezoutPolynomial(BigInteger a, BigInteger b) {
            this.a = a;
            this.b = b;
        }

        public BezoutPolynomial(BigInteger a, BigInteger b, BigInteger x, BigInteger y) {
            this.a = a;
            this.b = b;

            this.x = x;
            this.y = y;
        }

        public BigInteger getA() {
            return a;
        }

        public BigInteger getB() {
            return b;
        }

        public BigInteger getX() {
            return x;
        }

        public BigInteger getY() {
            return y;
        }

        public BigInteger computeGCD() {
            if(b.equals(BigInteger.ZERO))
                return a.abs();
            BigInteger first = a.multiply(x);
            BigInteger second = b.multiply(y);
            return first.add(second);
        }

        public BigInteger computeMultiplicativeInverse() {
            if(this.computeGCD().equals(BigInteger.ONE))
                return this.x.mod(this.b);
            else
                return BigInteger.ZERO;
        }

        public boolean isCoPrime() {
            return this.computeGCD().equals(BigInteger.ONE);
        }


        @Override
        public String toString(){
            return "(a, b): (" + a + ", " + b + "), (x, y): (" + x + ", " + y + ")";
        }
    }

    public static BezoutPolynomial computePolynomial(BigInteger a, BigInteger b) {
        BigInteger s     = BigInteger.ZERO;
        BigInteger old_s = BigInteger.ONE;
        BigInteger t     = BigInteger.ONE;
        BigInteger old_t = BigInteger.ZERO;
        BigInteger r     = b;
        BigInteger old_r = a;

        BigInteger q;
        BigInteger prov;

        while(!r.equals(BigInteger.ZERO)) {
            q = old_r.divide(r);

            prov = BigInteger.valueOf(r.longValue());
            r = old_r.subtract(q.multiply(prov));
            old_r = BigInteger.valueOf(prov.longValue());

            prov = BigInteger.valueOf(s.longValue());
            s = old_s.subtract(q.multiply(prov));
            old_s = BigInteger.valueOf(prov.longValue());

            prov = BigInteger.valueOf(t.longValue());
            t = old_t.subtract(q.multiply(prov));
            old_t = BigInteger.valueOf(prov.longValue());

        }

        return new BezoutPolynomial(a, b, old_s, old_t);
    }

    public static BigInteger computeChineseRemainder(BigInteger[] a, BigInteger[] n) throws NullPointerException, ArrayIndexOutOfBoundsException {
        if(a == null && n == null)
            throw new NullPointerException();

        if(a.length != n.length)
            throw new ArrayIndexOutOfBoundsException();

        BezoutPolynomial[] pols = new BezoutPolynomial[a.length];
        BigInteger prod = BigInteger.ONE;


        for (BigInteger elem : a) {
            prod = prod.multiply(elem);
        }

        BigInteger result = BigInteger.ZERO;

        for(int i = 0; i < a.length; i++) {
            BigInteger pp = prod.divide(a[i]);
            pols[i] = computePolynomial(pp, a[i]);
            result = result.add((n[i].multiply(pols[i].computeMultiplicativeInverse())).multiply(pp));
        }

        return result.mod(prod);
    }

    public static boolean checkPrimality(BigInteger n) {
        BigInteger k = n.subtract(BigInteger.ONE);
        Random generator = new Random();
        BigInteger a;
        BezoutPolynomial pol;
        do {
            a = BigInteger.valueOf(generator.nextInt(Integer.MAX_VALUE));
            pol = computePolynomial(a, n);
        } while (!pol.isCoPrime());

        BigInteger x = a.pow(k.intValue());

        return x.mod(n).equals(BigInteger.ONE) || x.mod(n).equals(k);

    }
}

