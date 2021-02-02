import java.math.BigInteger;

class Add {
    public static BigInteger add(BigInteger x, BigInteger y) {
        return x.add(y);
    }

    public static BigInteger dbl(BigInteger x) {
        return add(x, x);
    }
}
