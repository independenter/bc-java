package org.bouncycastle.learning.base;

public class ECPoint {

    static class Point {
        final int x, y;
        Point(int x, int y) { this.x = x; this.y = y; }
        static final Point INFINITY = null;
    }

    static int mod = 17;

    static Point add(Point p, Point q) {
        if (p == Point.INFINITY) return q;
        if (q == Point.INFINITY) return p;

        int dx = (q.x - p.x + mod) % mod;
        int dy = (q.y - p.y + mod) % mod;
        int invDx = modInverse(dx, mod);

        int lam = (dy * invDx) % mod;
        int xr = (lam * lam - p.x - q.x) % mod;
        int yr = (lam * (p.x - xr) - p.y) % mod;

        return new Point((xr + mod) % mod, (yr + mod) % mod);
    }

    static Point doublePoint(Point p) {
        int lam = (3 * p.x * p.x) % mod;
        int inv2y = modInverse(2 * p.y, mod);
        lam = (lam * inv2y) % mod;

        int xr = (lam * lam - 2 * p.x) % mod;
        int yr = (lam * (p.x - xr) - p.y) % mod;

        return new Point((xr + mod) % mod, (yr + mod) % mod);
    }

    static Point multiply(Point p, int k) {
        Point result = Point.INFINITY;
        Point addend = p;

        while (k > 0) {
            if ((k & 1) == 1) {
                result = add(result, addend);
            }
            addend = doublePoint(addend);
            k >>= 1;
        }
        return result;
    }

    public static void main(String[] args) {
        Point G = new Point(5, 1); // 示例基点
        int k = 7;

        Point R = multiply(G, k);
        System.out.println("kG = (" + R.x + ", " + R.y + ")");
    }

    static int modInverse(int a, int mod) {
        int t = 0, newT = 1;
        int r = mod, newR = a;
        while (newR != 0) {
            int q = r / newR;
            int tempT = t - q * newT;
            t = newT; newT = tempT;
            int tempR = r - q * newR;
            r = newR; newR = tempR;
        }
        return t < 0 ? t + mod : t;
    }
}