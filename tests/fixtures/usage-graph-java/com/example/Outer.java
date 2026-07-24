package com.example;

public class Outer {
    public static class Inner {
        public int compute(Inner other) {
            // A call through another `Inner` instance: the receiver type `Inner`
            // must resolve to the enclosing nested class `com.example.Outer.Inner`
            // (not a same-named top-level type). An unqualified `helper()` call
            // would be a same-owner site excluded from edges under #1014 facet B,
            // so this uses a distinct instance to keep an external edge.
            return other.helper();
        }

        public int helper() {
            return 1;
        }
    }
}
