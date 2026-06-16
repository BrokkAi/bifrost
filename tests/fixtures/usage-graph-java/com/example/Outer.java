package com.example;

public class Outer {
    public static class Inner {
        public int compute() {
            // Unqualified call: attributes to the enclosing nested class
            // `com.example.Outer.Inner`, not a same-named top-level type.
            return helper();
        }

        public int helper() {
            return 1;
        }
    }
}
