# Enclosing generic signature boundary fixture

Real javac output targeting Java 17 class files. From this directory regenerate with:

```sh
/home/jonathan/.sdkman/candidates/java/current/bin/javac --release 17 -d . Outer.java Shadow.java
```

The regression reads these checked-in class bytes; it does not require javac at runtime.
It also patches `TT;` to `TZ;` in Inner's Signature constants to exercise a name
that no enclosing type declares, preserving constant lengths and class structure.
