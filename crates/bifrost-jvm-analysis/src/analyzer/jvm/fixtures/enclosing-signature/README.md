# Enclosing generic signature boundary fixture

Real javac output targeting Java 17 class files. From this directory regenerate with:

```sh
/home/jonathan/.sdkman/candidates/java/current/bin/javac --release 17 -d . Outer.java Shadow.java
```

`Pipeline.java` was added later (Temurin 17.0.16) with the same flags:

```sh
javac --release 17 -d . Pipeline.java
```

Its anonymous classes name type variables of their enclosing constructor's
class, of an enclosing generic method, through an anonymous class nested in
another anonymous class, and of a static generic method (#9901).

The regression reads these checked-in class bytes; it does not require javac at runtime.
It also patches `TT;` to `TZ;` in Inner's Signature constants to exercise a name
that no enclosing type declares, preserving constant lengths and class structure.
