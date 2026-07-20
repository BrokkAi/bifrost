# Java classfile fixture provenance

`bin/*.class` is the checked-in bytecode subset of this Java source fixture.
Normal Rust tests consume only the committed files and their SHA-256 manifest;
they do not require a JDK.

The source corpus also contains deliberately unresolved Java used by parser and
analyzer tests. `class-fixture-sources.txt` is therefore the complete, explicit
list of sources that produce the classfiles. Do not broaden it by compiling
every `*.java` file in this directory.

The canonical compiler is Eclipse Temurin 21.0.8+9. The scripts require that
exact build and invoke `javac` with `--release 21 -g -encoding UTF-8 -proc:none`
and `-implicit:none` in the listed source order. All compiler output is created
in a temporary directory first.

From the repository root, verify the checked-in bytes and manifest with:

```sh
bash scripts/verify-java-class-fixture.sh
```

To intentionally replace only `bin/*.class` and `classes.sha256` from a clean
temporary build, run:

```sh
bash scripts/regenerate-java-class-fixture.sh
bash scripts/verify-java-class-fixture.sh
```

The `.classpath` and `.project` files retained under `bin/` are historical
source-fixture metadata. They are not compiler outputs and are outside the
classfile manifest.
