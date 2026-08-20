# Pinned JDK source slices used by the summary-foundry derivation tests

These files are reduced verbatim slices of the standard-library sources that
`scripts/public/build-pinned-jvm-semantic-packs.sh` already pins.

    artifact: OpenJDK21U-jdk_aarch64_mac_hotspot_21.0.8_9.tar.gz
    member:   jdk-21.0.8+9/Contents/Home/lib/src.zip
    sha256:   5440baccc6c54b18671ab9cb9bf6ffdd7698d3a85ee74faa0b47b111312f200c
    module:   java.base
    license:  GPL-2.0-only WITH Classpath-exception-2.0

The slices exist so the derivation tests never touch the network. They are not
distributed: `Cargo.toml` excludes `testdata/summary-sources/**` from the
published crate.

Each file keeps the upstream copyright header unchanged. Every other retained
line is byte-identical to the pinned upstream file. One clearly labelled slice
marker comment records that declarations were removed. Nothing was rewritten.

## `java/util/Objects.java`

Upstream `java.base/java/util/Objects.java`, retained line ranges:

| upstream lines | content |
| --- | --- |
| 1-31 | copyright header, `package`, imports |
| 42 | `public final class Objects {` |
| 163-165 | `toString(Object, String)` |
| 230-235 | `requireNonNull(T)` |
| 256-261 | `requireNonNull(T, String)` |
| 313-315 | `requireNonNullElse(T, T)` |
| 332-335 | `requireNonNullElseGet(T, Supplier)` |
| 515 | closing brace |

Javadoc blocks between the retained declarations were removed.

## `java/lang/reflect/Array.java`

Upstream `java.base/java/lang/reflect/Array.java`, retained line ranges:

| upstream lines | content |
| --- | --- |
| 1-28 | copyright header, `package`, import |
| 41-42 | `public final` / `class Array {` |
| 47 | `private Array() {}` |
| 76-79 | `newInstance(Class, int)` |
| 145-146 | `native get(Object, int)` |
| 317-318 | `native set(Object, int, Object)` |
| 484-486 | `native newArray(Class, int)` |
| 493 | closing brace |

Javadoc blocks and the other native accessors were removed.
