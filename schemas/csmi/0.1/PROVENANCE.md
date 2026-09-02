# CSMI v0.1 pinned assets

The 120 files listed below are copied byte-for-byte from the immutable local
Git object for BrokkAi/code-semantic-model-interchange at commit
7f9f1975be99529a42bceb94d37adddcf083d0ba.
The source commit is the normative CSMI v0.1 revision for this pin. The core
schema is stored at spec/0.1/schema.json upstream and is vendored as
schema.json. Java/JVM profile fixtures are stored under
fixtures/profiles/java-jvm upstream and are vendored under
profiles/java-jvm/0.1/fixtures. All other listed paths retain their upstream
relative path.

Each digest is SHA-256 of the vendored file bytes. The deterministic inventory
record is the UTF-8 concatenation of sorted rows in the form
target-path<TAB>source-path<TAB>sha256<LF>, hashed as:

4b5cfcca58c46a578ec192d774ae94152bae0939ac4b92eff4f042090abf5b87

| Vendored path | Upstream path | SHA-256 |
| --- | --- | --- |
| fixtures/invalid/exact-purl-with-version-range.json | fixtures/invalid/exact-purl-with-version-range.json | 0d623e60867b1085dd61a94ac5e49639e6db675b9d895b12f5001c573a1d8d87 |
| fixtures/invalid/indexed-receiver-root.json | fixtures/invalid/indexed-receiver-root.json | e02af233407201dfca91c863a041481f1669502515e72389e1fac066e2b31178 |
| fixtures/invalid/invalid-boundary-root.json | fixtures/invalid/invalid-boundary-root.json | cdabe941511e320ebb22e7b6a5720b6fa32ca6bb4fc6205906a458d18a8772ef |
| fixtures/invalid/invalid-resource-digest.json | fixtures/invalid/invalid-resource-digest.json | 72fa75b80367071013c576fe8d6d02cae5340f8272644d0954d8ddb02a732a32 |
| fixtures/invalid/named-parameter-without-label.json | fixtures/invalid/named-parameter-without-label.json | 0f1a33260c75322c28bc8e33c2ea1a7f4a41da494de19f4329d7d3ce519c8f64 |
| fixtures/invalid/nul-resource-path.json | fixtures/invalid/nul-resource-path.json | 2d151e2947c81da53d8ee8b58aa4fce972b90fc157afca1e212be1ef1b18d8b5 |
| fixtures/invalid/partial-without-limitation.json | fixtures/invalid/partial-without-limitation.json | ec06d6fc9a02137f9888db4cf6f274b2010904dbbdebabbbb81ebc14a27a195a |
| fixtures/invalid/purl-with-subpath.json | fixtures/invalid/purl-with-subpath.json | 8efa24db2b0d8b5095d4a55bdae155fecc9e336795e2c618ceb6b3752344e33f |
| fixtures/invalid/trailing-resource-path.json | fixtures/invalid/trailing-resource-path.json | d44b9c18204f3ae8913b98d166f47e1b513b22132dde5712175f1d5a835198ae |
| fixtures/invalid/unknown-core-field.json | fixtures/invalid/unknown-core-field.json | bfc3f82c6e8133379de16e05ea9c60f3c74283671c4d36f520f9289c9283defe |
| fixtures/invalid/unknown-root-property.json | fixtures/invalid/unknown-root-property.json | df5dceb2cf55e032a8a0c2208c36d9781aac87560e862966df259641a65c156c |
| fixtures/invalid/unknown-type-variant.json | fixtures/invalid/unknown-type-variant.json | a187f5e19068fb166b0b1e26e104089657f9779be7e48dbbad385a84c1a43db7 |
| fixtures/invalid/unsafe-resource-path.json | fixtures/invalid/unsafe-resource-path.json | 7f7e16c56573b2d1e615bebe448652a5cacf48947d5254cde2c3585cfbd986c7 |
| fixtures/invalid/versionless-purl-without-range.json | fixtures/invalid/versionless-purl-without-range.json | 2b0796f154de05ed7f147e66a0bf3218231b336c623a34743cade5fb4cfdffea |
| fixtures/profile-inputs/typescript-signatures.json | fixtures/profile-inputs/typescript-signatures.json | e6d067138a57e6299750afc290853dbf55e682569644373abdd560dc2615dd60 |
| fixtures/semantic-invalid/README.md | fixtures/semantic-invalid/README.md | 46f844c8ec55b40a4ef8f35c6dc6b30a52ad43fd0d3a9d34a98753f2655e8554 |
| fixtures/semantic-invalid/duplicate-completeness-scope.json | fixtures/semantic-invalid/duplicate-completeness-scope.json | f48f7d8980998066836c7a7f8d1e5b86c1be2fc59f403c922f6884fe42323947 |
| fixtures/semantic-invalid/javascript-identity-profile-optional.json | fixtures/semantic-invalid/javascript-identity-profile-optional.json | ce39165980936965ec0a25568fb13f8800255bb65e3ba7108659c17cf26eb6d3 |
| fixtures/semantic-invalid/javascript-module-binding-mismatch.json | fixtures/semantic-invalid/javascript-module-binding-mismatch.json | eb79905af27f6ef24b83b850a701e45acf233ef1197c90b5497597c38d9d9a8d |
| fixtures/semantic-invalid/javascript-profile-payload-undeclared.json | fixtures/semantic-invalid/javascript-profile-payload-undeclared.json | ec221209d88476b09514b1b8e279404da010544dd252ddd85f4f354d9ae6118d |
| fixtures/semantic-invalid/javascript-runtime-binding-scope-mismatch.json | fixtures/semantic-invalid/javascript-runtime-binding-scope-mismatch.json | 2779a0b454f1a2c4e5ef306fc9f2646cef17330391c4c615670f7db9b5951a87 |
| fixtures/semantic-invalid/missing-declaration-dependency.json | fixtures/semantic-invalid/missing-declaration-dependency.json | 3fc9bc908f792b31b47a2405f1f7277341595cfdc04c2260fb832dfbd1227b65 |
| fixtures/semantic-invalid/missing-provenance.json | fixtures/semantic-invalid/missing-provenance.json | 45916a4de038391442debc311e2dbb96d29cce0c464733e7386b29d16a76e151 |
| fixtures/semantic-invalid/node-mutually-exclusive-conditions.json | fixtures/semantic-invalid/node-mutually-exclusive-conditions.json | 799d9ed4c02e7dfbbe56460b1fda9cdf8f50d1e21449049cd1538347b4517a1c |
| fixtures/semantic-invalid/noncontiguous-parameters.json | fixtures/semantic-invalid/noncontiguous-parameters.json | 36b193bb94556d81e8e70ef0c23cbd3d15c66406ac542ef943136392bf822710 |
| fixtures/semantic-invalid/python-runtime-overload-identity.json | fixtures/semantic-invalid/python-runtime-overload-identity.json | b2a2c2a9cd5e35e06b56ba4e86bb7f611b1ceea1b5a73c6802c5367b21ea6649 |
| fixtures/semantic-invalid/rust-complete-with-unsupported-expansion.json | fixtures/semantic-invalid/rust-complete-with-unsupported-expansion.json | 5cf7b3184b417434f98b932274fcc31cac57df076346fa3234a5665c0abae7d5 |
| fixtures/semantic-invalid/rust-invalid-identity-normalization.json | fixtures/semantic-invalid/rust-invalid-identity-normalization.json | 64ba4f98ff21690cd0f2f0f4b26b4d7ce6fd003517227accf90304acc878bca1 |
| fixtures/semantic-invalid/rust-name-only-trait-binding.json | fixtures/semantic-invalid/rust-name-only-trait-binding.json | 0c520ff724b179abfc57946b6eb9d98efe25e4e7a721ac50ccc1b303dc82fbab |
| fixtures/semantic-invalid/rust-sysroot-selector-mismatch.json | fixtures/semantic-invalid/rust-sysroot-selector-mismatch.json | 1b5aa7d234a28b3205228446c60eda9e20efae4c8c0e08772b758c37afba4642 |
| fixtures/semantic-invalid/undeclared-vocabulary.json | fixtures/semantic-invalid/undeclared-vocabulary.json | 151599453a38b61d2097105aa0628e0eaf5ef19d98c593b4d9939ad76b947430 |
| fixtures/semantic-invalid/unresolved-symbol.json | fixtures/semantic-invalid/unresolved-symbol.json | 6f64765e02455e4f33b94f35f439378d23fa150a633050c9b3523aa5703e14d8 |
| fixtures/valid/consumer-resolved-dependency.json | fixtures/valid/consumer-resolved-dependency.json | 0b03714c5150062cf531363c84ede412725dfb8aac8d581853ce209c35351fd1 |
| fixtures/valid/java-jvm-mapping.json | fixtures/valid/java-jvm-mapping.json | 3a7fed7b194791bbf7a7be5b24c14fce0dead24e41c94acc541f453d7abe34a9 |
| fixtures/valid/javascript-typescript-node.json | fixtures/valid/javascript-typescript-node.json | f6876073249c08fc6b3ad44740db662ae48aacbd2243380c7f36f9c7df5d1e44 |
| fixtures/valid/pack-manifest.json | fixtures/valid/pack-manifest.json | 2c370b027eb28e62813e5e310f6432e070a5fbe471dbc51667016f403bb4d30a |
| fixtures/valid/partial-summary.json | fixtures/valid/partial-summary.json | ca0a94653814ed01b2160e90d2627200f7a6d413fd1dee4b6b38735b7129ed54 |
| fixtures/valid/procedure-summary.json | fixtures/valid/procedure-summary.json | e33df997c34700a552df80ba3436fcd0fe8a6285c289f54119ba5fc83761e127 |
| fixtures/valid/python-overloads-descriptors.json | fixtures/valid/python-overloads-descriptors.json | 7d1c44b2297eab26f45388336a58489f890ad35094147dd767d8a4e08e6bbc4d |
| fixtures/valid/python-profile.json | fixtures/valid/python-profile.json | 5ec2707de3dd5d968ca6f035a4d2d966d050a1bab8a5cdf85fe980eec6ac9c4d |
| fixtures/valid/python-stub-correspondence.json | fixtures/valid/python-stub-correspondence.json | 89918c4bc4d76e0a776824097522ec31a13846af94b5a82e4d19a935b5290cd4 |
| fixtures/valid/receiver-summary.json | fixtures/valid/receiver-summary.json | 752c755f14e96874d92cb775e57f9b54f74de5e8b1ab862239b9bf6a5cb2468e |
| fixtures/valid/rust-profile.json | fixtures/valid/rust-profile.json | 5778f37b1c42d0b33b25b797d1103da35ed498b5d67e130cd36098f465054475 |
| fixtures/valid/rust-sysroot-profile.json | fixtures/valid/rust-sysroot-profile.json | 54458e99a19a465c59fc4c7458e8a4d4d41393d7066ad0cbf7f04a8fa131266a |
| profiles/java-jvm/0.1/fixtures/invalid/compatibility-empty-constraints.json | fixtures/profiles/java-jvm/invalid/compatibility-empty-constraints.json | 33d41b6eb6e7c11cfe9339c8ecf5239af282e522607b33a6fbf2088710d1350f |
| profiles/java-jvm/0.1/fixtures/invalid/compatibility-relative-vendor.json | fixtures/profiles/java-jvm/invalid/compatibility-relative-vendor.json | 681fe3327e3445f45d0f6ff0cd04eeb02a65eacf20062c72bdc121409944cd5c |
| profiles/java-jvm/0.1/fixtures/invalid/java-constructor-with-name.json | fixtures/profiles/java-jvm/invalid/java-constructor-with-name.json | 6c871756410b3b9600f72661df831721d8efeebf6577fbbc9141a9243b44c40e |
| profiles/java-jvm/0.1/fixtures/invalid/java-generated-without-stable-key.json | fixtures/profiles/java-jvm/invalid/java-generated-without-stable-key.json | 4a48dee0d8c10a474204a671c0f0a35b60db3843e4e9b1392151e932df254981 |
| profiles/java-jvm/0.1/fixtures/invalid/java-local-without-stable-key.json | fixtures/profiles/java-jvm/invalid/java-local-without-stable-key.json | 687cb613b151f6f6572abc1214824ec75f84d3954908af474f74cfa7fc255b01 |
| profiles/java-jvm/0.1/fixtures/invalid/java-source-unsupported-version.json | fixtures/profiles/java-jvm/invalid/java-source-unsupported-version.json | 86838f48e3889eb2c79fabcc6d41e732f9289b1b93a96c106ee2ce53994dd1a6 |
| profiles/java-jvm/0.1/fixtures/invalid/jvm-class-initializer-parameters.json | fixtures/profiles/java-jvm/invalid/jvm-class-initializer-parameters.json | a86f81d816f83763009fdae73745e61b857b20b7a2e86028a39ed15ab194586e |
| profiles/java-jvm/0.1/fixtures/invalid/jvm-constructor-nonvoid.json | fixtures/profiles/java-jvm/invalid/jvm-constructor-nonvoid.json | 1a1293484b3dd63815157ece15bf82d7cfc31de570117a14b14e9378ed9341a9 |
| profiles/java-jvm/0.1/fixtures/invalid/jvm-method-without-descriptor.json | fixtures/profiles/java-jvm/invalid/jvm-method-without-descriptor.json | e51425ffcbfe2e8f2d506ad5e6a9fc0471f1116f070c94ac1ee8bcdbad6c133b |
| profiles/java-jvm/0.1/fixtures/invalid/jvm-multi-release-as-base.json | fixtures/profiles/java-jvm/invalid/jvm-multi-release-as-base.json | 0cdaebf02a8fada4ebbc392a963504051d73b354e022c4fabc87858a53ef799f |
| profiles/java-jvm/0.1/fixtures/invalid/jvm-multi-release-eight.json | fixtures/profiles/java-jvm/invalid/jvm-multi-release-eight.json | 1bbb1f5c50daf5e6cab25bf84e0b0ec4a6eeebe51cbb0e3bb4930262910f87d2 |
| profiles/java-jvm/0.1/fixtures/invalid/mapping-established-without-evidence.json | fixtures/profiles/java-jvm/invalid/mapping-established-without-evidence.json | f43b3b240a22ec99b87f91a8663203ed2dc319342953ff1485e68dbe0b3ad37b |
| profiles/java-jvm/0.1/fixtures/invalid/mapping-indeterminate-with-target.json | fixtures/profiles/java-jvm/invalid/mapping-indeterminate-with-target.json | a5cec1b5f82dfd1b5945bf3300a6d7f03b9454178f06e702081342b94f65e2b4 |
| profiles/java-jvm/0.1/fixtures/invalid/mapping-relative-producer.json | fixtures/profiles/java-jvm/invalid/mapping-relative-producer.json | ce24a396d4f0363b71ec219ad32f3dd0753c386f4e8dee8cae1cb454d73af9f3 |
| profiles/java-jvm/0.1/fixtures/semantic-invalid/compatibility-reversed-range.json | fixtures/profiles/java-jvm/semantic-invalid/compatibility-reversed-range.json | 7229fa1f6eca5ebe9e75bbbe879f759ea18bd63ceb631fbbd522f38363a6670f |
| profiles/java-jvm/0.1/fixtures/semantic-invalid/java-varargs-not-normalized.json | fixtures/profiles/java-jvm/semantic-invalid/java-varargs-not-normalized.json | 293e7d013d82c6e64572751c404d7287772c1a68e6ac7802474cac67c4c3168b |
| profiles/java-jvm/0.1/fixtures/semantic-invalid/multi-release-path-release-mismatch.json | fixtures/profiles/java-jvm/semantic-invalid/multi-release-path-release-mismatch.json | a4e484ecf592678633e1b6f61a97540fd7931f980f1721a295a77d7ba279d1c7 |
| profiles/java-jvm/0.1/fixtures/valid/compatibility-indeterminate-jvm-vendor.json | fixtures/profiles/java-jvm/valid/compatibility-indeterminate-jvm-vendor.json | 0eef2235fa5331e2594fce340eebad5e19355bb65176365ecf3d30473f83569f |
| profiles/java-jvm/0.1/fixtures/valid/compatibility-maven-kotlin-mrjar.json | fixtures/profiles/java-jvm/valid/compatibility-maven-kotlin-mrjar.json | 0e3a2bee609db31f5364287cd99d7ced7d0228f924b39619f40d7ce89e9e364c |
| profiles/java-jvm/0.1/fixtures/valid/java-constructor.json | fixtures/profiles/java-jvm/valid/java-constructor.json | d26bc1b19409b7f02fd221b2145806fb6143c947084927020275208391faad5c |
| profiles/java-jvm/0.1/fixtures/valid/java-overload-bytes.json | fixtures/profiles/java-jvm/valid/java-overload-bytes.json | 419a71c8766a5873fbd932099fe352093d53d2cf2c6b728b7e3789ef2a5003f4 |
| profiles/java-jvm/0.1/fixtures/valid/java-overload-string.json | fixtures/profiles/java-jvm/valid/java-overload-string.json | 40d8c199cf4fd641fb894d5cf6d8dd6e59f0f9cbc23bf27abb362137d4c4f4c6 |
| profiles/java-jvm/0.1/fixtures/valid/jvm-bridge-method.json | fixtures/profiles/java-jvm/valid/jvm-bridge-method.json | 844060f15f1ec6c59e400b43e09e1c001d640b6274a65bdfee6b8ec097119f68 |
| profiles/java-jvm/0.1/fixtures/valid/jvm-erased-generic-method.json | fixtures/profiles/java-jvm/valid/jvm-erased-generic-method.json | 2fde9c6035a4c77257f916f2bc3cb8e34326344b6b135ce4065d3228521a10a1 |
| profiles/java-jvm/0.1/fixtures/valid/jvm-jdk-module-member.json | fixtures/profiles/java-jvm/valid/jvm-jdk-module-member.json | 9c2cd6566f0d89acd94b8d8d5e67c53c36d14fca0a56f7fa1f753b713233ba40 |
| profiles/java-jvm/0.1/fixtures/valid/jvm-multi-release-17.json | fixtures/profiles/java-jvm/valid/jvm-multi-release-17.json | 97aa3b8f3f6b588da2781852d6ba7cb0867604cffe0be6f9779c5b70c0885446 |
| profiles/java-jvm/0.1/fixtures/valid/jvm-shaded-member.json | fixtures/profiles/java-jvm/valid/jvm-shaded-member.json | a2a19abe4041abf430aba91be838f2cccfbf663ba676db5c82cbb020e76d42c5 |
| profiles/java-jvm/0.1/fixtures/valid/kotlin-extension.json | fixtures/profiles/java-jvm/valid/kotlin-extension.json | 3828ea1c71967fa84f643ac1056276dcf93f72ac313d00b791cc4c4c32e51302 |
| profiles/java-jvm/0.1/fixtures/valid/mapping-indeterminate-relocation.json | fixtures/profiles/java-jvm/valid/mapping-indeterminate-relocation.json | b8aa388eb3de59e5d9af14aff3c4b3afdbe82bea585a43ebd05be9516c26d180 |
| profiles/java-jvm/0.1/fixtures/valid/mapping-kotlin-default-lowering.json | fixtures/profiles/java-jvm/valid/mapping-kotlin-default-lowering.json | d10ac192667bac11507ba302a1187f319df80f80e2007ae9b4b54903e91ad281 |
| profiles/java-jvm/0.1/fixtures/valid/mapping-scala-erasure.json | fixtures/profiles/java-jvm/valid/mapping-scala-erasure.json | c4ce160ea84f462162249ddf162fded48a279ab130bb78818b62c7e23bc8af6e |
| profiles/java-jvm/0.1/fixtures/valid/mapping-unsupported-profile.json | fixtures/profiles/java-jvm/valid/mapping-unsupported-profile.json | 1f95e50531730a11787141c7a7357beda4c56b45c06a37ae7991874b318c49bf |
| profiles/java-jvm/0.1/fixtures/valid/scala-generated-case-copy.json | fixtures/profiles/java-jvm/valid/scala-generated-case-copy.json | a0b0c8b2dc1f293d6668b38e9636cf43f6dbfe8161864789bbdc73753ec6d176 |
| profiles/java-jvm/0.1/java-jvm-mapping.schema.json | profiles/java-jvm/0.1/java-jvm-mapping.schema.json | e88d5c3b33eea38b5df88c1a85cd4cb7a50cb9427ba6f8e912b87162e4e9d64f |
| profiles/java-jvm/0.1/java-source-identity.schema.json | profiles/java-jvm/0.1/java-source-identity.schema.json | 832ca193519731deba37f48bed0dddf5cfafb72092c624052e76621f459ead4b |
| profiles/java-jvm/0.1/jvm-binary-identity.schema.json | profiles/java-jvm/0.1/jvm-binary-identity.schema.json | 820f9739bdefc1172b11dc1bc2f8c731843f80a3c5b5dd790bc69ba3a9f1b0b2 |
| profiles/java-jvm/0.1/jvm-compatibility.schema.json | profiles/java-jvm/0.1/jvm-compatibility.schema.json | 36ad9e9b93935868f3034baee21ed34dad8fdc59f545992c090d71d7da37ca7f |
| profiles/javascript-typescript/0.1/fixtures/invalid/name-only-binding.json | profiles/javascript-typescript/0.1/fixtures/invalid/name-only-binding.json | bec4391587a5af72406d7e549e72c096392f091f10f3d6523fa4583bfb9e9a55 |
| profiles/javascript-typescript/0.1/fixtures/valid/module-binding.json | profiles/javascript-typescript/0.1/fixtures/valid/module-binding.json | 5deecfa9be3cdd6c5a1a7e99b0ecec0d2ea5d36c8cdc2939bc34d231eeeaf375 |
| profiles/javascript-typescript/0.1/fixtures/valid/runtime-declaration-binding.json | profiles/javascript-typescript/0.1/fixtures/valid/runtime-declaration-binding.json | 51804041d8a7dd921526a66dc29248db89bcef3a82556476812c8d6edbbf76a6 |
| profiles/javascript-typescript/0.1/schema.json | profiles/javascript-typescript/0.1/schema.json | f13d5ebb717db247ad7faec72711cad33e877e6cffa979dd48c8857dbb1240d4 |
| profiles/node-compatibility/0.1/fixtures/invalid/default-condition.json | profiles/node-compatibility/0.1/fixtures/invalid/default-condition.json | 9a4388dd4eff01f1c60bc5e3bbd855f932bf4649f25d24bd2e39de18a3c3a4f9 |
| profiles/node-compatibility/0.1/fixtures/invalid/free-form-version-range.json | profiles/node-compatibility/0.1/fixtures/invalid/free-form-version-range.json | 64f7f4eafb299254e998eb492d7a2b8355b15568cb1702dc5917d981235b1463 |
| profiles/node-compatibility/0.1/fixtures/valid/default-only-resolution.json | profiles/node-compatibility/0.1/fixtures/valid/default-only-resolution.json | fb4572e3a71159ffd87c705e2b357e16fd119fcc5e3fb055b27a8873a2366e79 |
| profiles/node-compatibility/0.1/fixtures/valid/module-resolution.json | profiles/node-compatibility/0.1/fixtures/valid/module-resolution.json | 8574891ffb56b935595f73866b97d7d18225567f299211f18cc96b9d41407e58 |
| profiles/node-compatibility/0.1/fixtures/valid/node-runtime.json | profiles/node-compatibility/0.1/fixtures/valid/node-runtime.json | e5611e4fcf16f2caa3db20d10a5e4ea2c67a37a9f8e3369bda4aa4c53e41acd2 |
| profiles/node-compatibility/0.1/fixtures/valid/typescript-resolution.json | profiles/node-compatibility/0.1/fixtures/valid/typescript-resolution.json | 801c21b7ef5d4124576e3eafaf9e2eab3e18391a2e4fa9a89ca67d87e343017b |
| profiles/node-compatibility/0.1/schema.json | profiles/node-compatibility/0.1/schema.json | 3b58370fdc9c0872178c1e6869eeef221f57eb208e849e79ec1c6cc2431721ff |
| profiles/python/0.1/fixtures/invalid/inferred-import-string.json | profiles/python/0.1/fixtures/invalid/inferred-import-string.json | 11018a1263ecf1883718bff1dd655a844b5f0b9a205ae240aeeb11c8c1784077 |
| profiles/python/0.1/fixtures/invalid/unknown-binding-kind.json | profiles/python/0.1/fixtures/invalid/unknown-binding-kind.json | 20e3f78ccb7eafdab1c630a7aaa0bb918b0d163ac298b50bf5e64816177aff24 |
| profiles/python/0.1/fixtures/valid/compatibility.json | profiles/python/0.1/fixtures/valid/compatibility.json | 05d48ce483d61cb9dc2621552e5b7a0954b85445755998541a99ddae9ed78d30 |
| profiles/python/0.1/fixtures/valid/declaration-correspondence.json | profiles/python/0.1/fixtures/valid/declaration-correspondence.json | 80ef715f7a12b5196d785913c64b9465d6f908bcbd599fb7d55f697234e05b25 |
| profiles/python/0.1/fixtures/valid/distribution-imports.json | profiles/python/0.1/fixtures/valid/distribution-imports.json | b7e4549b5bfa59410c65f089306420d75f40a5f8fe745c5aa3ee2151bb2c2953 |
| profiles/python/0.1/fixtures/valid/import-bindings.json | profiles/python/0.1/fixtures/valid/import-bindings.json | d86331ba92fabd450e66bc527c88452ef9bb8a41022e255359b29abf96797fec |
| profiles/python/0.1/fixtures/valid/namespace-package.json | profiles/python/0.1/fixtures/valid/namespace-package.json | 2523af156e8de8975b4d4bcebd46ef2f1a9a8859ead5af8a34113b120733300b |
| profiles/python/0.1/schema.json | profiles/python/0.1/schema.json | cb54343c764de2ce8ebe6103c05dd080a1fd37e66dfc02fac639677d3c34bafd |
| profiles/rust/0.1/fixtures/invalid/incomplete-custom-target.json | profiles/rust/0.1/fixtures/invalid/incomplete-custom-target.json | a5062326d8f37e372b2632bfcca47dd27eb51a3b48332be977151c1cad88e038 |
| profiles/rust/0.1/fixtures/invalid/malformed-cargo-purl.json | profiles/rust/0.1/fixtures/invalid/malformed-cargo-purl.json | 0bc11bae34a78606d1c0ba7da92d635a4f8c6e7a2a40f2ef20c8fbfe8e96fdb0 |
| profiles/rust/0.1/fixtures/invalid/mixed-target-identity.json | profiles/rust/0.1/fixtures/invalid/mixed-target-identity.json | 33788994ff11f330e99853a43fe6ef78b17ce7e541a03147142d1da066e22ef8 |
| profiles/rust/0.1/fixtures/invalid/nightly-without-commit.json | profiles/rust/0.1/fixtures/invalid/nightly-without-commit.json | 81ee06ae4ef8f0a5072624522f23a37256b88c4a8da0f2a1a7288ed4c2ab43fc |
| profiles/rust/0.1/fixtures/invalid/non-cargo-crate-target.json | profiles/rust/0.1/fixtures/invalid/non-cargo-crate-target.json | d4a303b31a47efc2b01616c73a3466f4a06954195bf3a6d168fa44303ea9e60f |
| profiles/rust/0.1/fixtures/invalid/sysroot-without-artifact-link.json | profiles/rust/0.1/fixtures/invalid/sysroot-without-artifact-link.json | 51b293ba0ac6aaee79876718f0f087f4a7f8c4a9e6c414524c7da7a4dcac2a2f |
| profiles/rust/0.1/fixtures/invalid/trait-implementation-without-trait.json | profiles/rust/0.1/fixtures/invalid/trait-implementation-without-trait.json | 824d033d6f6bbb34a8b21245e40ba2cd67c3da5125ebb792339bea6036427abd |
| profiles/rust/0.1/fixtures/invalid/unknown-payload-field.json | profiles/rust/0.1/fixtures/invalid/unknown-payload-field.json | 90b662485230e6595d1df1b37939c4af227cffa317ae4ccf737fd9d4b14097bb |
| profiles/rust/0.1/fixtures/invalid/versionless-sysroot-purl.json | profiles/rust/0.1/fixtures/invalid/versionless-sysroot-purl.json | 89e056e114e95a1d0be596accbb594a18fbdb7ce21dc7f607ad93f8ffcda28b6 |
| profiles/rust/0.1/fixtures/valid/configuration.json | profiles/rust/0.1/fixtures/valid/configuration.json | 481113f71fd111900a12fca2a750f05e9cf7acc7ca0633512778a03d0ff5d9f0 |
| profiles/rust/0.1/fixtures/valid/crate-target.json | profiles/rust/0.1/fixtures/valid/crate-target.json | 594f9af13d9502d808da1736c507e3b41182eea466c6c86c58212ee93d07f9ed |
| profiles/rust/0.1/fixtures/valid/dependency-binding.json | profiles/rust/0.1/fixtures/valid/dependency-binding.json | 9aab2d05c6c28e100d71c9be5e44caad0b2c8a17c4b7e171d5fc86cdfc7a2aee |
| profiles/rust/0.1/fixtures/valid/generation.json | profiles/rust/0.1/fixtures/valid/generation.json | 97e323b1b268b64d1add06a68f00e55d91866b9e288f0809ddcfee92487e55a3 |
| profiles/rust/0.1/fixtures/valid/implementation.json | profiles/rust/0.1/fixtures/valid/implementation.json | 01e01656e7abc867c9495ecc1a04d0406966d2b7f46a91bd9135d3a2ce40a68c |
| profiles/rust/0.1/fixtures/valid/native-mapping.json | profiles/rust/0.1/fixtures/valid/native-mapping.json | 335cdd6bea890dfce8c94b6132b12bf600442ea13a6de5ac48fcf41d71277954 |
| profiles/rust/0.1/fixtures/valid/reexport.json | profiles/rust/0.1/fixtures/valid/reexport.json | 0aa0cf76d52257f97a43edea5d94b725644496e7a9da91877c2b5a8214c2a79e |
| profiles/rust/0.1/fixtures/valid/sysroot-core.json | profiles/rust/0.1/fixtures/valid/sysroot-core.json | 3ce806774ccf038149c6368bb12c7868f2708120df0c186ebae102f6d9859d4d |
| profiles/rust/0.1/fixtures/valid/workspace.json | profiles/rust/0.1/fixtures/valid/workspace.json | 33c9ca38cf0280098b3ba16d2a05e071893b5e6f5f5852d51dc1ad74ff3f1127 |
| profiles/rust/0.1/schema.json | profiles/rust/0.1/schema.json | 1af9d7dc34f23a43bcdd795bc7010bba21ad277ec7b97c7c774e42d7fb1a1488 |
| schema.json | spec/0.1/schema.json | 99d280864662e947421e0a840d7dbbd81bdf635fedaefaa7e44fa63bd49221b8 |

The canonical core schema URI is
https://csmi.brokk.ai/schema/0.1/schema.json. The fixture corpus is pinned
for offline validation; tests and production validation must not retrieve the
schema URI or fixture bytes over the network.

The following files are Bifrost-authored and are intentionally not attributed
to the upstream object or included in the byte inventory:

- fixtures/README.md is local validator integration documentation.
- profiles/ai.brokk.csmi.jvm-symbol-0.1.md is the legacy Bifrost JVM-symbol
  profile. It predates and is distinct from the standardized Java/JVM profiles.
