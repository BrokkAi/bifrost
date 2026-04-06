mod common;

use brokk_analyzer::{
    IAnalyzer, ImportAnalysisProvider, JavascriptAnalyzer, Language, ProjectFile, TestProject,
};
use std::collections::BTreeSet;
use std::path::Path;
use tempfile::tempdir;

use common::write_file;

fn analyzer_for(root: &Path) -> JavascriptAnalyzer {
    JavascriptAnalyzer::from_project(TestProject::new(root, Language::JavaScript))
}

fn imported_fq_names(analyzer: &JavascriptAnalyzer, file: &ProjectFile) -> BTreeSet<String> {
    analyzer
        .imported_code_units_of(file)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect()
}

#[test]
fn test_import() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = write_file(
        root,
        "foo.js",
        r#"
            import React, { useState } from 'react';
            import { Something, AnotherThing as AT } from './another-module';
            import * as AllThings from './all-the-things';
            import DefaultThing from './default-thing';
            import './side-effect-module';
            import 'global-polyfill';

            function foo() {};
        "#,
    );

    let analyzer = analyzer_for(root);
    let imports: BTreeSet<_> = analyzer.import_statements_of(&file).into_iter().collect();
    let expected = BTreeSet::from([
        "import { Something, AnotherThing as AT } from './another-module';".to_string(),
        "import * as AllThings from './all-the-things';".to_string(),
        "import React, { useState } from 'react';".to_string(),
        "import DefaultThing from './default-thing';".to_string(),
        "import './side-effect-module';".to_string(),
        "import 'global-polyfill';".to_string(),
    ]);
    assert_eq!(expected, imports);
}

#[test]
fn test_resolve_imports_and_import_variants() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "utils/helper.js",
        "export function helper() { return 42; }\n",
    );
    write_file(
        root,
        "main.js",
        "import { helper } from './utils/helper';\nfunction main() { return helper(); }\n",
    );
    write_file(
        root,
        "math/operations.js",
        "export function add(a, b) { return a + b; }\nexport function subtract(a, b) { return a - b; }\nexport const PI = 3.14159;\n",
    );
    write_file(
        root,
        "calculator.js",
        "import * as MathOps from './math/operations';\nfunction calculate() { return MathOps.add(1, 2) + MathOps.PI; }\n",
    );
    write_file(
        root,
        "src/some/BaseService.js",
        "export class BaseService { getData() { return []; } }\n",
    );
    write_file(
        root,
        "src/some/dir/ChildService.js",
        "import { BaseService } from '../BaseService';\nexport class ChildService extends BaseService { process() { return this.getData().map(x => x * 2); } }\n",
    );
    write_file(
        root,
        "lib/shared.js",
        "export function shared() { return 1; }\n",
    );
    write_file(
        root,
        "index.js",
        "const { shared } = require('./lib/shared');\nshared();\n",
    );
    write_file(
        root,
        "polyfill.js",
        "// polyfill.js sets up global state\nif (typeof window !== 'undefined') { window.polyfilled = true; }\nexport const POLYFILL_VERSION = '1.0';\n",
    );
    write_file(
        root,
        "app.js",
        "import './polyfill';\nfunction main() { console.log('app started'); }\n",
    );
    write_file(
        root,
        "utils/greet.js",
        "export function greet() { return 'hello'; }\n",
    );
    write_file(
        root,
        "explicit.js",
        "import { greet } from './utils/greet.js';\nfunction main() { return greet(); }\n",
    );
    write_file(root, "mod1.js", "export const val = 100;\n");
    write_file(root, "mod2.js", "export const otherVal = 200;\n");
    write_file(
        root,
        "mixed.js",
        "import { val } from './mod1';\nconst { otherVal } = require('./mod2');\n",
    );
    write_file(
        root,
        "lib/index.js",
        "export function libFunc() { return 'lib'; }\nexport function otherFunc() { return 'other'; }\n",
    );
    write_file(
        root,
        "dir_main.js",
        "import { libFunc } from './lib/index.js';\nimport { libFunc as libFunc2 } from './lib';\nlibFunc();\n",
    );
    write_file(
        root,
        "dir_alias_only.js",
        "import { libFunc as libFuncAlias } from './lib';\nlibFuncAlias();\n",
    );
    write_file(
        root,
        "require_dir.js",
        "const { libFunc } = require('./lib/index');\nlibFunc();\n",
    );
    write_file(
        root,
        "util-dir.js",
        "export function fromFile() { return 1; }\n",
    );
    write_file(
        root,
        "util-dir/index.js",
        "export function fromIndex() { return 2; }\n",
    );
    write_file(
        root,
        "explicit_file.js",
        "import { fromFile } from './util-dir.js';\nfromFile();\n",
    );

    let analyzer = analyzer_for(root);

    assert!(
        imported_fq_names(&analyzer, &ProjectFile::new(root.to_path_buf(), "main.js"))
            .contains("helper")
    );
    let calculator_imports =
        analyzer.imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "calculator.js"));
    assert!(
        calculator_imports
            .iter()
            .any(|code_unit| code_unit.identifier() == "add")
    );
    assert!(
        calculator_imports
            .iter()
            .any(|code_unit| code_unit.identifier() == "subtract")
    );
    assert!(
        calculator_imports
            .iter()
            .any(|code_unit| code_unit.identifier() == "PI")
    );
    assert!(
        analyzer
            .imported_code_units_of(&ProjectFile::new(
                root.to_path_buf(),
                "src/some/dir/ChildService.js"
            ))
            .iter()
            .any(|code_unit| {
                code_unit.identifier() == "BaseService"
                    && code_unit.is_class()
                    && code_unit.source().rel_path() == Path::new("src/some/BaseService.js")
            })
    );
    assert!(
        imported_fq_names(&analyzer, &ProjectFile::new(root.to_path_buf(), "index.js"))
            .contains("shared")
    );
    assert!(
        analyzer
            .imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "app.js"))
            .iter()
            .any(|code_unit| {
                code_unit.identifier() == "POLYFILL_VERSION"
                    && code_unit.source().rel_path() == Path::new("polyfill.js")
            })
    );
    assert!(
        analyzer
            .imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "explicit.js"))
            .iter()
            .any(|code_unit| {
                code_unit.identifier() == "greet"
                    && code_unit.source().rel_path() == Path::new("utils/greet.js")
            })
    );
    let mixed_imports =
        imported_fq_names(&analyzer, &ProjectFile::new(root.to_path_buf(), "mixed.js"));
    assert!(mixed_imports.iter().any(|fq_name| fq_name.ends_with("val")));
    assert!(
        mixed_imports
            .iter()
            .any(|fq_name| fq_name.ends_with("otherVal"))
    );
    assert!(
        analyzer
            .imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "dir_main.js"))
            .iter()
            .any(|code_unit| {
                code_unit.identifier() == "libFunc"
                    && code_unit.source().rel_path() == Path::new("lib/index.js")
            })
    );
    assert!(
        analyzer
            .imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "dir_alias_only.js"))
            .iter()
            .any(|code_unit| {
                code_unit.identifier() == "libFunc"
                    && code_unit.source().rel_path() == Path::new("lib/index.js")
            })
    );
    assert!(
        analyzer
            .imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "require_dir.js"))
            .iter()
            .any(|code_unit| {
                code_unit.identifier() == "libFunc"
                    && code_unit.source().rel_path() == Path::new("lib/index.js")
            })
    );
    let explicit_imports =
        analyzer.imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "explicit_file.js"));
    assert!(explicit_imports.iter().any(|code_unit| {
        code_unit.identifier() == "fromFile"
            && code_unit.source().rel_path() == Path::new("util-dir.js")
    }));
    assert!(
        !explicit_imports
            .iter()
            .any(|code_unit| { code_unit.source().rel_path() == Path::new("util-dir/index.js") })
    );
}

#[test]
fn default_import_of_aggregator_module_keeps_module_file() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_file(root, "lib/axios.js", "export default { create() { return {}; } };\n");
    write_file(
        root,
        "index.js",
        "import axios from './lib/axios.js';\nexport { axios as default, axios };\n",
    );
    write_file(
        root,
        "bin/githubAxios.js",
        "import axios from '../index.js';\nexport default axios.create();\n",
    );

    let analyzer = analyzer_for(root);
    let imports =
        analyzer.imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "bin/githubAxios.js"));

    assert!(
        imports
            .iter()
            .any(|code_unit| code_unit.source().rel_path() == Path::new("index.js")),
        "default import should retain the aggregator module file when no exact declaration matches"
    );
}

#[test]
fn test_require_import() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = write_file(
        root,
        "app.js",
        r#"
            const path = require('path');
            const fs = require('fs');
            const local = require('./local-module');
            const { func } = require('../other');

            function app() {}
        "#,
    );

    let analyzer = analyzer_for(root);
    let imports = analyzer.import_statements_of(&file);
    assert!(imports.iter().any(|line| line.contains("require('path')")));
    assert!(imports.iter().any(|line| line.contains("require('fs')")));
    assert!(
        imports
            .iter()
            .any(|line| line.contains("require('./local-module')"))
    );
    assert!(
        imports
            .iter()
            .any(|line| line.contains("require('../other')"))
    );
    assert_eq!(4, imports.len());
}

#[test]
fn test_extract_type_identifiers_and_relevant_imports() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "test.js",
        r#"
            import { Foo } from './foo';
            import { Bar } from './bar';

            function useFoo() {
                const x = new Foo();
                return <Bar prop={x} />;
            }
        "#,
    );
    write_file(
        root,
        "main.js",
        r#"
            import { Foo } from './foo';
            import { Bar } from './bar';

            export function useFoo() {
                return new Foo();
            }
        "#,
    );
    write_file(
        root,
        "work.js",
        r#"
            import { Used } from './used';
            import { Unused } from './unused';

            export function doWork() {
                Used.process();
            }
        "#,
    );
    write_file(
        root,
        "require_app.js",
        r#"
            const fs = require('fs');
            const { readFile } = require('fs');
            const path = require('path');

            export function readConfig() {
                fs.readFileSync('config.json');
                readFile('other.json', () => {});
            }

            export function unusedFunction() {
                return 1;
            }
        "#,
    );
    write_file(
        root,
        "destructured.js",
        r#"
            const { helper, other } = require('./utils');

            export function callHelper() {
                helper();
            }

            export function callOther() {
                other();
            }
        "#,
    );
    write_file(
        root,
        "component.js",
        r#"
            import React from 'react';
            import { useState } from 'react';
            const fs = require('fs');
            const path = require('path');

            export function MyComponent() {
                const [val] = useState(0);
                fs.readFileSync('foo');
                return <div>{val}</div>;
            }
        "#,
    );

    let analyzer = analyzer_for(root);
    let identifiers = analyzer.extract_type_identifiers(
        r#"
            function useFoo() {
                const x = new Foo();
                return <Bar prop={x} />;
            }
        "#,
    );
    assert!(identifiers.contains("Foo"));
    assert!(identifiers.contains("Bar"));
    assert!(identifiers.contains("x"));

    let use_foo = analyzer
        .get_definitions("useFoo")
        .into_iter()
        .next()
        .unwrap();
    let relevant = analyzer.relevant_imports_for(&use_foo);
    assert!(relevant.contains("import { Foo } from './foo';"));
    assert!(!relevant.contains("import { Bar } from './bar';"));

    let do_work = analyzer
        .get_definitions("doWork")
        .into_iter()
        .next()
        .unwrap();
    let work_relevant = analyzer.relevant_imports_for(&do_work);
    assert_eq!(
        BTreeSet::from(["import { Used } from './used';".to_string()]),
        work_relevant
    );

    let read_config = analyzer
        .get_definitions("readConfig")
        .into_iter()
        .next()
        .unwrap();
    let read_relevant = analyzer.relevant_imports_for(&read_config);
    assert!(
        read_relevant
            .iter()
            .any(|line| line.contains("const fs = require('fs')"))
    );
    assert!(
        read_relevant
            .iter()
            .any(|line| line.contains("const { readFile } = require('fs')"))
    );
    assert!(
        !read_relevant
            .iter()
            .any(|line| line.contains("const path = require('path')"))
    );

    let unused = analyzer
        .get_definitions("unusedFunction")
        .into_iter()
        .next()
        .unwrap();
    assert!(analyzer.relevant_imports_for(&unused).is_empty());

    let call_helper = analyzer
        .get_definitions("callHelper")
        .into_iter()
        .next()
        .unwrap();
    assert!(
        analyzer
            .relevant_imports_for(&call_helper)
            .iter()
            .any(|line| line.contains("const { helper, other } = require('./utils')"))
    );

    let component = analyzer
        .get_definitions("MyComponent")
        .into_iter()
        .next()
        .unwrap();
    let component_relevant = analyzer.relevant_imports_for(&component);
    assert!(!component_relevant.contains("import React from 'react';"));
    assert!(component_relevant.contains("import { useState } from 'react';"));
    assert!(
        component_relevant
            .iter()
            .any(|line| line.contains("const fs = require('fs')"))
    );
    assert!(
        !component_relevant
            .iter()
            .any(|line| line.contains("const path = require('path')"))
    );
}

#[test]
fn test_referencing_files_uses_resolved_import_targets() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_file(root, "lib/index.js", "export function libFunc() { return 'lib'; }\n");
    write_file(
        root,
        "consumer.js",
        "import { libFunc as libFuncAlias } from './lib';\nlibFuncAlias();\n",
    );

    let analyzer = analyzer_for(root);
    let target = ProjectFile::new(root.to_path_buf(), "lib/index.js");
    let consumer = ProjectFile::new(root.to_path_buf(), "consumer.js");

    assert_eq!(
        BTreeSet::from([consumer]),
        analyzer.referencing_files_of(&target)
    );
}
