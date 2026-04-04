mod common;

use brokk_analyzer::{
    IAnalyzer, ImportAnalysisProvider, Language, ProjectFile, TestProject, TypescriptAnalyzer,
};
use std::collections::BTreeSet;
use std::path::Path;
use tempfile::tempdir;

use common::write_file;

fn analyzer_for(root: &Path) -> TypescriptAnalyzer {
    TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript))
}

#[test]
fn test_import_and_require_statements() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = write_file(
        root,
        "foo.ts",
        r#"
            import React, { useState } from 'react';
            import { Something, AnotherThing as AT } from './another-module';
            import * as AllThings from './all-the-things';
            import DefaultThing from './default-thing';

            function foo(): void {};
        "#,
    );
    let require_file = write_file(
        root,
        "app.ts",
        r#"
            const path = require('path');
            const fs = require('fs');
            const local = require('./local-module');
            const { func } = require('../other');

            function app(): void {}
        "#,
    );

    let analyzer = analyzer_for(root);
    let imports: BTreeSet<_> = analyzer.import_statements_of(&file).into_iter().collect();
    let expected = BTreeSet::from([
        "import { Something, AnotherThing as AT } from './another-module';".to_string(),
        "import * as AllThings from './all-the-things';".to_string(),
        "import React, { useState } from 'react';".to_string(),
        "import DefaultThing from './default-thing';".to_string(),
    ]);
    assert_eq!(expected, imports);

    let require_imports = analyzer.import_statements_of(&require_file);
    assert!(
        require_imports
            .iter()
            .any(|line| line.contains("require('path')"))
    );
    assert!(
        require_imports
            .iter()
            .any(|line| line.contains("require('fs')"))
    );
    assert!(
        require_imports
            .iter()
            .any(|line| line.contains("require('./local-module')"))
    );
    assert!(
        require_imports
            .iter()
            .any(|line| line.contains("require('../other')"))
    );
    assert_eq!(4, require_imports.len());
}

#[test]
fn test_resolve_imports_relevant_imports_and_could_import_file() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "utils/helper.ts",
        "export function helper(): number { return 42; }\n",
    );
    write_file(
        root,
        "main.ts",
        "import { helper } from './utils/helper';\nfunction main(): number { return helper(); }\n",
    );
    write_file(
        root,
        "math/operations.ts",
        "export function add(a: number, b: number): number { return a + b; }\nexport function subtract(a: number, b: number): number { return a - b; }\nexport const PI: number = 3.14159;\n",
    );
    write_file(
        root,
        "calculator.ts",
        "import * as MathOps from './math/operations';\nfunction calculate(): number { return MathOps.add(1, 2) + MathOps.PI; }\n",
    );
    write_file(
        root,
        "src/some/BaseService.ts",
        "export class BaseService { getData(): any[] { return []; } }\n",
    );
    write_file(
        root,
        "src/some/dir/ChildService.ts",
        "import { BaseService } from '../BaseService';\nexport class ChildService extends BaseService { process(): number[] { return this.getData().map(x => x * 2); } }\n",
    );
    write_file(
        root,
        "lib/shared.ts",
        "export function shared(): number { return 1; }\n",
    );
    write_file(
        root,
        "index.ts",
        "const { shared } = require('./lib/shared');\nshared();\n",
    );
    write_file(
        root,
        "utils/greet.ts",
        "export function greet(): string { return 'hello'; }\n",
    );
    write_file(
        root,
        "explicit.ts",
        "import { greet } from './utils/greet.ts';\nfunction main(): string { return greet(); }\n",
    );
    write_file(root, "mod1.ts", "export const val: number = 100;\n");
    write_file(root, "mod2.ts", "export const otherVal: number = 200;\n");
    write_file(
        root,
        "mixed.ts",
        "import { val } from './mod1';\nconst { otherVal } = require('./mod2');\n",
    );
    write_file(
        root,
        "lib/index.ts",
        "export function libFunc(): string { return 'lib'; }\nexport function otherFunc(): string { return 'other'; }\n",
    );
    write_file(
        root,
        "dir_main.ts",
        "import { libFunc } from './lib/index.ts';\nimport { libFunc as libFunc2 } from './lib';\nlibFunc();\n",
    );
    write_file(
        root,
        "dir_alias_only.ts",
        "import { libFunc as libFuncAlias } from './lib';\nlibFuncAlias();\n",
    );
    write_file(
        root,
        "require_dir.ts",
        "const { libFunc } = require('./lib/index');\nlibFunc();\n",
    );
    write_file(
        root,
        "util-dir.ts",
        "export function fromFile(): number { return 1; }\n",
    );
    write_file(
        root,
        "util-dir/index.ts",
        "export function fromIndex(): number { return 2; }\n",
    );
    write_file(
        root,
        "explicit_file.ts",
        "import { fromFile } from './util-dir.ts';\nfromFile();\n",
    );
    write_file(
        root,
        "work.ts",
        "import { Used } from './used';\nimport { Unused } from './unused';\nexport function doWork(): void { Used.process(); }\n",
    );
    write_file(
        root,
        "typed.ts",
        "import { Foo } from './models';\nfunction process(input: Foo): void { console.log(input); }\n",
    );
    write_file(
        root,
        "require_app.ts",
        "const fs = require('fs');\nconst { readFile } = require('fs');\nconst path = require('path');\nexport function readConfig(): void { fs.readFileSync('config.json'); readFile('other.json', () => {}); }\nexport function unusedFunction(): number { return 1; }\n",
    );
    write_file(
        root,
        "src/utils/helper.ts",
        "export function X(): void {}\n",
    );
    write_file(
        root,
        "src/rel_main.ts",
        "import { X } from './utils/helper';\nfunction foo(): void {}\n",
    );
    write_file(root, "src/models/User.ts", "export default class User {}\n");
    write_file(
        root,
        "src/components/Component.ts",
        "import User from '../models/User';\nfunction foo(): void {}\n",
    );
    write_file(
        root,
        "src/external.ts",
        "import _ from 'lodash';\nfunction foo(): void {}\n",
    );
    write_file(
        root,
        "src/utils/index.ts",
        "export function something(): void {}\n",
    );
    write_file(
        root,
        "src/index_main.ts",
        "import { something } from './utils';\nfunction foo(): void {}\n",
    );

    let analyzer = analyzer_for(root);

    assert!(
        analyzer
            .imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "main.ts"))
            .iter()
            .any(|code_unit| {
                code_unit.identifier() == "helper"
                    && code_unit.source().rel_path() == Path::new("utils/helper.ts")
            })
    );
    let wildcard_imports =
        analyzer.imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "calculator.ts"));
    assert!(
        wildcard_imports
            .iter()
            .any(|code_unit| code_unit.identifier() == "add")
    );
    assert!(
        wildcard_imports
            .iter()
            .any(|code_unit| code_unit.identifier() == "subtract")
    );
    assert!(
        wildcard_imports
            .iter()
            .any(|code_unit| code_unit.identifier() == "PI")
    );
    assert!(
        analyzer
            .imported_code_units_of(&ProjectFile::new(
                root.to_path_buf(),
                "src/some/dir/ChildService.ts"
            ))
            .iter()
            .any(|code_unit| {
                code_unit.identifier() == "BaseService"
                    && code_unit.is_class()
                    && code_unit.source().rel_path() == Path::new("src/some/BaseService.ts")
            })
    );
    assert!(
        analyzer
            .imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "index.ts"))
            .iter()
            .any(|code_unit| {
                code_unit.identifier() == "shared"
                    && code_unit.source().rel_path() == Path::new("lib/shared.ts")
            })
    );
    assert!(
        analyzer
            .imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "explicit.ts"))
            .iter()
            .any(|code_unit| {
                code_unit.identifier() == "greet"
                    && code_unit.source().rel_path() == Path::new("utils/greet.ts")
            })
    );
    let mixed_imports =
        analyzer.imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "mixed.ts"));
    assert!(
        mixed_imports
            .iter()
            .any(|code_unit| code_unit.identifier().ends_with("val"))
    );
    assert!(
        mixed_imports
            .iter()
            .any(|code_unit| code_unit.identifier().ends_with("otherVal"))
    );
    assert!(
        analyzer
            .imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "dir_main.ts"))
            .iter()
            .any(|code_unit| {
                code_unit.identifier() == "libFunc"
                    && code_unit.source().rel_path() == Path::new("lib/index.ts")
            })
    );
    assert!(
        analyzer
            .imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "dir_alias_only.ts"))
            .iter()
            .any(|code_unit| {
                code_unit.identifier() == "libFunc"
                    && code_unit.source().rel_path() == Path::new("lib/index.ts")
            })
    );
    assert!(
        analyzer
            .imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "require_dir.ts"))
            .iter()
            .any(|code_unit| {
                code_unit.identifier() == "libFunc"
                    && code_unit.source().rel_path() == Path::new("lib/index.ts")
            })
    );
    let explicit_imports =
        analyzer.imported_code_units_of(&ProjectFile::new(root.to_path_buf(), "explicit_file.ts"));
    assert!(explicit_imports.iter().any(|code_unit| {
        code_unit.identifier() == "fromFile"
            && code_unit.source().rel_path() == Path::new("util-dir.ts")
    }));
    assert!(
        !explicit_imports
            .iter()
            .any(|code_unit| { code_unit.source().rel_path() == Path::new("util-dir/index.ts") })
    );

    let do_work = analyzer
        .get_definitions("doWork")
        .into_iter()
        .next()
        .unwrap();
    let relevant = analyzer.relevant_imports_for(&do_work);
    assert_eq!(
        BTreeSet::from(["import { Used } from './used';".to_string()]),
        relevant
    );

    let identifiers = analyzer.extract_type_identifiers(
        r#"
            function process(input: Foo): void {
                console.log(input);
            }
        "#,
    );
    assert!(identifiers.contains("Foo"));
    assert!(identifiers.contains("input"));
    assert!(identifiers.contains("process"));

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

    let rel_main = ProjectFile::new(root.to_path_buf(), "src/rel_main.ts");
    let rel_imports = analyzer.import_info_of(&rel_main);
    assert!(analyzer.could_import_file(
        &rel_main,
        &rel_imports,
        &ProjectFile::new(root.to_path_buf(), "src/utils/helper.ts")
    ));

    let component_file = ProjectFile::new(root.to_path_buf(), "src/components/Component.ts");
    let component_imports = analyzer.import_info_of(&component_file);
    assert!(analyzer.could_import_file(
        &component_file,
        &component_imports,
        &ProjectFile::new(root.to_path_buf(), "src/models/User.ts")
    ));

    let external_file = ProjectFile::new(root.to_path_buf(), "src/external.ts");
    let external_imports = analyzer.import_info_of(&external_file);
    assert!(!analyzer.could_import_file(
        &external_file,
        &external_imports,
        &ProjectFile::new(root.to_path_buf(), "src/utils/helper.ts")
    ));

    let index_main = ProjectFile::new(root.to_path_buf(), "src/index_main.ts");
    let index_imports = analyzer.import_info_of(&index_main);
    assert!(analyzer.could_import_file(
        &index_main,
        &index_imports,
        &ProjectFile::new(root.to_path_buf(), "src/utils/index.ts")
    ));
}
