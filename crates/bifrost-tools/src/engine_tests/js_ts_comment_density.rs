#[cfg(test)]
mod js_ts_extraction_tests {

    use brokk_bifrost_analysis::analyzer::comment_density::assert_projection_matches_direct;
    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon(
        "#2592: JavaScript import projection attributed comments differently from the direct scan"
    )]
    fn javascript_projection_preserves_imported_module_attribution() {
        let stats = assert_projection_matches_direct(
            "response.js",
            "var dep = require('dep');\n\
             function send(body) {\n\
               // settings\n\
               return dep(body);\n\
             }\n",
            "send",
        );
        assert_eq!(
            (stats.header_comment_lines, stats.inline_comment_lines),
            (0, 0)
        );
    }
    #[test]
    #[hardwon(
        "#2592: TypeScript import projection attributed comments differently from the direct scan"
    )]
    fn typescript_projection_preserves_imported_module_attribution() {
        let stats = assert_projection_matches_direct(
            "Ky.ts",
            "import type {Options} from './types.js';\n\
             function cloneRetryOptions(options: Options): Options {\n\
               // clone before mutation\n\
               return {...options};\n\
             }\n",
            "cloneRetryOptions",
        );
        assert_eq!(
            (stats.header_comment_lines, stats.inline_comment_lines),
            (0, 0)
        );
    }
}
