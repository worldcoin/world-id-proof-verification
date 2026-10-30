//! Static guard for metric-label hygiene requirement: no
//! `metrics::{counter,histogram,gauge}!` label may be named after or interpolate
//! `challenge_id`, `credential_sub`, or `merkle_root` (PII + cardinality). Parses
//! every Rust source file so it catches call sites that handler tests do not run.

#[cfg(test)]
mod tests {
    use std::fs;
    use std::ops::Range;
    use std::path::Path;

    use annotate_snippets::{Level, Renderer, Snippet};
    use proc_macro2::{Span, TokenStream, TokenTree};
    use syn::visit::{self, Visit};

    const FORBIDDEN: &[&str] = &["challenge_id", "credential_sub", "merkle_root"];

    #[derive(Debug, Eq, PartialEq)]
    struct MetricViolation {
        span: Range<usize>,
        macro_name: &'static str,
        forbidden: &'static str,
    }

    #[derive(Default)]
    struct MetricMacroVisitor {
        violations: Vec<MetricViolation>,
    }

    impl<'ast> Visit<'ast> for MetricMacroVisitor {
        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            if let Some(macro_name) = metric_macro_name(&node.path) {
                for &forbidden in FORBIDDEN {
                    let offending_span = find_label_key(&node.tokens, forbidden)
                        .or_else(|| find_ident(node.tokens.clone(), forbidden));
                    if let Some(span) = offending_span {
                        self.violations.push(MetricViolation {
                            span: span.byte_range(),
                            macro_name,
                            forbidden,
                        });
                    }
                }
            }

            visit::visit_macro(self, node);
        }
    }

    fn metric_macro_name(path: &syn::Path) -> Option<&'static str> {
        let mut segments = path.segments.iter();
        let namespace = segments.next()?.ident.to_string();
        let macro_name = segments.next()?.ident.to_string();

        if namespace != "metrics" || segments.next().is_some() {
            return None;
        }

        match macro_name.as_str() {
            "counter" => Some("metrics::counter"),
            "histogram" => Some("metrics::histogram"),
            "gauge" => Some("metrics::gauge"),
            _ => None,
        }
    }

    fn find_ident(tokens: TokenStream, needle: &str) -> Option<Span> {
        tokens.into_iter().find_map(|token| match token {
            TokenTree::Ident(ident) if ident == needle => Some(ident.span()),
            TokenTree::Group(group) => find_ident(group.stream(), needle),
            TokenTree::Ident(_) | TokenTree::Punct(_) | TokenTree::Literal(_) => None,
        })
    }

    fn find_label_key(tokens: &TokenStream, needle: &str) -> Option<Span> {
        let tokens: Vec<_> = tokens.clone().into_iter().collect();
        tokens.windows(3).find_map(|window| {
            let [TokenTree::Literal(key), TokenTree::Punct(equals), TokenTree::Punct(greater_than)] =
                window
            else {
                return None;
            };

            (equals.as_char() == '='
                && greater_than.as_char() == '>'
                && syn::parse_str::<syn::LitStr>(&key.to_string())
                    .is_ok_and(|key| key.value() == needle))
            .then(|| key.span())
        })
    }

    fn metric_label_violations(source: &str) -> syn::Result<Vec<MetricViolation>> {
        let file = syn::parse_file(source)?;
        let mut visitor = MetricMacroVisitor::default();
        visitor.visit_file(&file);
        Ok(visitor.violations)
    }

    fn collect_rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in fs::read_dir(dir).expect("read source directory") {
            let path = entry.expect("read dir entry").path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    fn render_violation(file: &Path, source: &str, violation: &MetricViolation) -> String {
        let title = format!("{}! uses a forbidden metric field", violation.macro_name);
        let label = format!(
            "`{}` may contain PII or high-cardinality values",
            violation.forbidden
        );
        let origin = file.display().to_string();
        let message = Level::Error.title(&title).snippet(
            Snippet::source(source)
                .origin(&origin)
                .fold(true)
                .annotation(Level::Error.span(violation.span.clone()).label(&label)),
        );
        let renderer = if std::env::var_os("NO_COLOR").is_some() {
            Renderer::plain()
        } else {
            Renderer::styled()
        };

        let rendered = renderer.render(message).to_string();
        rendered
    }

    #[test]
    fn no_metric_call_interpolates_a_pii_or_high_cardinality_field() {
        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs_files(&src_dir, &mut files);
        files.sort();
        assert!(
            !files.is_empty(),
            "expected to find source files under src/"
        );

        let mut diagnostics = Vec::new();
        for file in files {
            let contents = fs::read_to_string(&file).expect("read source file");
            let violations = metric_label_violations(&contents)
                .unwrap_or_else(|error| panic!("failed to parse {}: {error}", file.display()));

            for violation in violations {
                diagnostics.push(render_violation(&file, &contents, &violation));
            }
        }

        assert!(diagnostics.is_empty(), "\n{}", diagnostics.join("\n\n"));
    }

    #[test]
    fn guard_catches_a_forbidden_label_key() {
        let source = r#"
            fn example() {
                metrics::counter!(
                    "x.rejected",
                    "challenge_id" => format!("{something_else}"),
                ).increment(1);
            }
        "#;

        let violations = metric_label_violations(source).expect("parse planted violation");

        assert_eq!(violations.len(), 1);
        assert_eq!(&source[violations[0].span.clone()], "\"challenge_id\"");
        assert_eq!(violations[0].macro_name, "metrics::counter");
        assert_eq!(violations[0].forbidden, "challenge_id");
    }

    #[test]
    fn guard_catches_a_forbidden_value_identifier() {
        let source = r#"
            fn example() {
                metrics::gauge!("x.value", "id" => normalize(merkle_root));
            }
        "#;

        let violations = metric_label_violations(source).expect("parse planted violation");

        assert_eq!(violations.len(), 1);
        assert_eq!(&source[violations[0].span.clone()], "merkle_root");
        assert_eq!(violations[0].macro_name, "metrics::gauge");
        assert_eq!(violations[0].forbidden, "merkle_root");
    }

    #[test]
    fn guard_ignores_forbidden_metric_names_values_and_larger_identifiers() {
        let source = r#"
            fn example(challenge_id_suffix: String) {
                metrics::counter!(
                    "challenge_id",
                    "description" => "credential_sub",
                    "id" => challenge_id_suffix,
                ).increment(1);
            }
        "#;

        assert!(metric_label_violations(source)
            .expect("parse allowed metric")
            .is_empty());
    }
}
