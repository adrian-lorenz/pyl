// Copyright (c) 2026 Adrian Lorenz <a.lorenz@noa-x.de>
// SPDX-License-Identifier: MIT

pub mod config;
pub mod output;
pub mod rules;
pub mod scanner;

#[cfg(feature = "extension-module")]
mod python {
    use pyo3::prelude::*;

    use crate::config::Config;
    use crate::rules::builtin_rules;
    use crate::scanner::Scanner;

    #[pyclass(get_all)]
    #[derive(Clone)]
    pub struct PyFinding {
        pub rule_id: String,
        pub description: String,
        pub severity: String,
        pub line_number: usize,
        pub line: String,
        pub secret: String,
        pub tags: Vec<String>,
    }

    /// Scan text for secrets and return a list of findings.
    ///
    /// Arguments:
    ///   text: The text to scan for secrets.
    ///   disable_rules: Optional list of rule IDs to disable.
    #[pyfunction]
    #[pyo3(signature = (text, disable_rules=None))]
    fn scan_text(text: &str, disable_rules: Option<Vec<String>>) -> PyResult<Vec<PyFinding>> {
        let mut cfg = Config::default();
        if let Some(disabled) = disable_rules {
            cfg.rules.disable = disabled;
        }
        let rules = builtin_rules();
        let scanner = Scanner::new(rules, u64::MAX, &cfg)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let findings = scanner.scan_text(text, "<text>");
        Ok(findings
            .into_iter()
            .map(|f| PyFinding {
                rule_id: f.rule_id,
                description: f.description,
                severity: f.severity,
                line_number: f.line_number,
                line: f.line,
                secret: f.secret,
                tags: f.tags,
            })
            .collect())
    }

    #[pymodule]
    fn pyl(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(scan_text, m)?)?;
        m.add_class::<PyFinding>()?;
        Ok(())
    }
}
