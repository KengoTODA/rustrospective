use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;

use crate::ir::Class;

/// Resolved classpath index keyed by class name.
pub(crate) struct ClasspathIndex {
    pub(crate) classes: BTreeMap<String, i64>,
}

pub(crate) fn resolve_classpath(classes: &[Class]) -> Result<ClasspathIndex> {
    let mut class_map: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    for class in classes {
        class_map
            .entry(class.name.clone())
            .or_default()
            .push(class.artifact_index);
    }

    let mut duplicates = Vec::new();
    for (name, indices) in &class_map {
        if indices.len() > 1 {
            duplicates.push(format!("{name}: {indices:?}"));
        }
    }
    if !duplicates.is_empty() {
        anyhow::bail!("duplicate classes found: {}", duplicates.join(", "));
    }

    let class_names: BTreeSet<String> = class_map.keys().cloned().collect();
    let mut missing = BTreeSet::new();
    for class in classes {
        for reference in &class.referenced_classes {
            if is_platform_class(reference) {
                continue;
            }
            if !class_names.contains(reference) {
                missing.insert(reference.clone());
            }
        }
    }
    let _missing = missing;

    let classes = class_map
        .into_iter()
        .map(|(name, indices)| {
            (
                name,
                indices.into_iter().next().expect("class indices not empty"),
            )
        })
        .collect();

    Ok(ClasspathIndex { classes })
}

fn is_platform_class(name: &str) -> bool {
    const PREFIXES: [&str; 5] = ["java/", "javax/", "jdk/", "sun/", "com/sun/"];
    PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_classpath_accepts_java_references() {
        let classes = vec![
            Class {
                name: "com/example/Foo".to_string(),
                super_name: None,
                referenced_classes: vec!["java/lang/Object".to_string()],
                methods: Vec::new(),
                artifact_index: 0,
            },
            Class {
                name: "com/example/Bar".to_string(),
                super_name: None,
                referenced_classes: Vec::new(),
                methods: Vec::new(),
                artifact_index: 1,
            },
        ];

        let result = resolve_classpath(&classes);

        assert!(result.is_ok());
    }

    #[test]
    fn resolve_classpath_allows_missing_classes() {
        let classes = vec![Class {
            name: "com/example/Foo".to_string(),
            super_name: None,
            referenced_classes: vec!["com/example/Bar".to_string()],
            methods: Vec::new(),
            artifact_index: 0,
        }];

        let result = resolve_classpath(&classes);

        assert!(result.is_ok());
    }

    #[test]
    fn resolve_classpath_rejects_duplicates() {
        let classes = vec![
            Class {
                name: "com/example/Foo".to_string(),
                super_name: None,
                referenced_classes: Vec::new(),
                methods: Vec::new(),
                artifact_index: 0,
            },
            Class {
                name: "com/example/Foo".to_string(),
                super_name: None,
                referenced_classes: Vec::new(),
                methods: Vec::new(),
                artifact_index: 1,
            },
        ];

        let result = resolve_classpath(&classes);

        assert!(result.is_err());
        let error = result.err().expect("duplicate class error");
        assert!(format!("{error:#}").contains("duplicate classes"));
    }
}
