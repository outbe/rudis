use std::{
    collections::BTreeSet,
    fmt::Write as _,
    path::{Path, PathBuf},
};

use alloy_primitives::keccak256;
use eyre::{bail, ensure, Context, Result};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RowKind {
    Object,
    Domain,
    List,
}

impl RowKind {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "object" => Ok(Self::Object),
            "domain" => Ok(Self::Domain),
            "list" => Ok(Self::List),
            value => {
                bail!("unknown registry row type {value:?}");
            }
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Object => "object",
            Self::Domain => "domain",
            Self::List => "list",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Row {
    kind: RowKind,
    identifier: String,
    variant: String,
    wire: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InputCodecRow {
    role_id: u16,
    variant: String,
    version: u16,
    constant: String,
    descriptor: String,
}

pub fn run(repository_root: &Path, check: bool) -> Result<()> {
    let crate_root = repository_root.join("crates/system/ocomp-protocol");
    let source = crate_root.join("registry/ocomp-v1.tsv");
    let input_codec_source = crate_root.join("registry/input-codecs-v1.tsv");
    let rows = load_rows(&source)?;
    let input_codecs = load_input_codecs(&input_codec_source)?;
    let outputs = [(
        crate_root.join("src/generated_registry.rs"),
        render_rust(&rows, &input_codecs)?,
    )];
    for (path, output) in outputs {
        update_or_check(repository_root, &path, output, check)?;
    }
    Ok(())
}

fn load_input_codecs(path: &Path) -> Result<Vec<InputCodecRow>> {
    let contents = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("failed reading {}", path.display()))?;
    let mut lines = contents.lines();
    ensure!(
        lines.next() == Some("role_id\tvariant\tversion\tconstant\tdescriptor"),
        "unexpected OCOMP input codec TSV header"
    );
    let mut rows = Vec::new();
    for (index, line) in lines.enumerate() {
        if line.is_empty() {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        ensure!(
            fields.len() == 5,
            "input codec line {} has {} fields, expected 5",
            index + 2,
            fields.len()
        );
        rows.push(InputCodecRow {
            role_id: fields[0]
                .parse()
                .wrap_err_with(|| format!("invalid input codec role at line {}", index + 2))?,
            variant: fields[1].to_owned(),
            version: fields[2]
                .parse()
                .wrap_err_with(|| format!("invalid input codec version at line {}", index + 2))?,
            constant: fields[3].to_owned(),
            descriptor: fields[4].to_owned(),
        });
    }
    ensure!(
        rows.len() == 3,
        "Lysis V1 requires exactly three input codecs"
    );
    ensure_unique_values("input codec role", rows.iter().map(|row| row.role_id))?;
    ensure_unique_values(
        "input codec variant",
        rows.iter().map(|row| row.variant.as_str()),
    )?;
    ensure_unique_values(
        "input codec constant",
        rows.iter().map(|row| row.constant.as_str()),
    )?;
    ensure!(
        rows.iter().all(|row| {
            row.role_id > 0
                && row.version > 0
                && !row.descriptor.is_empty()
                && row.descriptor.is_ascii()
        }),
        "input codec descriptors must be non-empty ASCII with non-zero role/version"
    );
    ensure!(
        rows.iter().map(|row| row.role_id).eq([1, 2, 3]),
        "input codec roles must be canonical 1,2,3 order"
    );
    Ok(rows)
}

fn ensure_unique_values<T: Ord + std::fmt::Debug>(
    what: &str,
    values: impl IntoIterator<Item = T>,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure!(seen.insert(value), "duplicate {what}");
    }
    Ok(())
}

fn load_rows(path: &Path) -> Result<Vec<Row>> {
    let contents = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("failed reading {}", path.display()))?;
    let mut lines = contents.lines();
    ensure!(
        lines.next() == Some("type\tid\tvariant\twire"),
        "unexpected OCOMP registry TSV header"
    );
    let mut rows = Vec::new();
    for (index, line) in lines.enumerate() {
        if line.is_empty() {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        ensure!(
            fields.len() == 4,
            "registry line {} has {} fields, expected 4",
            index + 2,
            fields.len()
        );
        rows.push(Row {
            kind: RowKind::parse(fields[0])?,
            identifier: fields[1].to_owned(),
            variant: fields[2].to_owned(),
            wire: fields[3].to_owned(),
        });
    }
    validate_rows(&rows)?;
    Ok(rows)
}

fn validate_rows(rows: &[Row]) -> Result<()> {
    for kind in [RowKind::Object, RowKind::Domain, RowKind::List] {
        let selected = rows
            .iter()
            .filter(|row| row.kind == kind)
            .collect::<Vec<_>>();
        ensure!(!selected.is_empty(), "registry has no {} rows", kind.name());
        ensure_unique(
            kind,
            "variant",
            selected.iter().map(|row| row.variant.as_str()),
        )?;
        ensure_unique(kind, "wire", selected.iter().map(|row| row.wire.as_str()))?;
        ensure!(
            selected.iter().all(|row| row.wire.is_ascii()),
            "{} registry contains non-ASCII wire value",
            kind.name()
        );

        if kind == RowKind::Domain {
            ensure!(
                selected.iter().all(|row| row.identifier.is_empty()),
                "domain rows must not have numeric identifiers"
            );
        } else {
            let mut identifiers = BTreeSet::new();
            for row in selected {
                ensure!(
                    !row.identifier.is_empty(),
                    "{} row {} has no identifier",
                    kind.name(),
                    row.variant
                );
                let value = parse_identifier(&row.identifier)?;
                ensure!(
                    identifiers.insert(value),
                    "duplicate normalized {} identifier {}",
                    kind.name(),
                    row.identifier
                );
            }
        }
    }
    Ok(())
}

fn ensure_unique<'a>(
    kind: RowKind,
    field: &str,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure!(
            seen.insert(value),
            "duplicate {} {field} {value:?}",
            kind.name()
        );
    }
    Ok(())
}

fn parse_identifier(value: &str) -> Result<u16> {
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        u16::from_str_radix(hex, 16)
    } else {
        value.parse()
    };
    parsed.wrap_err_with(|| format!("invalid u16 registry identifier {value:?}"))
}

fn render_rust(rows: &[Row], input_codecs: &[InputCodecRow]) -> Result<String> {
    let objects = rows_for(rows, RowKind::Object);
    let domains = rows_for(rows, RowKind::Domain);
    let lists = rows_for(rows, RowKind::List);
    let mut output = String::from(
        "// @generated by cargo xtask ocomp registry from registry/ocomp-v1.tsv.\n\
         // Do not edit by hand.\n\n",
    );
    output.push_str(&render_numeric_enum(
        "ObjectKind",
        "u16",
        &objects,
        "UnknownObjectKind",
        "tag",
    )?);
    output.push_str(
        "#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]\n\
         pub enum HashDomain {\n",
    );
    for row in &domains {
        writeln!(output, "    {},", row.variant)?;
    }
    output.push_str("}\n\nimpl HashDomain {\n    pub const ALL: &'static [Self] = &[\n");
    for row in &domains {
        writeln!(output, "        Self::{},", row.variant)?;
    }
    output.push_str(
        "    ];\n\n    #[must_use]\n    pub const fn as_str(self) -> &'static str {\n\
         \x20       match self {\n",
    );
    for row in &domains {
        writeln!(
            output,
            "            Self::{} => {:?},",
            row.variant, row.wire
        )?;
    }
    output.push_str("        }\n    }\n}\n\n");
    output.push_str(&render_numeric_enum(
        "ListKind",
        "u16",
        &lists,
        "UnknownListKind",
        "id",
    )?);
    output.push_str(&render_input_codec_constants(input_codecs)?);
    Ok(output)
}

fn render_input_codec_constants(rows: &[InputCodecRow]) -> Result<String> {
    let mut output = String::new();
    for row in rows {
        let descriptor_constant = format!(
            "{}_DESCRIPTOR",
            row.constant
                .strip_suffix("_ID")
                .expect("validated codec ID constant")
        );
        writeln!(
            output,
            "\npub const {descriptor_constant}: &str = {:?};",
            row.descriptor
        )?;
        writeln!(
            output,
            "pub const {}: alloy_primitives::B256 = alloy_primitives::B256::new({:?});",
            row.constant,
            codec_id(row).0
        )?;
    }
    let fidelity = rows
        .iter()
        .find(|row| row.role_id == 2)
        .expect("validated Fidelity codec");
    let oracle = rows
        .iter()
        .find(|row| row.role_id == 3)
        .expect("validated Oracle codec");
    writeln!(
        output,
        "\npub const OPENING_CODEC_REGISTRY_HASH: alloy_primitives::B256 = alloy_primitives::B256::new({:?});",
        opening_codec_registry_hash(codec_id(fidelity), codec_id(oracle)).0
    )?;
    Ok(output)
}

fn codec_id(row: &InputCodecRow) -> alloy_primitives::B256 {
    let descriptor = row.descriptor.as_bytes();
    let mut payload = Vec::with_capacity(8 + descriptor.len());
    payload.extend_from_slice(&row.role_id.to_be_bytes());
    payload.extend_from_slice(&row.version.to_be_bytes());
    payload.extend_from_slice(
        &u32::try_from(descriptor.len())
            .expect("validated descriptor length fits u32")
            .to_be_bytes(),
    );
    payload.extend_from_slice(descriptor);
    framed_hash("OUTBE_OCOMP_CODEC_DESCRIPTOR_V1", &payload)
}

fn opening_codec_registry_hash(
    fidelity: alloy_primitives::B256,
    oracle: alloy_primitives::B256,
) -> alloy_primitives::B256 {
    let mut payload = Vec::with_capacity(68);
    payload.extend_from_slice(&2_u16.to_be_bytes());
    payload.push(1);
    payload.extend_from_slice(fidelity.as_slice());
    payload.push(2);
    payload.extend_from_slice(oracle.as_slice());
    framed_hash("OUTBE_OCOMP_OPENING_CODEC_REGISTRY_V1", &payload)
}

fn framed_hash(domain: &str, payload: &[u8]) -> alloy_primitives::B256 {
    let domain = domain.as_bytes();
    let mut preimage = Vec::with_capacity(6 + domain.len() + payload.len());
    preimage.extend_from_slice(
        &u16::try_from(domain.len())
            .expect("registered domain length fits u16")
            .to_be_bytes(),
    );
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("generated payload length fits u32")
            .to_be_bytes(),
    );
    preimage.extend_from_slice(payload);
    keccak256(preimage)
}

fn render_numeric_enum(
    name: &str,
    repr_type: &str,
    rows: &[&Row],
    unknown_error: &str,
    id_method: &str,
) -> Result<String> {
    let mut output = format!(
        "#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]\n\
         #[repr({repr_type})]\n\
         pub enum {name} {{\n"
    );
    for row in rows {
        writeln!(output, "    {} = {},", row.variant, row.identifier)?;
    }
    writeln!(
        output,
        "}}\n\nimpl {name} {{\n    pub const ALL: &'static [Self] = &["
    )?;
    for row in rows {
        writeln!(output, "        Self::{},", row.variant)?;
    }
    write!(
        output,
        "    ];\n\n    #[must_use]\n    pub const fn {id_method}(self) -> {repr_type} {{\n\
         \x20       self as {repr_type}\n\
         \x20   }}\n\n\
         \x20   #[must_use]\n\
         \x20   pub const fn name(self) -> &'static str {{\n\
         \x20       match self {{\n"
    )?;
    for row in rows {
        writeln!(
            output,
            "            Self::{} => {:?},",
            row.variant, row.wire
        )?;
    }
    write!(
        output,
        "        }}\n    }}\n}}\n\n\
         impl TryFrom<{repr_type}> for {name} {{\n\
         \x20   type Error = crate::error::ProtocolError;\n\n\
         \x20   fn try_from(value: {repr_type}) -> Result<Self, Self::Error> {{\n\
         \x20       match value {{\n"
    )?;
    for row in rows {
        writeln!(
            output,
            "            {} => Ok(Self::{}),",
            row.identifier, row.variant
        )?;
    }
    write!(
        output,
        "            value => Err(crate::error::ProtocolError::{unknown_error}(value)),\n\
         \x20       }}\n    }}\n}}\n"
    )?;
    Ok(output)
}

fn rows_for(rows: &[Row], kind: RowKind) -> Vec<&Row> {
    rows.iter().filter(|row| row.kind == kind).collect()
}

fn update_or_check(repository_root: &Path, path: &Path, output: String, check: bool) -> Result<()> {
    let mut expected = output;
    if !expected.ends_with('\n') {
        expected.push('\n');
    }
    let actual = std::fs::read_to_string(path).ok();
    if actual.as_deref() == Some(expected.as_str()) {
        return Ok(());
    }
    let display = relative_path(repository_root, path);
    if check {
        bail!("stale generated OCOMP registry: {}", display.display());
    }
    std::fs::write(path, expected)
        .wrap_err_with(|| format!("failed writing {}", path.display()))?;
    println!("wrote {}", display.display());
    Ok(())
}

fn relative_path(repository_root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(repository_root)
        .unwrap_or(path)
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_collisions_are_normalized() {
        let rows = [
            Row {
                kind: RowKind::Object,
                identifier: "1".to_owned(),
                variant: "One".to_owned(),
                wire: "One".to_owned(),
            },
            Row {
                kind: RowKind::Object,
                identifier: "0x0001".to_owned(),
                variant: "AlsoOne".to_owned(),
                wire: "AlsoOne".to_owned(),
            },
            Row {
                kind: RowKind::Domain,
                identifier: String::new(),
                variant: "Domain".to_owned(),
                wire: "DOMAIN_V1".to_owned(),
            },
            Row {
                kind: RowKind::List,
                identifier: "1".to_owned(),
                variant: "List".to_owned(),
                wire: "list".to_owned(),
            },
        ];
        assert!(validate_rows(&rows)
            .unwrap_err()
            .to_string()
            .contains("duplicate normalized object identifier"));
    }

    #[test]
    fn checked_in_registry_is_current() {
        run(&crate::release::sgx::repository_root().unwrap(), true).unwrap();
    }
}
