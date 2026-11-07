//! Engine 3: Python PEP 552 (`.pyc`) Header, Timestamp Outlier & Marshal Bytecode Stub Engine.
//!
//! Recursively scans `/opt/cyops/` and `/opt/cyops-*` for compiled Python `.pyc` files,
//! parses 16-byte PEP 552 headers from exact binary offsets, detects single-file
//! recompilation/timestomp outliers via cohort median + MAD statistics, deserializes
//! CPython `marshal` code objects (Python 3.8–3.12+), and catches license/signature
//! verification functions short-circuited with `LOAD_CONST (True)` + `RETURN_VALUE`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::hex_encode;
use crate::hw_integrity::{join_rooted, raw_syscall_read_file};
use crate::schema::{EngineId, Finding, JsonValue, Severity};

/// Sensitive FortiSOAR licensing and cryptographic keywords targeted for bytecode stubbing.
pub const SENSITIVE_PYC_KEYWORDS: [&str; 7] = [
    "license",
    "validate",
    "expiry",
    "hw_id",
    "serial",
    "signature",
    "fortiguard",
];

/// CPython bytecode opcode constants (Python 3.8 – 3.12).
const OP_NOP: u8 = 9;
const OP_RETURN_VALUE: u8 = 83;
const OP_LOAD_CONST: u8 = 100;
const OP_RETURN_CONST_312: u8 = 121;
const OP_EXTENDED_ARG: u8 = 144;
const OP_RESUME_311: u8 = 151;

/// Python minor version layout family for `marshal` `TYPE_CODE` binary deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyCodeLayout {
    Py36To37,
    Py38To310,
    Py311To312,
    Unknown(u16),
}

impl PyCodeLayout {
    pub fn from_magic(magic_u16: u16) -> (Self, &'static str) {
        match magic_u16 {
            3360..=3379 => (PyCodeLayout::Py36To37, "3.6"),
            3390..=3399 => (PyCodeLayout::Py36To37, "3.7"),
            3400..=3419 => (PyCodeLayout::Py38To310, "3.8"),
            3420..=3429 => (PyCodeLayout::Py38To310, "3.9"),
            3430..=3449 => (PyCodeLayout::Py38To310, "3.10"),
            3450..=3499 => (PyCodeLayout::Py311To312, "3.11"),
            3500..=3549 => (PyCodeLayout::Py311To312, "3.12"),
            3550..=3599 => (PyCodeLayout::Py311To312, "3.13"),
            3600..=3699 => (PyCodeLayout::Py311To312, "3.14"),
            other => (PyCodeLayout::Unknown(other), "unknown"),
        }
    }
}

/// Binary representation of the 16-byte PEP 552 `.pyc` header (Python 3.7+).
#[derive(Debug, Clone)]
pub enum Pep552ValidationPayload {
    Timestamp {
        source_mtime_unix: u32,
        source_size_mod32: u32,
    },
    SipHash {
        check_source: bool,
        siphash64: u64,
    },
}

#[derive(Debug, Clone)]
pub struct Pep552Header {
    pub magic_number: u16,
    pub crlf_valid: bool,
    pub python_version: &'static str,
    pub code_layout: PyCodeLayout,
    pub bitfield: u32,
    pub payload: Pep552ValidationPayload,
    pub header_len: usize,
}

/// Parses the 16-byte PEP 552 header (`[0..4]` magic, `[4..8]` bitfield, `[8..16]` payload).
pub fn parse_pep552_header(bytes: &[u8]) -> Result<Pep552Header, String> {
    if bytes.len() < 16 {
        return Err(format!(
            "file truncated ({} bytes < 16-byte PEP 552 header)",
            bytes.len()
        ));
    }

    let magic_number = u16::from_le_bytes([bytes[0], bytes[1]]);
    let crlf_valid = bytes[2] == 0x0d && bytes[3] == 0x0a;
    let (code_layout, python_version) = PyCodeLayout::from_magic(magic_number);

    // Handle legacy 12-byte Python 3.6 `.pyc` if present alongside PEP 552 files on RHEL 8
    if python_version == "3.6" {
        let source_mtime_unix = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let source_size_mod32 = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        return Ok(Pep552Header {
            magic_number,
            crlf_valid,
            python_version,
            code_layout,
            bitfield: 0,
            payload: Pep552ValidationPayload::Timestamp {
                source_mtime_unix,
                source_size_mod32,
            },
            header_len: 12,
        });
    }

    let bitfield = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let payload = if (bitfield & 0x1) == 0 {
        let source_mtime_unix = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let source_size_mod32 = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        Pep552ValidationPayload::Timestamp {
            source_mtime_unix,
            source_size_mod32,
        }
    } else {
        let check_source = (bitfield & 0x2) != 0;
        let siphash64 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        Pep552ValidationPayload::SipHash {
            check_source,
            siphash64,
        }
    };

    Ok(Pep552Header {
        magic_number,
        crlf_valid,
        python_version,
        code_layout,
        bitfield,
        payload,
        header_len: 16,
    })
}

/// Deserialized CPython `marshal` CodeObject.
#[derive(Debug, Clone)]
pub struct PyCodeObject {
    pub co_argcount: i32,
    pub co_kwonlyargcount: i32,
    pub co_flags: i32,
    pub co_code: Vec<u8>,
    pub co_consts: Vec<MarshalObj>,
    pub co_names: Vec<String>,
    pub co_varnames: Vec<String>,
    pub co_filename: String,
    pub co_name: String,
    pub co_qualname: String,
    pub co_firstlineno: i32,
}

/// Subset of CPython `marshal` object graph required for static forensic inspection.
#[derive(Debug, Clone)]
pub enum MarshalObj {
    Null,
    NoneVal,
    Bool(bool),
    Int(i64),
    Float,
    Bytes(Vec<u8>),
    Str(String),
    Tuple(Vec<MarshalObj>),
    Code(Box<PyCodeObject>),
    Other,
}

struct MarshalReader<'a> {
    data: &'a [u8],
    pos: usize,
    layout: PyCodeLayout,
    refs: Vec<MarshalObj>,
    depth: usize,
}

impl<'a> MarshalReader<'a> {
    fn new(data: &'a [u8], layout: PyCodeLayout) -> Self {
        Self {
            data,
            pos: 0,
            layout,
            refs: Vec::new(),
            depth: 0,
        }
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| "EOF reading marshal u8".to_string())?;
        self.pos += 1;
        Ok(b)
    }

    fn read_i32(&mut self) -> Result<i32, String> {
        let s = self
            .data
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| "EOF reading marshal i32".to_string())?;
        self.pos += 4;
        Ok(i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        Ok(self.read_i32()? as u32)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| "marshal slice overflow".to_string())?;
        let s = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| "EOF reading marshal byte slice".to_string())?;
        self.pos = end;
        Ok(s)
    }

    fn reserve_ref(&mut self, flag_ref: bool) -> Option<usize> {
        if flag_ref {
            let idx = self.refs.len();
            self.refs.push(MarshalObj::NoneVal);
            Some(idx)
        } else {
            None
        }
    }

    fn store_ref(&mut self, slot: Option<usize>, obj: &MarshalObj) {
        if let Some(idx) = slot {
            if let Some(entry) = self.refs.get_mut(idx) {
                *entry = obj.clone();
            }
        }
    }

    fn read_object(&mut self) -> Result<MarshalObj, String> {
        if self.depth > 96 {
            return Err("marshal recursion depth exceeded".to_string());
        }
        self.depth += 1;
        let res = self.read_object_inner();
        self.depth -= 1;
        res
    }

    fn read_object_inner(&mut self) -> Result<MarshalObj, String> {
        let raw_code = self.read_u8()?;
        let flag_ref = (raw_code & 0x80) != 0;
        let kind = raw_code & 0x7f;

        match kind {
            b'0' => Ok(MarshalObj::Null),
            b'N' => Ok(MarshalObj::NoneVal),
            b'F' => Ok(MarshalObj::Bool(false)),
            b'T' => Ok(MarshalObj::Bool(true)),
            b'S' | b'.' => Ok(MarshalObj::Other),
            b'i' => {
                let slot = self.reserve_ref(flag_ref);
                let v = MarshalObj::Int(self.read_i32()? as i64);
                self.store_ref(slot, &v);
                Ok(v)
            }
            b'I' => {
                let slot = self.reserve_ref(flag_ref);
                let b = self.read_bytes(8)?;
                let v = MarshalObj::Int(i64::from_le_bytes(b.try_into().unwrap()));
                self.store_ref(slot, &v);
                Ok(v)
            }
            b'l' => {
                let slot = self.reserve_ref(flag_ref);
                let n = self.read_i32()?;
                let digits = (n.unsigned_abs() as usize).saturating_mul(2);
                let _ = self.read_bytes(digits)?;
                let v = MarshalObj::Int(if n == 0 { 0 } else { 1 });
                self.store_ref(slot, &v);
                Ok(v)
            }
            b'f' => {
                let slot = self.reserve_ref(flag_ref);
                let n = self.read_u8()? as usize;
                let _ = self.read_bytes(n)?;
                let v = MarshalObj::Float;
                self.store_ref(slot, &v);
                Ok(v)
            }
            b'g' => {
                let slot = self.reserve_ref(flag_ref);
                let _ = self.read_bytes(8)?;
                let v = MarshalObj::Float;
                self.store_ref(slot, &v);
                Ok(v)
            }
            b'x' => {
                let slot = self.reserve_ref(flag_ref);
                let n1 = self.read_u8()? as usize;
                let _ = self.read_bytes(n1)?;
                let n2 = self.read_u8()? as usize;
                let _ = self.read_bytes(n2)?;
                let v = MarshalObj::Other;
                self.store_ref(slot, &v);
                Ok(v)
            }
            b'y' => {
                let slot = self.reserve_ref(flag_ref);
                let _ = self.read_bytes(16)?;
                let v = MarshalObj::Other;
                self.store_ref(slot, &v);
                Ok(v)
            }
            b's' => {
                let slot = self.reserve_ref(flag_ref);
                let len = self.read_u32()? as usize;
                let bytes = self.read_bytes(len)?.to_vec();
                let v = MarshalObj::Bytes(bytes);
                self.store_ref(slot, &v);
                Ok(v)
            }
            b't' | b'u' | b'a' | b'A' => {
                let slot = self.reserve_ref(flag_ref);
                let len = self.read_u32()? as usize;
                let bytes = self.read_bytes(len)?;
                let v = MarshalObj::Str(String::from_utf8_lossy(bytes).into_owned());
                self.store_ref(slot, &v);
                Ok(v)
            }
            b'z' | b'Z' => {
                let slot = self.reserve_ref(flag_ref);
                let len = self.read_u8()? as usize;
                let bytes = self.read_bytes(len)?;
                let v = MarshalObj::Str(String::from_utf8_lossy(bytes).into_owned());
                self.store_ref(slot, &v);
                Ok(v)
            }
            b')' => {
                let slot = self.reserve_ref(flag_ref);
                let count = self.read_u8()? as usize;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.read_object()?);
                }
                let v = MarshalObj::Tuple(items);
                self.store_ref(slot, &v);
                Ok(v)
            }
            b'(' | b'[' | b'<' | b'>' => {
                let slot = self.reserve_ref(flag_ref);
                let count = self.read_u32()? as usize;
                if count > 1_000_000 {
                    return Err("unreasonable marshal sequence length".to_string());
                }
                let mut items = Vec::with_capacity(count.min(4096));
                for _ in 0..count {
                    items.push(self.read_object()?);
                }
                let v = MarshalObj::Tuple(items);
                self.store_ref(slot, &v);
                Ok(v)
            }
            b'{' => {
                let slot = self.reserve_ref(flag_ref);
                loop {
                    let k = self.read_object()?;
                    if matches!(k, MarshalObj::Null) {
                        break;
                    }
                    let _val = self.read_object()?;
                }
                let v = MarshalObj::Other;
                self.store_ref(slot, &v);
                Ok(v)
            }
            b'r' => {
                let idx = self.read_u32()? as usize;
                self.refs
                    .get(idx)
                    .cloned()
                    .ok_or_else(|| format!("invalid marshal TYPE_REF index {}", idx))
            }
            b'c' => {
                let slot = self.reserve_ref(flag_ref);
                let code_obj = self.read_code_object()?;
                let v = MarshalObj::Code(Box::new(code_obj));
                self.store_ref(slot, &v);
                Ok(v)
            }
            other => Err(format!("unsupported marshal tag 0x{:02x}", other)),
        }
    }

    fn read_code_object(&mut self) -> Result<PyCodeObject, String> {
        match self.layout {
            PyCodeLayout::Py38To310 => {
                let co_argcount = self.read_i32()?;
                let _co_posonlyargcount = self.read_i32()?;
                let co_kwonlyargcount = self.read_i32()?;
                let _co_nlocals = self.read_i32()?;
                let _co_stacksize = self.read_i32()?;
                let co_flags = self.read_i32()?;
                let co_code = extract_bytes(self.read_object()?)?;
                let co_consts = extract_tuple(self.read_object()?)?;
                let co_names = extract_str_tuple(self.read_object()?);
                let co_varnames = extract_str_tuple(self.read_object()?);
                let _co_freevars = self.read_object()?;
                let _co_cellvars = self.read_object()?;
                let co_filename = extract_str(self.read_object()?);
                let co_name = extract_str(self.read_object()?);
                let co_firstlineno = self.read_i32()?;
                let _co_lnotab = self.read_object()?;

                Ok(PyCodeObject {
                    co_argcount,
                    co_kwonlyargcount,
                    co_flags,
                    co_code,
                    co_consts,
                    co_names,
                    co_varnames,
                    co_filename,
                    co_qualname: co_name.clone(),
                    co_name,
                    co_firstlineno,
                })
            }
            PyCodeLayout::Py311To312 => {
                let co_argcount = self.read_i32()?;
                let _co_posonlyargcount = self.read_i32()?;
                let co_kwonlyargcount = self.read_i32()?;
                let _co_stacksize = self.read_i32()?;
                let co_flags = self.read_i32()?;
                let co_code = extract_bytes(self.read_object()?)?;
                let co_consts = extract_tuple(self.read_object()?)?;
                let co_names = extract_str_tuple(self.read_object()?);
                let co_varnames = extract_str_tuple(self.read_object()?);
                let _co_localspluskinds = self.read_object()?;
                let co_filename = extract_str(self.read_object()?);
                let co_name = extract_str(self.read_object()?);
                let co_qualname = extract_str(self.read_object()?);
                let co_firstlineno = self.read_i32()?;
                let _co_linetable = self.read_object()?;
                let _co_exceptiontable = self.read_object()?;

                Ok(PyCodeObject {
                    co_argcount,
                    co_kwonlyargcount,
                    co_flags,
                    co_code,
                    co_consts,
                    co_names,
                    co_varnames,
                    co_filename,
                    co_name,
                    co_qualname,
                    co_firstlineno,
                })
            }
            PyCodeLayout::Py36To37 => {
                let co_argcount = self.read_i32()?;
                let co_kwonlyargcount = self.read_i32()?;
                let _co_nlocals = self.read_i32()?;
                let _co_stacksize = self.read_i32()?;
                let co_flags = self.read_i32()?;
                let co_code = extract_bytes(self.read_object()?)?;
                let co_consts = extract_tuple(self.read_object()?)?;
                let co_names = extract_str_tuple(self.read_object()?);
                let co_varnames = extract_str_tuple(self.read_object()?);
                let _co_freevars = self.read_object()?;
                let _co_cellvars = self.read_object()?;
                let co_filename = extract_str(self.read_object()?);
                let co_name = extract_str(self.read_object()?);
                let co_firstlineno = self.read_i32()?;
                let _co_lnotab = self.read_object()?;

                Ok(PyCodeObject {
                    co_argcount,
                    co_kwonlyargcount,
                    co_flags,
                    co_code,
                    co_consts,
                    co_names,
                    co_varnames,
                    co_filename,
                    co_qualname: co_name.clone(),
                    co_name,
                    co_firstlineno,
                })
            }
            PyCodeLayout::Unknown(m) => {
                Err(format!("unsupported Python magic {} for marshal TYPE_CODE", m))
            }
        }
    }
}

fn extract_bytes(obj: MarshalObj) -> Result<Vec<u8>, String> {
    match obj {
        MarshalObj::Bytes(b) => Ok(b),
        _ => Err("expected marshal Bytes for co_code".to_string()),
    }
}

fn extract_tuple(obj: MarshalObj) -> Result<Vec<MarshalObj>, String> {
    match obj {
        MarshalObj::Tuple(t) => Ok(t),
        _ => Err("expected marshal Tuple for co_consts".to_string()),
    }
}

fn extract_str(obj: MarshalObj) -> String {
    match obj {
        MarshalObj::Str(s) => s,
        _ => String::new(),
    }
}

fn extract_str_tuple(obj: MarshalObj) -> Vec<String> {
    match obj {
        MarshalObj::Tuple(items) => items
            .into_iter()
            .filter_map(|i| match i {
                MarshalObj::Str(s) => Some(s),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Deserializes the root module `PyCodeObject` from the marshal payload following the PEP 552 header.
pub fn parse_marshaled_code_object(
    payload: &[u8],
    layout: PyCodeLayout,
) -> Result<PyCodeObject, String> {
    let mut reader = MarshalReader::new(payload, layout);
    match reader.read_object()? {
        MarshalObj::Code(c) => Ok(*c),
        _ => Err("root marshaled object in .pyc is not TYPE_CODE".to_string()),
    }
}

/// Checks whether a `PyCodeObject`'s entry wordcode immediately executes `LOAD_CONST (True)` + `RETURN_VALUE`
/// (handling Python 3.8–3.10 direct entry, Python 3.11 `RESUME 0` prologue, `NOP`, `EXTENDED_ARG`,
/// and Python 3.12 `RETURN_CONST (True)`).
pub fn detect_return_true_stub(code: &PyCodeObject) -> Option<(usize, Vec<u8>, Vec<String>)> {
    let bc = &code.co_code;
    if bc.len() < 2 || (bc.len() & 1) != 0 {
        return None;
    }

    let mut pc = 0usize;
    let mut trace = Vec::new();

    // Skip harmless function entry prologue instructions (e.g. Python 3.11 `RESUME 0` or `NOP`)
    while pc + 2 <= bc.len() {
        let op = bc[pc];
        let arg = bc[pc + 1];
        if op == OP_NOP {
            trace.push(format!("NOP {}", arg));
            pc += 2;
        } else if op == OP_RESUME_311 && arg == 0 {
            trace.push("RESUME 0".to_string());
            pc += 2;
        } else {
            break;
        }
    }

    // Decode optional EXTENDED_ARG prefix before first real instruction
    let mut ext_arg: usize = 0;
    while pc + 2 <= bc.len() && bc[pc] == OP_EXTENDED_ARG {
        ext_arg = (ext_arg << 8) | (bc[pc + 1] as usize);
        trace.push(format!("EXTENDED_ARG {}", bc[pc + 1]));
        pc += 2;
    }

    if pc + 2 > bc.len() {
        return None;
    }

    let op1 = bc[pc];
    let arg1 = (ext_arg << 8) | (bc[pc + 1] as usize);

    // Python 3.12+ superinstruction `RETURN_CONST (True)`
    if op1 == OP_RETURN_CONST_312 {
        if matches!(code.co_consts.get(arg1), Some(MarshalObj::Bool(true))) {
            trace.push(format!("RETURN_CONST {} (True)", arg1));
            let end = pc + 2;
            return Some((arg1, bc[..end].to_vec(), trace));
        }
        return None;
    }

    // Python 3.8 – 3.11 `LOAD_CONST (True)` immediately followed by `RETURN_VALUE`
    if op1 == OP_LOAD_CONST && matches!(code.co_consts.get(arg1), Some(MarshalObj::Bool(true))) {
        trace.push(format!("LOAD_CONST {} (True)", arg1));
        let next_pc = pc + 2;
        if next_pc + 2 <= bc.len() && bc[next_pc] == OP_RETURN_VALUE {
            trace.push("RETURN_VALUE".to_string());
            let end = next_pc + 2;
            return Some((arg1, bc[..end].to_vec(), trace));
        }
    }

    None
}

#[derive(Debug)]
struct ScannedPycRecord {
    logical_path: String,
    full_path: PathBuf,
    cohort: String,
    fs_mtime: i64,
    fs_ctime: i64,
    header: Pep552Header,
}

/// Output of Engine 3 (`pyc_inspector`).
pub struct PycInspectorResult {
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Runs Engine 3 across `/opt/cyops` and `/opt/cyops-*` under `root`.
pub fn run_pyc_inspector_audit(root: &Path) -> PycInspectorResult {
    let mut findings = Vec::new();
    let opt_dir = join_rooted(root, "opt");

    let mut target_roots: Vec<(String, PathBuf)> = Vec::new();
    if let Ok(entries) = fs::read_dir(&opt_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name == "cyops" || name.starts_with("cyops-") {
                    let p = entry.path();
                    if fs::symlink_metadata(&p)
                        .map(|m| m.is_dir())
                        .unwrap_or(false)
                    {
                        target_roots.push((format!("/opt/{}", name), p));
                    }
                }
            }
        }
    }
    if target_roots.is_empty()
        && (join_rooted(root, "server/csdassrv.py").is_file()
            || join_rooted(root, "handlerworkers").is_dir())
    {
        target_roots.push(("/opt/cyops-auth".to_string(), root.to_path_buf()));
    }
    target_roots.sort_by(|a, b| a.0.cmp(&b.0));

    let mut pyc_files: Vec<(String, String, PathBuf)> = Vec::new();
    for (cohort_name, dir_path) in &target_roots {
        collect_pyc_recursive(root, cohort_name, dir_path, &mut pyc_files);
    }
    pyc_files.sort_by(|a, b| a.1.cmp(&b.1));

    let mut records: Vec<ScannedPycRecord> = Vec::with_capacity(pyc_files.len());
    let mut sensitive_pyc_inspected = 0u64;
    let mut marshal_parsed_count = 0u64;

    for (cohort, logical_path, full_path) in pyc_files {
        let Some(bytes) = read_file_bytes(&full_path) else {
            continue;
        };
        let (fs_mtime, fs_ctime) = read_mtime_ctime(&full_path);

        let fname_lower = full_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_site_packages_root_pyc = (logical_path.contains("/site-packages/")
            && !logical_path
                .split("/site-packages/")
                .nth(1)
                .unwrap_or("")
                .trim_start_matches("__pycache__/")
                .contains('/'))
            && !fname_lower.starts_with("_virtualenv.");
        if is_site_packages_root_pyc || fname_lower.starts_with("usercustomize.") {
            findings.push(
                Finding::new(
                    EngineId::PycInspector,
                    "CRITICAL_COMPILED_STARTUP_PYC_HOOK",
                    Severity::Critical,
                    &logical_path,
                    format!(
                        "Compiled Python startup hook `{}` present in FortiSOAR cohort `{}` (executes before `cyops-auth` / services even if `.py` source was deleted)",
                        logical_path, cohort
                    ),
                )
                .with_evidence("cohort", JsonValue::str(&cohort)),
            );
        }

        // Check for forged FortiSOAR license claims / Cython `.so` shadowing literals embedded in `.pyc` bytecode
        for forged_marker in [
            "FSRVMPTM99999999",
            "FSR99999999",
            "MOCK-HARDWARE-UUID-KEY",
            "MOCK_CRYPTOGRAPHIC_LICENSE_DATA",
            "_SC_LICENSE_PAYLOAD",
            "FakeLicenseManager",
            "_guaranteed_execute",
        ] {
            if bytes
                .windows(forged_marker.len())
                .any(|w| w == forged_marker.as_bytes())
            {
                findings.push(
                    Finding::new(
                        EngineId::PycInspector,
                        "CRITICAL_PYC_MARSHAL_FORGED_LICENSE_PAYLOAD",
                        Severity::Critical,
                        &logical_path,
                        format!(
                            "Compiled `.pyc` file `{}` embeds forged FortiSOAR license / `sys.modules` Cython shadowing indicator `{}`",
                            logical_path, forged_marker
                        ),
                    )
                    .with_evidence("forged_indicator", JsonValue::str(forged_marker))
                    .with_evidence("cohort", JsonValue::str(&cohort)),
                );
                break;
            }
        }

        let header = match parse_pep552_header(&bytes) {
            Ok(h) => h,
            Err(err) => {
                findings.push(
                    Finding::new(
                        EngineId::PycInspector,
                        "HIGH_PYC_MALFORMED_PEP552_HEADER",
                        Severity::High,
                        &logical_path,
                        format!("Malformed PEP 552 header in {}: {}", logical_path, err),
                    )
                    .with_evidence("cohort", JsonValue::str(&cohort)),
                );
                continue;
            }
        };

        if !header.crlf_valid {
            findings.push(
                Finding::new(
                    EngineId::PycInspector,
                    "HIGH_PYC_INVALID_MAGIC_CRLF",
                    Severity::High,
                    &logical_path,
                    format!(
                        "Corrupted or manually forged .pyc magic terminator in {} (expected 0x0d0a)",
                        logical_path
                    ),
                )
                .with_evidence("magic_u16", JsonValue::Uint(header.magic_number as u64)),
            );
        }

        if (header.bitfield & !0x3) != 0 {
            findings.push(
                Finding::new(
                    EngineId::PycInspector,
                    "HIGH_PYC_INVALID_PEP552_BITFIELD",
                    Severity::High,
                    &logical_path,
                    format!(
                        "Reserved PEP 552 bitfield bits set (0x{:08x}) in {}",
                        header.bitfield, logical_path
                    ),
                )
                .with_evidence("bitfield", JsonValue::Uint(header.bitfield as u64)),
            );
        }

        // Parse marshaled code object and inspect sensitive modules/functions for bytecode stubbing
        if bytes.len() > header.header_len {
            let marshal_slice = &bytes[header.header_len..];
            let path_keywords = match_keywords(&logical_path);

            if let Ok(root_code) = parse_marshaled_code_object(marshal_slice, header.code_layout) {
                marshal_parsed_count += 1;
                let mut tree_keywords = path_keywords.clone();
                collect_code_tree_keywords(&root_code, &mut tree_keywords);

                if !tree_keywords.is_empty() {
                    sensitive_pyc_inspected += 1;
                    inspect_code_tree_for_stubs(
                        &logical_path,
                        &header,
                        &root_code,
                        &tree_keywords,
                        &mut findings,
                    );
                }
            } else if !path_keywords.is_empty() {
                // Fallback raw binary keyword/opcode scan if custom marshal obfuscation was applied
                sensitive_pyc_inspected += 1;
                findings.push(
                    Finding::new(
                        EngineId::PycInspector,
                        "HIGH_PYC_UNPARSABLE_SENSITIVE_MARSHAL",
                        Severity::High,
                        &logical_path,
                        format!(
                            "License/security-sensitive bytecode file {} failed standard CPython {} marshal deserialization (possible obfuscator or custom marshaler)",
                            logical_path, header.python_version
                        ),
                    )
                    .with_evidence("python_version", JsonValue::str(header.python_version))
                    .with_evidence(
                        "matched_keywords",
                        JsonValue::Array(path_keywords.into_iter().map(JsonValue::Str).collect()),
                    ),
                );
            }
        }

        records.push(ScannedPycRecord {
            logical_path,
            full_path,
            cohort,
            fs_mtime,
            fs_ctime,
            header,
        });
    }

    // Statistical Cohort Outlier Analysis (PEP 552 Header Timestamp vs Filesystem mtime/ctime)
    let cohort_summaries = analyze_cohort_timestamp_outliers(&records, &mut findings);

    let summary = JsonValue::OrderedObject(vec![
        (
            "scanned_roots".to_string(),
            JsonValue::Array(
                target_roots
                    .into_iter()
                    .map(|(logical, _)| JsonValue::Str(logical))
                    .collect(),
            ),
        ),
        (
            "total_pyc_files_scanned".to_string(),
            JsonValue::Uint(records.len() as u64),
        ),
        (
            "marshal_code_objects_parsed".to_string(),
            JsonValue::Uint(marshal_parsed_count),
        ),
        (
            "sensitive_pyc_files_audited".to_string(),
            JsonValue::Uint(sensitive_pyc_inspected),
        ),
        (
            "cohort_statistics".to_string(),
            JsonValue::Array(cohort_summaries),
        ),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    PycInspectorResult { summary, findings }
}

fn collect_pyc_recursive(
    root: &Path,
    cohort: &str,
    dir: &Path,
    out: &mut Vec<(String, String, PathBuf)>,
) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut children: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    children.sort();

    let dir_str = dir.to_string_lossy();
    let in_site_packages_root =
        dir_str.ends_with("/site-packages") || dir_str.ends_with("\\site-packages");

    for path in children {
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            if in_site_packages_root {
                let dname = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                if dname == "__pycache__"
                    || dname == "tornado"
                    || dname == "fsr"
                    || dname.starts_with("cyops")
                    || dname.starts_with("handler")
                {
                    collect_pyc_recursive(root, cohort, &path, out);
                }
            } else {
                collect_pyc_recursive(root, cohort, &path, out);
            }
        } else if meta.is_file()
            && path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("pyc"))
                .unwrap_or(false)
        {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let logical = format!("/{}", rel.to_string_lossy().trim_start_matches('/'));
            out.push((cohort.to_string(), logical, path));
        }
    }
}

fn match_keywords(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut hits = Vec::new();
    for kw in &SENSITIVE_PYC_KEYWORDS {
        if lower.contains(kw) {
            hits.push((*kw).to_string());
        }
    }
    hits
}

fn push_matched_keywords(text: &str, acc: &mut Vec<String>) {
    for kw in match_keywords(text) {
        if !acc.contains(&kw) {
            acc.push(kw);
        }
    }
}

fn collect_code_tree_keywords(code: &PyCodeObject, acc: &mut Vec<String>) {
    push_matched_keywords(&code.co_name, acc);
    push_matched_keywords(&code.co_qualname, acc);
    push_matched_keywords(&code.co_filename, acc);
    for n in &code.co_names {
        push_matched_keywords(n, acc);
    }
    for v in &code.co_varnames {
        push_matched_keywords(v, acc);
    }
    for c in &code.co_consts {
        match c {
            MarshalObj::Str(s) => push_matched_keywords(s, acc),
            MarshalObj::Tuple(items) => {
                for item in items {
                    if let MarshalObj::Str(s) = item {
                        push_matched_keywords(s, acc);
                    }
                }
            }
            MarshalObj::Code(child) => collect_code_tree_keywords(child, acc),
            _ => {}
        }
    }
    acc.sort();
}

fn inspect_code_tree_for_stubs(
    logical_path: &str,
    header: &Pep552Header,
    code: &PyCodeObject,
    file_keywords: &[String],
    findings: &mut Vec<Finding>,
) {
    // Exclude synthetic module/comprehension/lambda wrappers; inspect real functions & methods
    let is_named_callable = !code.co_name.starts_with('<') && !code.co_name.is_empty();
    if is_named_callable {
        if let Some((const_idx, stub_bytes, disasm)) = detect_return_true_stub(code) {
            let mut local_kw = match_keywords(&code.co_qualname);
            for kw in match_keywords(&code.co_name) {
                if !local_kw.contains(&kw) {
                    local_kw.push(kw);
                }
            }

            // Flag as CRITICAL when the function itself carries a sensitive validation/license name
            // OR takes arguments that are completely ignored in a sensitive licensing module.
            let ignores_arguments = (code.co_argcount + code.co_kwonlyargcount) > 0;
            if !local_kw.is_empty() || ignores_arguments {
                let effective_keywords = if !local_kw.is_empty() {
                    local_kw
                } else {
                    file_keywords.to_vec()
                };

                findings.push(
                    Finding::new(
                        EngineId::PycInspector,
                        "CRITICAL_PYC_BYTECODE_RETURN_TRUE_STUB",
                        Severity::Critical,
                        format!("{}::{}", logical_path, code.co_qualname),
                        format!(
                            "Short-circuited Python {} function `{}` (line {}) in {} immediately executes LOAD_CONST(True) + RETURN_VALUE",
                            header.python_version,
                            code.co_qualname,
                            code.co_firstlineno,
                            logical_path
                        ),
                    )
                    .with_evidence("pyc_path", JsonValue::str(logical_path))
                    .with_evidence("python_version", JsonValue::str(header.python_version))
                    .with_evidence("magic_number", JsonValue::Uint(header.magic_number as u64))
                    .with_evidence("function_name", JsonValue::str(&code.co_name))
                    .with_evidence("qualname", JsonValue::str(&code.co_qualname))
                    .with_evidence("first_lineno", JsonValue::Int(code.co_firstlineno as i64))
                    .with_evidence("argcount", JsonValue::Int(code.co_argcount as i64))
                    .with_evidence("true_const_index", JsonValue::Uint(const_idx as u64))
                    .with_evidence("stub_bytecode_hex", JsonValue::str(hex_encode(&stub_bytes)))
                    .with_evidence(
                        "disassembly",
                        JsonValue::Array(disasm.into_iter().map(JsonValue::Str).collect()),
                    )
                    .with_evidence(
                        "matched_keywords",
                        JsonValue::Array(
                            effective_keywords.into_iter().map(JsonValue::Str).collect(),
                        ),
                    ),
                );
            }
        }
    }

    for constant in &code.co_consts {
        if let MarshalObj::Code(child) = constant {
            inspect_code_tree_for_stubs(logical_path, header, child, file_keywords, findings);
        }
    }
}

fn analyze_cohort_timestamp_outliers(
    records: &[ScannedPycRecord],
    findings: &mut Vec<Finding>,
) -> Vec<JsonValue> {
    let mut by_cohort: BTreeMap<&str, Vec<&ScannedPycRecord>> = BTreeMap::new();
    for rec in records {
        by_cohort.entry(rec.cohort.as_str()).or_default().push(rec);
    }

    let mut summaries = Vec::new();

    for (cohort, group) in by_cohort {
        let mut hdr_timestamps: Vec<i64> = Vec::new();
        let mut mtimes: Vec<i64> = Vec::new();
        let mut ctimes: Vec<i64> = Vec::new();
        let mut hash_based_count = 0usize;

        for rec in &group {
            mtimes.push(rec.fs_mtime);
            ctimes.push(rec.fs_ctime);
            match rec.header.payload {
                Pep552ValidationPayload::Timestamp {
                    source_mtime_unix, ..
                } => hdr_timestamps.push(source_mtime_unix as i64),
                Pep552ValidationPayload::SipHash { .. } => hash_based_count += 1,
            }
        }

        let (med_hdr, mad_hdr) = median_and_mad(&mut hdr_timestamps);
        let (med_mtime, mad_mtime) = median_and_mad(&mut mtimes);
        let (med_ctime, mad_ctime) = median_and_mad(&mut ctimes);

        summaries.push(JsonValue::OrderedObject(vec![
            ("cohort".to_string(), JsonValue::str(cohort)),
            ("pyc_count".to_string(), JsonValue::Uint(group.len() as u64)),
            (
                "median_header_timestamp".to_string(),
                JsonValue::Int(med_hdr),
            ),
            ("mad_header_timestamp".to_string(), JsonValue::Int(mad_hdr)),
            ("median_fs_mtime".to_string(), JsonValue::Int(med_mtime)),
            ("median_fs_ctime".to_string(), JsonValue::Int(med_ctime)),
            (
                "siphash_pyc_count".to_string(),
                JsonValue::Uint(hash_based_count as u64),
            ),
        ]));

        // Require at least 5 files in a cohort to establish a reliable statistical baseline
        if group.len() < 5 {
            continue;
        }

        // Detect foreign Python interpreter version `.pyc` contamination (e.g. `.cpython-314.pyc`
        // left behind by an external workstation inside a Python 3.9 `/opt/cyops-auth` tree).
        let mut version_counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        for rec in &group {
            *version_counts.entry(rec.header.python_version).or_insert(0) += 1;
        }
        if let Some((&dominant_py_ver, &dominant_cnt)) =
            version_counts.iter().max_by_key(|(_, &cnt)| cnt)
        {
            if dominant_cnt * 4 >= group.len() * 3 {
                for rec in &group {
                    if rec.header.python_version != dominant_py_ver {
                        findings.push(
                            Finding::new(
                                EngineId::PycInspector,
                                "MEDIUM_FOREIGN_PYTHON_VERSION_PYC_ARTIFACT",
                                Severity::Medium,
                                &rec.logical_path,
                                format!(
                                    "Foreign Python {} bytecode file `{}` (magic={}) found inside Python {} cohort `{}` — indicates package was unpacked or executed on an external host",
                                    rec.header.python_version,
                                    rec.logical_path,
                                    rec.header.magic_number,
                                    dominant_py_ver,
                                    cohort
                                ),
                            )
                            .with_evidence("file_python_version", JsonValue::str(rec.header.python_version))
                            .with_evidence("cohort_dominant_python_version", JsonValue::str(dominant_py_ver))
                            .with_evidence("magic_u16", JsonValue::Uint(rec.header.magic_number as u64))
                            .with_evidence("cohort", JsonValue::str(cohort)),
                        );
                    }
                }
            }
        }

        let hdr_threshold = (mad_hdr.saturating_mul(6)).max(3600);
        let fs_mtime_threshold = (mad_mtime.saturating_mul(6)).max(3600);
        let fs_ctime_threshold = (mad_ctime.saturating_mul(6)).max(3600);

        for rec in &group {
            let _ = &rec.full_path;
            let sensitive_path = !match_keywords(&rec.logical_path).is_empty();

            match rec.header.payload {
                Pep552ValidationPayload::Timestamp {
                    source_mtime_unix,
                    source_size_mod32,
                } => {
                    let hdr_ts = source_mtime_unix as i64;
                    let hdr_delta = (hdr_ts - med_hdr).abs();
                    let mtime_delta = (rec.fs_mtime - med_mtime).abs();
                    let ctime_delta = (rec.fs_ctime - med_ctime).abs();

                    let hdr_is_outlier = !hdr_timestamps.is_empty() && hdr_delta > hdr_threshold;
                    let fs_is_outlier =
                        mtime_delta > fs_mtime_threshold || ctime_delta > fs_ctime_threshold;

                    if hdr_is_outlier || fs_is_outlier {
                        let severity = if sensitive_path && hdr_is_outlier {
                            Severity::Critical
                        } else {
                            Severity::High
                        };
                        let code = if hdr_is_outlier {
                            "HIGH_PYC_RECOMPILED_TIMESTAMP_OUTLIER"
                        } else {
                            "HIGH_PYC_FILESYSTEM_TIMESTOMP_OR_REPLACE"
                        };

                        findings.push(
                            Finding::new(
                                EngineId::PycInspector,
                                code,
                                severity,
                                &rec.logical_path,
                                format!(
                                    "Statistical PEP 552 / filesystem timestamp outlier in {} (header_ts={}, cohort_median={}, mtime_delta={}s, ctime_delta={}s)",
                                    rec.logical_path, hdr_ts, med_hdr, mtime_delta, ctime_delta
                                ),
                            )
                            .with_evidence("cohort", JsonValue::str(cohort))
                            .with_evidence("header_timestamp", JsonValue::Int(hdr_ts))
                            .with_evidence("cohort_median_header_timestamp", JsonValue::Int(med_hdr))
                            .with_evidence("header_delta_seconds", JsonValue::Int(hdr_delta))
                            .with_evidence("source_size_mod32", JsonValue::Uint(source_size_mod32 as u64))
                            .with_evidence("fs_mtime", JsonValue::Int(rec.fs_mtime))
                            .with_evidence("cohort_median_mtime", JsonValue::Int(med_mtime))
                            .with_evidence("fs_ctime", JsonValue::Int(rec.fs_ctime))
                            .with_evidence("cohort_median_ctime", JsonValue::Int(med_ctime))
                            .with_evidence("sensitive_module_path", JsonValue::Bool(sensitive_path)),
                        );
                    }
                }
                Pep552ValidationPayload::SipHash {
                    check_source,
                    siphash64,
                } => {
                    // Flag an isolated `unchecked-hash` PEP 552 .pyc inside a timestamp-compiled RPM package
                    if !check_source && hash_based_count * 5 < group.len() {
                        let severity = if sensitive_path {
                            Severity::Critical
                        } else {
                            Severity::High
                        };
                        findings.push(
                            Finding::new(
                                EngineId::PycInspector,
                                "HIGH_PYC_UNCHECKED_SIPHASH_ANOMALY",
                                severity,
                                &rec.logical_path,
                                format!(
                                    "PEP 552 unchecked-hash .pyc (bitfield=0x{:x}) bypasses .py source verification inside timestamp-based package {}",
                                    rec.header.bitfield, cohort
                                ),
                            )
                            .with_evidence("bitfield", JsonValue::Uint(rec.header.bitfield as u64))
                            .with_evidence(
                                "siphash64_hex",
                                JsonValue::str(format!("0x{:016x}", siphash64)),
                            )
                            .with_evidence("cohort", JsonValue::str(cohort)),
                        );
                    }
                }
            }
        }
    }

    summaries
}

fn median_and_mad(values: &mut [i64]) -> (i64, i64) {
    if values.is_empty() {
        return (0, 0);
    }
    values.sort_unstable();
    let mid = values.len() / 2;
    let med = if values.len() % 2 == 1 {
        values[mid]
    } else {
        values[mid - 1] + (values[mid] - values[mid - 1]) / 2
    };

    let mut deviations: Vec<i64> = values.iter().map(|&v| (v - med).abs()).collect();
    deviations.sort_unstable();
    let mad = if deviations.len() % 2 == 1 {
        deviations[mid]
    } else {
        deviations[mid - 1] + (deviations[mid] - deviations[mid - 1]) / 2
    };
    (med, mad)
}

fn read_file_bytes(path: &Path) -> Option<Vec<u8>> {
    match raw_syscall_read_file(path) {
        Ok(b) => Some(b),
        Err(_) => fs::read(path).ok(),
    }
}

fn read_mtime_ctime(path: &Path) -> (i64, i64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(m) = fs::symlink_metadata(path) {
            return (m.mtime(), m.ctime());
        }
        (0, 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        (0, 0)
    }
}
