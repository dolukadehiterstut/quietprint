use std::fs;
use std::process::Command;

fn quietprint() -> Command {
    Command::new(env!("CARGO_BIN_EXE_quietprint"))
}

#[test]
fn help_lists_milestone_commands() {
    let output = quietprint().arg("--help").output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(output.status.success());
    assert!(stdout.contains("analyze"));
    assert!(stdout.contains("live"));
    assert!(stdout.contains("learn"));
    assert!(stdout.contains("validate-signatures"));
}

#[test]
fn validate_signatures_skeleton_succeeds() {
    let output = quietprint().args(["validate-signatures"]).output().unwrap();

    assert!(output.status.success());
}

#[test]
fn top_limit_accepts_50_and_rejects_51() {
    let accepted = quietprint()
        .args(["analyze", "missing.pcap", "--top", "50"])
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&accepted.stderr).contains("invalid value"));

    let rejected = quietprint()
        .args(["analyze", "missing.pcap", "--top", "51"])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("invalid value"));
}

#[test]
fn rejects_conflicting_output_formats() {
    let output = quietprint()
        .args(["analyze", "missing.pcap", "--json", "--csv"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("choose only one output format"));
}

fn synthetic_ipv4_syn_pcap() -> Vec<u8> {
    let mut frame = vec![0u8; 14 + 20 + 44];
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    frame[14] = 0x45;
    frame[15] = 0;
    frame[16..18].copy_from_slice(&64u16.to_be_bytes());
    frame[18..20].copy_from_slice(&0x1234u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&[192, 0, 2, 10]);
    frame[30..34].copy_from_slice(&[198, 51, 100, 20]);

    let tcp = &mut frame[34..];
    tcp[0..2].copy_from_slice(&49152u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
    tcp[4..8].copy_from_slice(&100u32.to_be_bytes());
    tcp[12] = 11 << 4;
    tcp[13] = 0x02;
    tcp[14..16].copy_from_slice(&14600u16.to_be_bytes());
    tcp[20..24].copy_from_slice(&[2, 4, 0x05, 0xb4]);
    tcp[24] = 1;
    tcp[25..28].copy_from_slice(&[3, 3, 7]);
    tcp[28..30].copy_from_slice(&[4, 2]);
    tcp[30..40].copy_from_slice(&[8, 10, 0, 0, 0, 1, 0, 0, 0, 0]);
    tcp[40..44].copy_from_slice(&[1, 0, 1, 0]);

    let mut pcap = Vec::new();
    pcap.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes());

    pcap.extend_from_slice(&1u32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    pcap.extend_from_slice(&frame);
    pcap
}

fn synthetic_pcap_with_server_synack() -> Vec<u8> {
    let mut pcap = synthetic_ipv4_syn_pcap();
    let mut packet_record = pcap[24..].to_vec();
    let frame = &mut packet_record[16..];
    frame[26..30].copy_from_slice(&[198, 51, 100, 20]);
    frame[30..34].copy_from_slice(&[192, 0, 2, 10]);
    frame[34..36].copy_from_slice(&443u16.to_be_bytes());
    frame[36..38].copy_from_slice(&49152u16.to_be_bytes());
    frame[42..46].copy_from_slice(&101u32.to_be_bytes());
    frame[47] = 0x12;
    pcap.extend_from_slice(&packet_record);
    pcap
}

#[test]
fn analyze_detects_synthetic_ipv4_syn_from_pcap() {
    let path =
        std::env::temp_dir().join(format!("quietprint-detection-{}.pcap", std::process::id()));
    fs::write(&path, synthetic_ipv4_syn_pcap()).unwrap();

    let output = quietprint()
        .args(["analyze"])
        .arg(&path)
        .arg("--json")
        .output()
        .unwrap();
    let _ = fs::remove_file(&path);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("\"direction\":\"client\""), "{stdout}");
    assert!(stdout.contains("\"source_ip\":\"192.0.2.10\""), "{stdout}");
    assert!(stdout.contains("\"mss\":1460"), "{stdout}");
    assert!(stdout.contains("\"window_scale\":7"), "{stdout}");
    assert!(stdout.contains("\"family\":\"Linux\""), "{stdout}");
}

#[test]
fn text_direction_filter_hides_observations_from_the_other_direction() {
    let path =
        std::env::temp_dir().join(format!("quietprint-direction-{}.pcap", std::process::id()));
    fs::write(&path, synthetic_pcap_with_server_synack()).unwrap();

    let output = quietprint()
        .args(["analyze"])
        .arg(&path)
        .args(["--direction", "client"])
        .output()
        .unwrap();
    let _ = fs::remove_file(&path);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("SYN observations: 1"), "{stdout}");
    assert!(stdout.contains("source_ip: \"192.0.2.10\""), "{stdout}");
    assert!(!stdout.contains("source_ip: \"198.51.100.20\""), "{stdout}");
}

#[test]
fn anonymize_redacts_addresses_in_all_output_formats() {
    let path =
        std::env::temp_dir().join(format!("quietprint-anonymize-{}.pcap", std::process::id()));
    fs::write(&path, synthetic_ipv4_syn_pcap()).unwrap();

    for format in [vec!["--json"], vec!["--ndjson"], vec!["--csv"], vec![]] {
        let output = quietprint()
            .args(["analyze"])
            .arg(&path)
            .args(format)
            .arg("--anonymize")
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("[redacted]"), "{stdout}");
        assert!(stdout.contains("Linux"), "{stdout}");
        assert!(!stdout.contains("192.0.2.10"), "{stdout}");
        assert!(!stdout.contains("198.51.100.20"), "{stdout}");
    }

    let _ = fs::remove_file(&path);
}

#[test]
fn csv_quotes_fields_that_contain_commas() {
    let path = std::env::temp_dir().join(format!("quietprint-csv-{}.pcap", std::process::id()));
    fs::write(&path, synthetic_ipv4_syn_pcap()).unwrap();

    let output = quietprint()
        .args(["analyze"])
        .arg(&path)
        .arg("--csv")
        .output()
        .unwrap();
    let _ = fs::remove_file(&path);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(",\"mss,nop,ws,sok,ts,nop,eol,nop,eol\","),
        "{stdout}"
    );
    assert!(stdout.contains("\"[Candidate"), "{stdout}");
}

#[test]
fn aggregate_skips_duplicate_syn_packets_before_emitting_results() {
    let path =
        std::env::temp_dir().join(format!("quietprint-aggregate-{}.pcap", std::process::id()));
    let mut pcap = synthetic_ipv4_syn_pcap();
    let packet_record = pcap[24..].to_vec();
    pcap.extend_from_slice(&packet_record);
    fs::write(&path, pcap).unwrap();

    let output = quietprint()
        .args(["analyze"])
        .arg(&path)
        .args(["--json", "--aggregate"])
        .output()
        .unwrap();
    let _ = fs::remove_file(&path);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8(output.stdout).unwrap().lines().count(), 1);
}
