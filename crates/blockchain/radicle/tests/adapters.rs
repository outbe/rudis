use outbe_radicle::manager::{
    DisconnectDisposition, HeartwoodControl, HttpRepositoryStatus, NativeHeartwoodControl, RepoId,
    RepositoryStatus, SessionDirection,
};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    os::unix::net::UnixListener,
    path::PathBuf,
    sync::mpsc,
    thread,
    time::Duration,
};

fn socket_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("outbe-radicle-{name}-{}.sock", std::process::id()))
}

fn serve_uds(path: PathBuf, response: String) -> mpsc::Receiver<String> {
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        sender.send(line).unwrap();
        stream.write_all(response.as_bytes()).unwrap();
    });
    receiver
}

fn stall_uds(path: PathBuf, stall: Duration) {
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        thread::sleep(stall);
    });
}

#[tokio::test]
async fn native_uds() {
    let path = socket_path("node-id");
    let mut node_id = [0; 34];
    node_id[..2].copy_from_slice(&[0xed, 0x01]);
    node_id[2..].copy_from_slice(&[7; 32]);
    let node_id = multibase::encode(multibase::Base::Base58Btc, node_id);
    let request = serve_uds(path.clone(), format!("\"{node_id}\"\n"));
    let control = NativeHeartwoodControl::new(path.clone(), Duration::from_secs(1));
    assert_eq!(control.node_id().await.unwrap(), [7; 32]);
    assert!(request.recv().unwrap().contains(r#""command":"nodeId""#));

    let path = socket_path("seed");
    let request = serve_uds(
        path.clone(),
        r#"{"updated":true}
"#
        .into(),
    );
    let control = NativeHeartwoodControl::new(path, Duration::from_secs(1));
    control.seed(RepoId::repeat_byte(0x12)).await.unwrap();
    let request = request.recv().unwrap();
    assert!(request.contains(r#""command":"seed""#));
    assert!(request.contains(r#""scope":"all""#));

    let path = socket_path("sessions");
    let response = format!(
        "[{{\"nid\":\"{node_id}\",\"link\":\"outbound\",\"addr\":\"127.0.0.1:8776\",\"state\":{{\"connected\":{{\"since\":1}}}}}}]\n"
    );
    let _request = serve_uds(path.clone(), response);
    let control = NativeHeartwoodControl::new(path, Duration::from_secs(1));
    let sessions = control.sessions().await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].direction, SessionDirection::Outbound);
    assert!(sessions[0].connected);

    let path = socket_path("disconnect");
    let request = serve_uds(path.clone(), "\"addressChanged\"\n".into());
    let control = NativeHeartwoodControl::new(path, Duration::from_secs(1));
    let disposition = control
        .disconnect(
            [7; 32],
            &outbe_radicle::endpoint::EndpointAddress::ipv4([127, 0, 0, 1], 8776).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(disposition, DisconnectDisposition::AddressChanged);
    assert!(request
        .recv()
        .unwrap()
        .contains(r#""command":"disconnectBounded""#));
}

#[tokio::test]
async fn tcp_status() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 4096];
        let read = stream.read(&mut request).unwrap();
        assert!(std::str::from_utf8(&request[..read])
            .unwrap()
            .starts_with("GET /v1/repositories/1212121212121212121212121212121212121212 HTTP/1.1"));
        let body = r#"{"version":1,"repo_id":"1212121212121212121212121212121212121212","available":true}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let status = HttpRepositoryStatus::new(address, Duration::from_secs(1)).unwrap();
    assert!(status.available(RepoId::repeat_byte(0x12)).await.unwrap());
}

#[tokio::test]
async fn uds_deadline() {
    let path = socket_path("deadline");
    stall_uds(path.clone(), Duration::from_millis(100));
    let control = NativeHeartwoodControl::new(path, Duration::from_millis(10));
    let started = std::time::Instant::now();
    assert!(control.node_id().await.is_err());
    assert!(started.elapsed() < Duration::from_millis(80));
}
