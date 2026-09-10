use outbe_radicle::endpoint::{AddressError, EndpointAddress};

#[test]
fn address_vectors() {
    let ipv4 = EndpointAddress::ipv4([127, 0, 0, 1], 8776).unwrap();
    assert_eq!(ipv4.encode(), hex::decode("007f0000012248").unwrap());
    assert_eq!(EndpointAddress::decode(&ipv4.encode()).unwrap(), ipv4);

    let ipv6 =
        EndpointAddress::ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 8776).unwrap();
    assert_eq!(
        ipv6.encode(),
        hex::decode("01000000000000000000000000000000012248").unwrap()
    );
    assert_eq!(EndpointAddress::decode(&ipv6.encode()).unwrap(), ipv6);

    let dns = EndpointAddress::dns("BÜCHER.Example", 8776).unwrap();
    assert_eq!(dns.host(), Some("xn--bcher-kva.example"));
    assert_eq!(EndpointAddress::decode(&dns.encode()).unwrap(), dns);
}

#[test]
fn address_rejections() {
    assert_eq!(
        EndpointAddress::ipv4([1, 2, 3, 4], 0),
        Err(AddressError::ZeroPort)
    );
    assert_eq!(
        EndpointAddress::dns("example.com.", 1),
        Err(AddressError::TrailingDot)
    );
    assert_eq!(
        EndpointAddress::dns("a..b", 1),
        Err(AddressError::EmptyLabel)
    );
    assert_eq!(
        EndpointAddress::dns("127.0.0.1", 1),
        Err(AddressError::IpLiteral)
    );
    assert_eq!(EndpointAddress::dns("::1", 1), Err(AddressError::IpLiteral));

    let long_label = format!("{}.example", "a".repeat(64));
    assert_eq!(
        EndpointAddress::dns(&long_label, 1),
        Err(AddressError::LabelTooLong)
    );
    let long_name = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );
    assert_eq!(
        EndpointAddress::dns(&long_name, 1),
        Err(AddressError::NameTooLong)
    );

    let uppercase_wire = [2, 3, b'F', b'o', b'o', 0, 1];
    assert_eq!(
        EndpointAddress::decode(&uppercase_wire),
        Err(AddressError::NonCanonicalDns)
    );
    let trailing = [0, 127, 0, 0, 1, 0, 1, 9];
    assert_eq!(
        EndpointAddress::decode(&trailing),
        Err(AddressError::TrailingBytes)
    );
}
