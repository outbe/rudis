use outbe_radicle::endpoint::{EndpointAddress, EndpointFrame, EndpointRequest};
use proptest::prelude::*;

proptest! {
    #[test]
    fn address_roundtrip_v4(octets in any::<[u8; 4]>(), port in 1u16..) {
        let address = EndpointAddress::ipv4(octets, port).unwrap();
        prop_assert_eq!(EndpointAddress::decode(&address.encode()).unwrap(), address);
    }

    #[test]
    fn address_roundtrip_v6(octets in any::<[u8; 16]>(), port in 1u16..) {
        let address = EndpointAddress::ipv6(octets, port).unwrap();
        prop_assert_eq!(EndpointAddress::decode(&address.encode()).unwrap(), address);
    }

    #[test]
    fn request_roundtrip(request_id in any::<[u8; 32]>().prop_filter("nonzero", |id| *id != [0; 32])) {
        let frame = EndpointFrame::Request(EndpointRequest::new(request_id).unwrap());
        prop_assert_eq!(EndpointFrame::decode(&frame.encode()).unwrap(), frame);
    }

    #[test]
    fn decoder_is_total(bytes in prop::collection::vec(any::<u8>(), 0..5000)) {
        let _ = EndpointFrame::decode(&bytes);
    }
}
