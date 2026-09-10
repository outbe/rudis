use alloy_primitives::{keccak256, B256};

pub struct IndependentEncoder {
    bytes: Vec<u8>,
}

impl IndependentEncoder {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn u16(&mut self, value: u16) {
        self.bytes.extend(value.to_be_bytes());
    }

    pub fn u32(&mut self, value: u32) {
        self.bytes.extend(value.to_be_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.bytes.extend(value.to_be_bytes());
    }

    pub fn u128(&mut self, value: u128) {
        self.bytes.extend(value.to_be_bytes());
    }

    pub fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend(value);
    }

    pub fn boolean(&mut self, value: bool) {
        self.u8(if value { 1 } else { 0 });
    }

    pub fn bounded(&mut self, value: &[u8]) {
        self.u32(u32::try_from(value.len()).expect("test value fits u32"));
        self.fixed(value);
    }

    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

pub fn envelope(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut encoded = IndependentEncoder::new();
    encoded.fixed(b"OCB1");
    encoded.u16(kind);
    encoded.u16(1);
    encoded.u32(u32::try_from(body.len()).expect("test body fits u32"));
    encoded.fixed(body);
    encoded.finish()
}

pub fn framed_hash(domain: &str, payload: &[u8]) -> B256 {
    let mut preimage = IndependentEncoder::new();
    preimage.u16(u16::try_from(domain.len()).expect("test domain fits u16"));
    preimage.fixed(domain.as_bytes());
    preimage.u32(u32::try_from(payload.len()).expect("test payload fits u32"));
    preimage.fixed(payload);
    keccak256(preimage.finish())
}

pub fn ordered_root(kind: u16, items: &[&[u8]]) -> B256 {
    if items.is_empty() {
        let mut payload = IndependentEncoder::new();
        payload.u16(kind);
        return framed_hash("OUTBE_OCOMP_LIST_EMPTY_V1", &payload.finish());
    }

    let padded_count = items.len().next_power_of_two();
    let mut nodes = Vec::with_capacity(padded_count);
    for (index, item) in items.iter().enumerate() {
        let mut payload = IndependentEncoder::new();
        payload.u16(kind);
        payload.u32(u32::try_from(index).expect("test index fits u32"));
        payload.bounded(item);
        nodes.push(framed_hash("OUTBE_OCOMP_LIST_LEAF_V1", &payload.finish()));
    }
    for index in items.len()..padded_count {
        let mut payload = IndependentEncoder::new();
        payload.u16(kind);
        payload.u32(u32::try_from(index).expect("test index fits u32"));
        nodes.push(framed_hash("OUTBE_OCOMP_LIST_PAD_V1", &payload.finish()));
    }

    let height = u16::try_from(padded_count.trailing_zeros()).expect("test height fits u16");
    let mut width = padded_count;
    let mut level = 1_u16;
    while width > 1 {
        let parents = width / 2;
        for index in 0..parents {
            let mut payload = IndependentEncoder::new();
            payload.u16(kind);
            payload.u16(level);
            payload.u32(u32::try_from(index).expect("test index fits u32"));
            payload.fixed(nodes[index * 2].as_slice());
            payload.fixed(nodes[index * 2 + 1].as_slice());
            nodes[index] = framed_hash("OUTBE_OCOMP_LIST_NODE_V1", &payload.finish());
        }
        width = parents;
        level += 1;
    }

    let mut payload = IndependentEncoder::new();
    payload.u16(kind);
    payload.u32(u32::try_from(items.len()).expect("test count fits u32"));
    payload.u16(height);
    payload.fixed(nodes[0].as_slice());
    framed_hash("OUTBE_OCOMP_LIST_ROOT_V1", &payload.finish())
}

pub struct IndependentReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> IndependentReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn u8(&mut self) -> Option<u8> {
        let value = *self.bytes.get(self.offset)?;
        self.offset += 1;
        Some(value)
    }

    pub fn u16(&mut self) -> Option<u16> {
        let bytes = self.bytes.get(self.offset..self.offset + 2)?;
        self.offset += 2;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        let bytes = self.bytes.get(self.offset..self.offset + 4)?;
        self.offset += 4;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn boolean(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    pub fn bounded(&mut self) -> Option<&'a [u8]> {
        let length = usize::try_from(self.u32()?).ok()?;
        let value = self.bytes.get(self.offset..self.offset + length)?;
        self.offset += length;
        Some(value)
    }

    pub fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
