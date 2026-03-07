#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OpKind {
    Accept = 1,
    Connect = 2,
    Read = 3,
    Write = 4,
    Close = 5,
    Tick = 6,
    MtlsConnect = 7,
    MtlsRead = 8,
    MtlsWrite = 9,
}

impl OpKind {
    #[inline]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Accept),
            2 => Some(Self::Connect),
            3 => Some(Self::Read),
            4 => Some(Self::Write),
            5 => Some(Self::Close),
            6 => Some(Self::Tick),
            7 => Some(Self::MtlsConnect),
            8 => Some(Self::MtlsRead),
            9 => Some(Self::MtlsWrite),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Side {
    Client = 0,
    Upstream = 1,
    None = 2,
}

impl Side {
    #[inline]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Client),
            1 => Some(Self::Upstream),
            2 => Some(Self::None),
            _ => None,
        }
    }
}

pub const IDX_BITS: u32 = 24;
pub const GEN_BITS: u32 = 24;

pub const IDX_MASK: u64 = (1u64 << IDX_BITS) - 1;
pub const GEN_MASK: u64 = (1u64 << GEN_BITS) - 1;

pub const GEN_SHIFT: u32 = IDX_BITS;
pub const OP_SHIFT: u32 = IDX_BITS + GEN_BITS;
pub const SIDE_SHIFT: u32 = 56;

pub const MAX_IDX: u32 = (1u32 << IDX_BITS) - 1;
pub const MAX_GEN: u32 = (1u32 << GEN_BITS) - 1;

#[inline]
pub fn pack(op: OpKind, side: Side, idx: u32, gen: u32) -> u64 {
    debug_assert!(idx <= MAX_IDX);
    debug_assert!(gen <= MAX_GEN);

    (idx as u64)
        | ((gen as u64) << GEN_SHIFT)
        | ((op as u64) << OP_SHIFT)
        | ((side as u64) << SIDE_SHIFT)
}

#[inline]
pub fn pack_accept() -> u64 {
    pack(OpKind::Accept, Side::None, 0, 0)
}

#[inline]
pub fn pack_tick() -> u64 {
    pack(OpKind::Tick, Side::None, 0, 0)
}

#[inline]
pub fn unpack(user_data: u64) -> (OpKind, Side, u32, u32) {
    let idx = (user_data & IDX_MASK) as u32;
    let gen = ((user_data >> GEN_SHIFT) & GEN_MASK) as u32;
    let op_u8 = ((user_data >> OP_SHIFT) & 0xFF) as u8;
    let side_u8 = ((user_data >> SIDE_SHIFT) & 0xFF) as u8;

    let op = OpKind::from_u8(op_u8).unwrap_or(OpKind::Accept);
    let side = Side::from_u8(side_u8).unwrap_or(Side::None);

    (op, side, idx, gen)
}
