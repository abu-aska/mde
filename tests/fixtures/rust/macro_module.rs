macro_rules! define_const {
    ($name:ident, $val:expr) => {
        pub const $name: u32 = $val;
    };
}

define_const!(MAX_BATCH, 64);

pub fn expand_items(seed: u32) -> Vec<u32> {
    vec![seed, seed + 1, MAX_BATCH]
}
