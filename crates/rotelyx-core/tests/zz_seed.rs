#[test]
fn dump_frames() {
    use rotelyx_core::wire::{Frame, FrameKind};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().parent().unwrap()
        .join("fuzz/corpus/frame_reader");
    std::fs::create_dir_all(&dir).unwrap();
    let kinds = [FrameKind::Message, FrameKind::Admission];
    for (n, len) in [0usize, 1, 17, 200, 4096, 65_535, 1_048_575].iter().enumerate() {
        for (k, kind) in kinds.iter().enumerate() {
            let mut out = Vec::new();
            let f = Frame::new(*kind, vec![0x41u8; *len]);
            if futures_lite::future::block_on(f.write(&mut out)).is_ok() {
                std::fs::write(dir.join(format!("seed{n}_{k}")), out).unwrap();
            }
        }
    }
}
