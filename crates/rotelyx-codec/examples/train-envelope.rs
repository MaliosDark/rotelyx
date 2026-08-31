//! Does a trained codebook for the band envelope save what Codec 2 suggests?
//!
//! # The claim being tested
//!
//! `TODO.md` has carried this for a long time: Codec 2 700C spends **18 bits**
//! on a K=20 mel-spaced envelope where Telyx spends about **100** on 24 bands.
//! It has stayed open because it needs a speech corpus and it ships a codebook.
//!
//! The corpus question is settled in `docs/PROVENANCE.md`. This answers the
//! other half, which nobody had measured: **whether a trained quantiser
//! actually buys that**, on this envelope, at this band layout, before anybody
//! commits to shipping a table.
//!
//!     scripts/make-speech-corpus <path to LibriSpeech>
//!     cargo run --release -p rotelyx-codec --example train-envelope
//!
//! # What it measures, and what it deliberately does not
//!
//! Rate against distortion, in the units the codec already thinks in: bits per
//! frame, and root mean square error in **levels**, where one level is 0.5 dB.
//! It does not measure how anything sounds. A codebook that halves the bits and
//! costs two levels of envelope error might be inaudible or might be obvious,
//! and this cannot say which. See the note at the top of `lib.rs`.
//!
//! # Why the split matters
//!
//! Trained on some speakers and measured on others, never the same ones. A
//! codebook measured on its own training set reports how well it memorised, and
//! this quantiser would be shipped to people it has never heard.

use std::collections::BTreeMap;
use std::path::Path;

use rotelyx_codec::bands::{self, BANDS};
use rotelyx_codec::mdct::{self, FRAME, WINDOW};

/// Envelopes, as the encoder sees them: one level per band, 0.5 dB apart.
type Envelope = Vec<u8>;

fn main() {
    let dir = Path::new("crates/rotelyx-codec/tests/speech-corpus");
    if !dir.exists() {
        println!("\n  no corpus at {}", dir.display());
        println!("  scripts/make-speech-corpus builds it from LibriSpeech.");
        return;
    }

    let mut by_speaker: BTreeMap<String, Vec<Envelope>> = BTreeMap::new();
    let window = mdct::window();

    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .expect("readable")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "wav"))
        .collect();
    paths.sort();

    for path in &paths {
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        let samples = read_wav(path);
        let mut frames = Vec::new();
        let mut at = 0;
        while at + WINDOW <= samples.len() {
            let coefficients = mdct::forward(&samples[at..at + WINDOW], &window);
            let energies = bands::energies(&coefficients);
            frames.push(energies.iter().map(|&e| level(e)).collect::<Envelope>());
            at += FRAME;
        }
        println!("  {name}: {} frames", frames.len());
        by_speaker.insert(name, frames);
    }

    if by_speaker.len() < 4 {
        println!("\n  fewer than four speakers, so a split would not mean much");
        return;
    }

    // Half the speakers train, half are measured, **balanced by sex**, and the
    // first attempt at this was not.
    //
    // Sorting the names put `f84, f1462, f1673, f1988` on one side and the four
    // men on the other, so the codebook learned female envelopes and was
    // measured on male ones. Those differ in spectral tilt before anything else
    // does, and the answer that came back, 11 levels of error, was mostly the
    // sound of that split.
    //
    // Names carry the sex here because `scripts/make-speech-corpus` writes it
    // into them, which is the only reason this can be done at all.
    let names: Vec<String> = by_speaker.keys().cloned().collect();
    let women: Vec<&String> = names.iter().filter(|n| n.starts_with('f')).collect();
    let men: Vec<&String> = names.iter().filter(|n| n.starts_with('m')).collect();

    let mut train_names: Vec<String> = Vec::new();
    let mut test_names: Vec<String> = Vec::new();
    for (i, n) in women.iter().chain(men.iter()).enumerate() {
        if i % 2 == 0 {
            train_names.push((*n).clone());
        } else {
            test_names.push((*n).clone());
        }
    }
    let (train_names, test_names) = (&train_names[..], &test_names[..]);

    let train: Vec<Envelope> = train_names
        .iter()
        .flat_map(|n| by_speaker[n].clone())
        .collect();
    let test: Vec<Envelope> = test_names
        .iter()
        .flat_map(|n| by_speaker[n].clone())
        .collect();

    println!();
    println!("  training on   {train_names:?}  {} frames", train.len());
    println!("  measuring on  {test_names:?}  {} frames", test.len());
    println!();

    // What the codec spends today, and what it costs, so the comparison is
    // against this codec rather than against a paper.
    let quantum = 3u8; // 1.5 dB, what a 60 byte frame uses
    let coded_levels = 96usize.div_ceil(quantum as usize);
    let bits_now = BANDS * coded_levels.next_power_of_two().trailing_zeros() as usize;
    let error_now = rms(&test, |e| e.iter().map(|&l| coarsen(l, quantum)).collect());

    println!("  {:<28} {:>6}  {:>8}", "", "bits", "rms err");
    println!(
        "  {:<28} {bits_now:>6}  {error_now:>8.2}",
        "today, fixed width"
    );

    // And the trained codebooks, at sizes worth knowing about.
    for bits in [6usize, 8, 10, 12] {
        let size = 1usize << bits;
        let book = train_codebook(&train, size);
        let error = rms(&test, |e| nearest(&book, e).clone());
        println!(
            "  {:<28} {bits:>6}  {error:>8.2}",
            format!("trained, {size} entries")
        );
    }

    // The same, with the overall level taken out first.
    //
    // # Why this is a different experiment and not a tweak
    //
    // A band envelope is loudness plus shape. Loudness moves over the whole
    // range as somebody leans towards a microphone, and shape is what a vowel
    // is. A codebook given both spends its entries learning how loud people
    // are, which is one number, and has nothing left for the thing that
    // carries the speech.
    //
    // Codec 2 codes the mean separately for this reason, and the first version
    // of this measurement did not, which is most of why its answer looked so
    // bad.
    println!();
    let shapes_train: Vec<Envelope> = train.iter().map(|e| without_mean(e).1).collect();
    for bits in [6usize, 8, 10, 12] {
        let size = 1usize << bits;
        let book = train_codebook(&shapes_train, size);
        let error = rms(&test, |e| {
            let (mean, shape) = without_mean(e);
            let picked = nearest(&book, &shape);
            picked
                .iter()
                .map(|&s| (s as i32 + mean as i32 - 96).clamp(0, 191) as u8)
                .collect()
        });
        // Plus the bits the mean itself costs, at the same 1.5 dB step the
        // codec already uses for a level.
        let with_mean = bits + 6;
        println!(
            "  {:<28} {with_mean:>6}  {error:>8.2}",
            format!("trained on shape, {size}")
        );
    }

    println!();
    println!("  One level is 0.5 dB. Whether the extra error is audible is not");
    println!("  measured here and cannot be measured without a person.");
}

/// Split an envelope into its overall level and its shape.
///
/// The shape is centred on 96, which is the middle of the level scale, so it
/// stays in a `u8` and the codebook sees only how a spectrum is bent rather than
/// how loud it was.
fn without_mean(envelope: &[u8]) -> (u8, Envelope) {
    let mean = (envelope.iter().map(|&l| l as u32).sum::<u32>() / envelope.len() as u32) as u8;
    let shape = envelope
        .iter()
        .map(|&l| (l as i32 - mean as i32 + 96).clamp(0, 191) as u8)
        .collect();
    (mean, shape)
}

/// LBG, which is k-means with a splitting start.
fn train_codebook(data: &[Envelope], size: usize) -> Vec<Envelope> {
    assert!(!data.is_empty());
    let mut book: Vec<Envelope> = vec![mean_of(data)];

    while book.len() < size {
        // Split every entry, nudged apart, then settle.
        let mut split = Vec::with_capacity(book.len() * 2);
        for entry in &book {
            split.push(entry.clone());
            split.push(entry.iter().map(|&l| l.saturating_add(1)).collect());
        }
        book = split;

        for _ in 0..12 {
            let mut sums: Vec<Vec<u64>> = vec![vec![0; BANDS]; book.len()];
            let mut counts = vec![0u64; book.len()];
            for point in data {
                let at = nearest_index(&book, point);
                counts[at] += 1;
                for (s, &l) in sums[at].iter_mut().zip(point) {
                    *s += l as u64;
                }
            }
            for (i, entry) in book.iter_mut().enumerate() {
                if counts[i] == 0 {
                    continue;
                }
                for (slot, sum) in entry.iter_mut().zip(&sums[i]) {
                    *slot = (sum / counts[i]) as u8;
                }
            }
        }
    }
    book.truncate(size);
    book
}

fn nearest_index(book: &[Envelope], point: &[u8]) -> usize {
    let mut best = (0usize, u64::MAX);
    for (i, entry) in book.iter().enumerate() {
        let d: u64 = entry
            .iter()
            .zip(point)
            .map(|(&a, &b)| {
                let d = a as i64 - b as i64;
                (d * d) as u64
            })
            .sum();
        if d < best.1 {
            best = (i, d);
        }
    }
    best.0
}

fn nearest<'a>(book: &'a [Envelope], point: &[u8]) -> &'a Envelope {
    &book[nearest_index(book, point)]
}

fn mean_of(data: &[Envelope]) -> Envelope {
    let mut sums = [0u64; BANDS];
    for point in data {
        for (s, &l) in sums.iter_mut().zip(point) {
            *s += l as u64;
        }
    }
    sums.iter().map(|s| (s / data.len() as u64) as u8).collect()
}

/// Root mean square error, in levels, of a quantiser applied to held out data.
fn rms(data: &[Envelope], quantise: impl Fn(&Envelope) -> Envelope) -> f64 {
    let mut total = 0.0f64;
    let mut n = 0usize;
    for point in data {
        let got = quantise(point);
        for (&a, &b) in point.iter().zip(&got) {
            let d = a as f64 - b as f64;
            total += d * d;
            n += 1;
        }
    }
    (total / n.max(1) as f64).sqrt()
}

fn coarsen(level: u8, quantum: u8) -> u8 {
    let q = quantum as u16;
    (((level as u16 + q / 2) / q) * q).min(191) as u8
}

fn level(energy: f32) -> u8 {
    let db = 20.0 * energy.max(1e-6).log10();
    (((db + 96.0) / 0.5).round()).clamp(0.0, 191.0) as u8
}

fn read_wav(path: &Path) -> Vec<f32> {
    let bytes = std::fs::read(path).expect("readable wav");
    let mut at = 12;
    while at + 8 <= bytes.len() {
        let id = &bytes[at..at + 4];
        let size = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if id == b"data" {
            let body = &bytes[at + 8..(at + 8 + size).min(bytes.len())];
            return body
                .chunks_exact(2)
                .map(|p| i16::from_le_bytes([p[0], p[1]]) as f32 / 32768.0)
                .collect();
        }
        at += 8 + size + (size & 1);
    }
    Vec::new()
}
