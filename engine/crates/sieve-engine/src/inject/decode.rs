//! Streaming, capped decoding of a response body (plan 5.6 item 2). Push-based,
//! because the proxy path holds chunks, not a reader: every decoder writes into
//! one [`CappedSink`], which counts output and trips the caps. Past a cap, on
//! corrupt or on truncated data the caller gets an error and resets the
//! connection: a half-rewritten body is never sent.
//!
//! zlib and raw deflate use flate2's `Decompress` directly: its write-side
//! decoders report success on a truncated stream, and only `Status::StreamEnd`
//! tells the two apart.
//!
//! A body ends where its stream ends, and bytes after that are ignored, because
//! the browser would render that page: resetting it would break a page that
//! works with Sieve off. For gzip the stream is the first member, so a later
//! member is ignored too, whole, cut or broken. Chromium 1228 was run on all
//! three and shows only the first member. Firefox was not run (plan, UNVERIFIED).
//!
//! zstd is the exception: Chromium did not load a zstd body with trailing bytes
//! either, so erroring there breaks nothing that works with Sieve off.
//!
//! Known residual risk: `zstd` is a C decoder fed hostile input in a SYSTEM
//! service. `ruzstd` is pure Rust but pull-only, which does not fit this path.

use std::io::{self, Write};

use flate2::write::GzDecoder;
use flate2::{Decompress, FlushDecompress, Status};
use zstd::stream::raw::{DParameter, Decoder as ZstdRaw};
use zstd::stream::write::Decoder as ZstdDecoder;

use super::{InjectError, InjectLimits};

/// brotli-decompressor's internal buffer; its own examples use this size.
const BROTLI_BUFFER_BYTES: usize = 4096;
/// One inflate step's output, then it goes through the sink.
const INFLATE_STEP_BYTES: usize = 32 * 1024;
/// RFC 1950: a zlib header has method 8 in the low nibble, a window of at most
/// 32 KiB in the high one, and is a multiple of 31 read big-endian.
const ZLIB_METHOD_DEFLATE: u8 = 8;
const ZLIB_MAX_WINDOW_INFO: u8 = 7;
const ZLIB_HEADER_MODULUS: u16 = 31;
const ZLIB_HEADER_BYTES: usize = 2;

/// The body encodings Sieve reads. [`ContentEncoding::from_header`] is the one
/// place a header value becomes one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentEncoding {
    Identity,
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

impl ContentEncoding {
    /// `None` for anything Sieve must not touch: unknown, or a list of several.
    pub fn from_header(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "deflate" => Some(Self::Deflate),
            "br" => Some(Self::Brotli),
            "zstd" => Some(Self::Zstd),
            _ => None,
        }
    }
}

/// Collects decoded bytes and enforces the size cap as they come, which is what
/// bounds a bomb's cost. The ratio is asked once, of the whole body
/// ([`BodyDecoder::finish`]): mid-stream it would judge how the transport cut the
/// body, so the same bytes would pass or reset by chunk size. It applies only
/// above the floor, so a small repetitive page is never reset.
#[derive(Default)]
struct CappedSink {
    out: Vec<u8>,
    decoded: u64,
    encoded: u64,
    limits: InjectLimits,
    tripped: Option<InjectError>,
}

impl CappedSink {
    fn new(limits: InjectLimits) -> Self {
        Self { out: Vec::new(), decoded: 0, encoded: 0, limits, tripped: None }
    }

    fn ratio_exceeded(&self) -> Option<InjectError> {
        let over_ratio = self.decoded > self.limits.ratio_floor_bytes && self.decoded / self.encoded.max(1) >= self.limits.max_ratio;
        over_ratio.then_some(InjectError::RatioExceeded { cap: self.limits.max_ratio })
    }
}

impl Write for CappedSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.decoded += buf.len() as u64;
        if self.decoded > self.limits.max_decoded_bytes {
            let error = InjectError::DecodedTooLarge { cap: self.limits.max_decoded_bytes };
            let message = error.to_string();
            self.tripped = Some(error);
            return Err(io::Error::other(message));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// zlib or raw deflate, chosen from the first two bytes as browsers do.
struct Inflate {
    decompress: Option<Decompress>,
    /// The first bytes, until there are enough to choose.
    start: Vec<u8>,
    ended: bool,
    scratch: Vec<u8>,
}

fn is_zlib_header(first: u8, second: u8) -> bool {
    first & 0x0f == ZLIB_METHOD_DEFLATE && first >> 4 <= ZLIB_MAX_WINDOW_INFO && u16::from_be_bytes([first, second]).is_multiple_of(ZLIB_HEADER_MODULUS)
}

impl Inflate {
    fn new() -> Self {
        Self { decompress: None, start: Vec::new(), ended: false, scratch: vec![0; INFLATE_STEP_BYTES] }
    }

    fn write(&mut self, chunk: &[u8], sink: &mut CappedSink) -> io::Result<()> {
        if self.decompress.is_some() {
            return self.inflate(chunk, sink);
        }
        self.start.extend_from_slice(chunk);
        if self.start.len() < ZLIB_HEADER_BYTES {
            return Ok(());
        }
        self.decompress = Some(Decompress::new(is_zlib_header(self.start[0], self.start[1])));
        let start = std::mem::take(&mut self.start);
        self.inflate(&start, sink)
    }

    fn inflate(&mut self, mut input: &[u8], sink: &mut CappedSink) -> io::Result<()> {
        let Some(decompress) = self.decompress.as_mut() else {
            return Ok(());
        };
        // Bytes after the end of the stream are ignored, as browsers do.
        while !self.ended {
            let (before_in, before_out) = (decompress.total_in(), decompress.total_out());
            let status = decompress.decompress(input, &mut self.scratch, FlushDecompress::None).map_err(io::Error::other)?;
            let consumed = usize::try_from(decompress.total_in() - before_in).map_err(io::Error::other)?;
            let produced = usize::try_from(decompress.total_out() - before_out).map_err(io::Error::other)?;
            input = &input[consumed..];
            sink.write_all(&self.scratch[..produced])?;
            self.ended = matches!(status, Status::StreamEnd);
            if consumed == 0 && produced == 0 {
                break;
            }
        }
        Ok(())
    }

    /// True when the stream reached its end, or never started.
    fn finish(&mut self, sink: &mut CappedSink) -> io::Result<bool> {
        if !self.start.is_empty() {
            // Too short to tell zlib from raw: inflate reports it as truncated.
            self.decompress = Some(Decompress::new(false));
            let start = std::mem::take(&mut self.start);
            self.inflate(&start, sink)?;
        }
        Ok(self.ended || self.decompress.is_none())
    }
}

/// Feeds a gzip or brotli decoder. Both answer Ok(0) on non-empty input, now and
/// on every later write, once their stream is complete; `write_all` would call
/// that an error. The rest is ignored (module doc), and their own finish step
/// still catches a stream that never reached its end.
fn write_to_stream_end(decoder: &mut impl Write, mut input: &[u8]) -> io::Result<()> {
    while !input.is_empty() {
        let consumed = decoder.write(input)?;
        if consumed == 0 {
            break;
        }
        input = &input[consumed..];
    }
    decoder.flush()
}

enum Decoder {
    Identity,
    Gzip(Box<GzDecoder<CappedSink>>),
    Deflate(Box<(Inflate, CappedSink)>),
    Brotli(Box<brotli_decompressor::DecompressorWriter<CappedSink>>),
    Zstd(Box<ZstdDecoder<'static, CappedSink>>),
}

/// One response body's decoder. Identity bodies pass straight through, uncapped:
/// no bomb is possible, and the rewriter's memory is bounded by its own limit.
pub struct BodyDecoder {
    decoder: Decoder,
    encoding: ContentEncoding,
    seen_input: bool,
}

impl BodyDecoder {
    pub fn new(encoding: ContentEncoding, limits: InjectLimits) -> Result<Self, InjectError> {
        let sink = CappedSink::new(limits);
        let decoder = match encoding {
            ContentEncoding::Identity => Decoder::Identity,
            ContentEncoding::Gzip => Decoder::Gzip(Box::new(GzDecoder::new(sink))),
            ContentEncoding::Deflate => Decoder::Deflate(Box::new((Inflate::new(), sink))),
            ContentEncoding::Brotli => Decoder::Brotli(Box::new(brotli_decompressor::DecompressorWriter::new(sink, BROTLI_BUFFER_BYTES))),
            ContentEncoding::Zstd => {
                let mut raw = ZstdRaw::new().map_err(|e| InjectError::corrupt(encoding, &e))?;
                raw.set_parameter(DParameter::WindowLogMax(limits.zstd_window_log_max)).map_err(|e| InjectError::corrupt(encoding, &e))?;
                Decoder::Zstd(Box::new(ZstdDecoder::with_decoder(sink, raw)))
            }
        };
        Ok(Self { decoder, encoding, seen_input: false })
    }

    fn sink_mut(&mut self) -> Option<&mut CappedSink> {
        match &mut self.decoder {
            Decoder::Identity => None,
            Decoder::Gzip(d) => Some(d.get_mut()),
            Decoder::Deflate(d) => Some(&mut d.1),
            Decoder::Brotli(d) => Some(d.get_mut()),
            Decoder::Zstd(d) => Some(d.get_mut()),
        }
    }

    /// What tripped a cap, or else the decoder's own failure.
    fn failure(&mut self, error: &io::Error) -> InjectError {
        let tripped = self.sink_mut().and_then(|sink| sink.tripped.take());
        tripped.unwrap_or_else(|| InjectError::corrupt(self.encoding, error))
    }

    fn take_output(&mut self) -> Vec<u8> {
        self.sink_mut().map(|sink| std::mem::take(&mut sink.out)).unwrap_or_default()
    }

    /// Feeds one body chunk and returns what could be decoded so far.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, InjectError> {
        if chunk.is_empty() {
            return Ok(Vec::new());
        }
        self.seen_input = true;
        if let Some(sink) = self.sink_mut() {
            sink.encoded += chunk.len() as u64;
        }
        let written = match &mut self.decoder {
            Decoder::Identity => return Ok(chunk.to_vec()),
            Decoder::Gzip(d) => write_to_stream_end(&mut **d, chunk),
            Decoder::Deflate(d) => {
                let (inflate, sink) = &mut **d;
                inflate.write(chunk, sink)
            }
            Decoder::Brotli(d) => write_to_stream_end(&mut **d, chunk),
            Decoder::Zstd(d) => d.write_all(chunk).and_then(|()| d.flush()),
        };
        written.map_err(|e| self.failure(&e))?;
        Ok(self.take_output())
    }

    /// Ends the body and returns the last output. An empty body is complete
    /// under any encoding; any other that stopped early is an error.
    pub fn finish(&mut self) -> Result<Vec<u8>, InjectError> {
        if !self.seen_input {
            return Ok(Vec::new());
        }
        let finished = match &mut self.decoder {
            Decoder::Identity => return Ok(Vec::new()),
            Decoder::Gzip(d) => d.try_finish(),
            Decoder::Deflate(d) => {
                let (inflate, sink) = &mut **d;
                match inflate.finish(sink) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                    Err(e) => Err(e),
                }
            }
            Decoder::Brotli(d) => d.close().map_err(|e| io::Error::other(format!("{e:?}"))),
            Decoder::Zstd(d) => d.do_finish(),
        };
        finished.map_err(|e| self.failure(&e))?;
        if let Some(error) = self.sink_mut().and_then(|sink| sink.ratio_exceeded()) {
            return Err(error);
        }
        Ok(self.take_output())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    use proptest::prelude::*;

    const ENCODINGS: [ContentEncoding; 4] = [ContentEncoding::Gzip, ContentEncoding::Deflate, ContentEncoding::Brotli, ContentEncoding::Zstd];
    /// Not zstd: Chromium does not load a zstd body with trailing bytes either,
    /// so that error is not a Sieve-only breakage (module doc).
    const ENDS_AT_STREAM_END: [ContentEncoding; 3] = [ContentEncoding::Gzip, ContentEncoding::Deflate, ContentEncoding::Brotli];
    const MIB: u64 = 1024 * 1024;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn brotli_of(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            w.write_all(data).unwrap();
        }
        out
    }

    fn zstd_of(data: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(data, 3).unwrap()
    }

    fn encode(encoding: ContentEncoding, data: &[u8]) -> Vec<u8> {
        match encoding {
            ContentEncoding::Identity => data.to_vec(),
            ContentEncoding::Gzip => gzip(data),
            ContentEncoding::Deflate => zlib(data),
            ContentEncoding::Brotli => brotli_of(data),
            ContentEncoding::Zstd => zstd_of(data),
        }
    }

    fn decode_chunks<'a>(encoding: ContentEncoding, chunks: impl IntoIterator<Item = &'a [u8]>, limits: InjectLimits) -> Result<Vec<u8>, InjectError> {
        let mut decoder = BodyDecoder::new(encoding, limits)?;
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(decoder.push(chunk)?);
        }
        out.extend(decoder.finish()?);
        Ok(out)
    }

    fn decode(encoding: ContentEncoding, body: &[u8]) -> Result<Vec<u8>, InjectError> {
        decode_chunks(encoding, [body], InjectLimits::default())
    }

    /// Noise that does not compress, so a ratio stays low.
    fn noise(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_u32;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    }

    #[test]
    fn a_header_value_names_one_encoding_or_nothing() {
        assert_eq!(ContentEncoding::from_header(" GZIP "), Some(ContentEncoding::Gzip));
        assert_eq!(ContentEncoding::from_header("x-gzip"), Some(ContentEncoding::Gzip));
        assert_eq!(ContentEncoding::from_header("br"), Some(ContentEncoding::Brotli));
        for other in ["gzip, br", "compress", "identity", ""] {
            assert_eq!(ContentEncoding::from_header(other), None, "{other}");
        }
    }

    #[test]
    fn a_bomb_of_each_encoding_errors_at_the_size_cap_with_bounded_output() {
        let limits = InjectLimits { max_decoded_bytes: 4 * MIB, max_ratio: u64::MAX, ..InjectLimits::default() };
        let plain = vec![0u8; 32 * MIB as usize];
        for encoding in ENCODINGS {
            let body = encode(encoding, &plain);
            let mut decoder = BodyDecoder::new(encoding, limits).unwrap();
            let error = body.chunks(16 * 1024).try_for_each(|chunk| {
                let out = decoder.push(chunk)?;
                assert!(out.len() as u64 <= limits.max_decoded_bytes, "{encoding:?}");
                Ok::<(), InjectError>(())
            });
            assert!(matches!(error, Err(InjectError::DecodedTooLarge { .. })), "{encoding:?}: {error:?}");
        }
    }

    #[test]
    fn a_bomb_of_each_encoding_errors_at_the_ratio_cap() {
        let limits = InjectLimits { max_ratio: 20, ratio_floor_bytes: MIB, ..InjectLimits::default() };
        let plain = vec![0u8; 8 * MIB as usize];
        for encoding in ENCODINGS {
            let error = decode_chunks(encoding, [&encode(encoding, &plain)[..]], limits);
            assert!(matches!(error, Err(InjectError::RatioExceeded { .. })), "{encoding:?}: {error:?}");
        }
    }

    /// A long compressible prefix, then noise: a low ratio overall that a mid-stream
    /// test would call a bomb or not by where the transport cut. The verdict is
    /// the same for every cut, and so is a real bomb's.
    #[test]
    fn the_verdict_does_not_depend_on_the_chunk_size() {
        const CUTS: [usize; 6] = [1024 * 1024, 64 * 1024, 16 * 1024, 8 * 1024, 4 * 1024, 1460];
        let prefix_then_noise = [vec![b' '; 2 * MIB as usize], noise(2 * MIB as usize)].concat();
        let bomb = vec![0u8; 8 * MIB as usize];
        for encoding in ENCODINGS {
            let page = encode(encoding, &prefix_then_noise);
            assert_eq!(decode(encoding, &page).unwrap().len(), prefix_then_noise.len(), "{encoding:?} whole");
            let bombed = encode(encoding, &bomb);
            for cut in CUTS {
                assert_eq!(decode_chunks(encoding, page.chunks(cut), InjectLimits::default()).unwrap().len(), prefix_then_noise.len(), "{encoding:?} {cut}");
                let error = decode_chunks(encoding, bombed.chunks(cut), InjectLimits::default());
                assert!(matches!(error, Err(InjectError::RatioExceeded { .. })), "{encoding:?} {cut}: {error:?}");
            }
        }
    }

    #[test]
    fn a_2_mib_page_at_a_low_ratio_passes() {
        let plain = noise(2 * MIB as usize);
        for encoding in ENCODINGS {
            assert_eq!(decode(encoding, &encode(encoding, &plain)).unwrap(), plain, "{encoding:?}");
        }
    }

    #[test]
    fn a_small_highly_compressible_page_under_the_floor_passes() {
        let plain = vec![b'x'; 900 * 1024];
        for encoding in ENCODINGS {
            assert_eq!(decode(encoding, &encode(encoding, &plain)).unwrap().len(), plain.len(), "{encoding:?}");
        }
    }

    #[test]
    fn a_truncated_stream_errors() {
        let plain = noise(64 * 1024);
        for encoding in ENCODINGS {
            let body = encode(encoding, &plain);
            let error = decode(encoding, &body[..body.len() / 2]);
            assert!(matches!(error, Err(InjectError::Corrupt { .. })), "{encoding:?}: {error:?}");
        }
        let body = raw_deflate(&plain);
        assert!(decode(ContentEncoding::Deflate, &body[..body.len() / 2]).is_err());
    }

    #[test]
    fn a_stream_cut_after_its_header_or_before_its_trailer_errors() {
        let gz = gzip(b"hello");
        assert!(decode(ContentEncoding::Gzip, &gz[..gz.len() - 4]).is_err());
        assert!(decode(ContentEncoding::Gzip, &gz[..5]).is_err());
        assert!(decode(ContentEncoding::Deflate, &zlib(b"hello")[..1]).is_err());
    }

    #[test]
    fn a_corrupt_stream_errors() {
        let garbage = noise(4096);
        for encoding in ENCODINGS {
            assert!(decode(encoding, &garbage).is_err(), "{encoding:?}");
        }
        let mut gz = gzip(b"hello hello hello");
        let last = gz.len() - 1;
        gz[last] ^= 0xff; // the length in the trailer
        assert!(decode(ContentEncoding::Gzip, &gz).is_err());
    }

    #[test]
    fn an_empty_body_is_complete_under_any_encoding() {
        for encoding in ENCODINGS {
            assert_eq!(decode(encoding, b"").unwrap(), b"", "{encoding:?}");
            assert_eq!(decode(encoding, &encode(encoding, b"")).unwrap(), b"", "{encoding:?}");
        }
    }

    #[test]
    fn deflate_takes_zlib_or_raw_from_the_first_two_bytes() {
        let plain = noise(5000);
        assert_eq!(decode(ContentEncoding::Deflate, &zlib(&plain)).unwrap(), plain);
        assert_eq!(decode(ContentEncoding::Deflate, &raw_deflate(&plain)).unwrap(), plain);
    }

    fn with_tail(encoding: ContentEncoding, tail: &[u8]) -> Vec<u8> {
        [encode(encoding, b"hello").as_slice(), tail].concat()
    }

    fn assert_decodes_to_hello(encoding: ContentEncoding, tail: &[u8]) {
        let body = with_tail(encoding, tail);
        assert_eq!(decode(encoding, &body).unwrap(), b"hello", "{encoding:?} {tail:?}");
        assert_eq!(decode_chunks(encoding, body.chunks(1), InjectLimits::default()).unwrap(), b"hello", "{encoding:?} {tail:?} in one byte chunks");
    }

    #[test]
    fn bytes_after_the_end_of_a_stream_are_ignored() {
        let tails: [&[u8]; 3] = [b"\n", b"junk", &[0; 16]];
        for encoding in ENDS_AT_STREAM_END {
            for tail in tails {
                assert_decodes_to_hello(encoding, tail);
            }
        }
    }

    #[test]
    fn junk_in_the_chunk_of_the_last_data_keeps_that_output() {
        for encoding in ENDS_AT_STREAM_END {
            let mut decoder = BodyDecoder::new(encoding, InjectLimits::default()).unwrap();
            assert_eq!(decoder.push(&with_tail(encoding, b"junk")).unwrap(), b"hello", "{encoding:?}");
            assert_eq!(decoder.push(b"more junk").unwrap(), b"", "{encoding:?}");
            assert_eq!(decoder.finish().unwrap(), b"", "{encoding:?}");
        }
    }

    /// Whole, cut or broken, a later member is only more bytes after the end
    /// (module doc).
    #[test]
    fn a_later_gzip_member_is_ignored() {
        let second = gzip(b"two");
        let tails: [&[u8]; 8] = [&second, &second[..2], &second[..5], &second[..second.len() - 1], &[0x1f], &[0x1f, 0x8b, 0xff, 0xff], &[0x1f, 0x00, 0x1f, 0x8b], b"x\x1f\x8b"];
        for tail in tails {
            assert_decodes_to_hello(ContentEncoding::Gzip, tail);
        }
    }

    #[test]
    fn a_later_gzip_member_cannot_trip_the_caps() {
        let limits = InjectLimits { max_decoded_bytes: 4096, max_ratio: u64::MAX, ..InjectLimits::default() };
        let plain = noise(3000);
        let member = gzip(&plain);
        let body = [member.as_slice(), member.as_slice()].concat();
        assert_eq!(decode_chunks(ContentEncoding::Gzip, [&body[..]], limits).unwrap(), plain);
    }

    #[test]
    fn a_bad_gzip_trailer_errors_even_with_junk_after_it() {
        let mut body = gzip(b"hello hello");
        let last = body.len() - 1;
        body[last] ^= 0xff;
        body.extend_from_slice(b"junk");
        assert!(matches!(decode(ContentEncoding::Gzip, &body), Err(InjectError::Corrupt { .. })));
    }

    #[test]
    fn a_brotli_stream_cut_one_byte_before_its_end_errors() {
        let br = brotli_of(&noise(4096));
        assert!(matches!(decode(ContentEncoding::Brotli, &br[..br.len() - 1]), Err(InjectError::Corrupt { .. })));
    }

    #[test]
    fn a_zstd_frame_over_the_window_limit_errors() {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
        encoder.window_log(27).unwrap();
        encoder.long_distance_matching(true).unwrap();
        encoder.write_all(&noise(1024)).unwrap();
        let body = encoder.finish().unwrap();
        let error = decode(ContentEncoding::Zstd, &body);
        assert!(matches!(error, Err(InjectError::Corrupt { .. })), "{error:?}");
        let wide = InjectLimits { zstd_window_log_max: 27, ..InjectLimits::default() };
        assert_eq!(decode_chunks(ContentEncoding::Zstd, [&body[..]], wide).unwrap(), noise(1024));
    }

    #[test]
    fn identity_passes_through_with_no_cap() {
        let limits = InjectLimits { max_decoded_bytes: 4, ..InjectLimits::default() };
        assert_eq!(decode_chunks(ContentEncoding::Identity, [&b"longer than the cap"[..]], limits).unwrap(), b"longer than the cap");
    }

    #[test]
    fn every_encoding_round_trips_in_one_byte_chunks() {
        let plain = noise(2000);
        for encoding in ENCODINGS {
            let body = encode(encoding, &plain);
            assert_eq!(decode_chunks(encoding, body.chunks(1), InjectLimits::default()).unwrap(), plain, "{encoding:?}");
        }
    }

    #[test]
    fn output_streams_before_finish() {
        let plain = noise(256 * 1024);
        for encoding in ENCODINGS {
            let body = encode(encoding, &plain);
            let mut decoder = BodyDecoder::new(encoding, InjectLimits::default()).unwrap();
            let out = decoder.push(&body[..body.len() * 3 / 4]).unwrap();
            assert!(!out.is_empty(), "{encoding:?} buffered everything");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn any_split_decodes_the_same(cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..12)) {
            let plain = noise(3000);
            for encoding in ENCODINGS {
                let body = encode(encoding, &plain);
                let mut points: Vec<usize> = cuts.iter().map(|c| c.index(body.len())).collect();
                points.sort_unstable();
                points.dedup();
                let mut chunks = Vec::new();
                let mut last = 0;
                for p in points {
                    chunks.push(&body[last..p]);
                    last = p;
                }
                chunks.push(&body[last..]);
                prop_assert_eq!(decode_chunks(encoding, chunks, InjectLimits::default()).unwrap(), plain.clone());
            }
        }
    }
}
