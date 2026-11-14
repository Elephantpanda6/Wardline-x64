#![forbid(unsafe_code)]

use zeroize::Zeroize;

use crate::dpapi::SecretBytes;

pub struct StreamingScrubber {
    secrets: Vec<(String, SecretBytes)>,
    max_len: usize,
    pending: Vec<u8>,
}

impl StreamingScrubber {
    pub fn new(secrets: Vec<(String, Vec<u8>)>) -> Self {
        let wrapped = secrets
            .into_iter()
            .filter(|(_, bytes)| !bytes.is_empty())
            .map(|(gid, bytes)| (gid, SecretBytes::new(bytes)))
            .collect();
        Self::from_secret_bytes(wrapped)
    }

    pub fn from_secret_bytes(secrets: Vec<(String, SecretBytes)>) -> Self {
        let mut filtered: Vec<(String, SecretBytes)> = secrets
            .into_iter()
            .filter(|(_, bytes)| !bytes.as_bytes().is_empty())
            .collect();
        filtered.sort_by_key(|a| std::cmp::Reverse(a.1.as_bytes().len()));
        let max_len = filtered
            .iter()
            .map(|(_, b)| b.as_bytes().len())
            .max()
            .unwrap_or(0);
        Self {
            secrets: filtered,
            max_len,
            pending: Vec::new(),
        }
    }

    pub fn push_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.secrets.is_empty() {
            return chunk.to_vec();
        }
        self.pending.extend_from_slice(chunk);
        self.drain(false)
    }

    pub fn finish(&mut self) -> Vec<u8> {
        self.drain(true)
    }

    fn drain(&mut self, final_flush: bool) -> Vec<u8> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let hold_back = if final_flush {
            0
        } else {
            self.max_len.saturating_sub(1)
        };

        let mut out = Vec::with_capacity(self.pending.len());
        let mut cursor = 0usize;

        while cursor < self.pending.len() {
            let safe_limit = self.pending.len().saturating_sub(hold_back);
            if !final_flush && cursor >= safe_limit {
                break;
            }

            if let Some((gid, needle_len)) = self.match_at(cursor) {
                out.extend_from_slice(format!("[WARDLINE_REDACTED:{gid}]").as_bytes());
                cursor += needle_len;
            } else {
                out.push(self.pending[cursor]);
                cursor += 1;
            }
        }

        if cursor > 0 {
            self.pending[..cursor].zeroize();
            self.pending.drain(0..cursor);
        }
        out
    }

    fn match_at(&self, pos: usize) -> Option<(&str, usize)> {
        let rem = &self.pending[pos..];
        for (gid, secret) in &self.secrets {
            let needle = secret.as_bytes();
            if rem.starts_with(needle) {
                return Some((gid.as_str(), needle.len()));
            }
        }
        None
    }
}

impl Drop for StreamingScrubber {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secret_split_across_arbitrary_byte_boundaries() {
        let secret = b"ghp_SuperSecretToken987".to_vec();
        let mut scrubber = StreamingScrubber::new(vec![("gh".into(), secret)]);

        let mut full = Vec::new();
        full.extend_from_slice(&scrubber.push_chunk(b"prefix ghp_Sup"));
        full.extend_from_slice(&scrubber.push_chunk(b"erSecret"));
        full.extend_from_slice(&scrubber.push_chunk(b"Token987 suffix"));
        full.extend_from_slice(&scrubber.finish());

        assert_eq!(
            String::from_utf8(full).unwrap(),
            "prefix [WARDLINE_REDACTED:gh] suffix"
        );
    }
}
