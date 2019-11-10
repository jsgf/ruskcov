use std::{
    fs::File,
    io,
    ops::{Bound, Deref, RangeBounds},
    sync::Arc,
};

/// Slice of data from a mapped file
#[derive(Clone, Debug)]
pub struct MappedSlice {
    mapping: Arc<memmap::Mmap>,
    start: usize,
    end: usize,
}

impl MappedSlice {
    pub fn new(file: File) -> Result<Self, io::Error> {
        let map = unsafe { memmap::Mmap::map(&file)? };

        Ok(MappedSlice {
            start: 0,
            end: map.len(),
            mapping: Arc::new(map),
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &**self
    }

    /// Get a subslice from the same mapping for a given set of bounds
    pub fn subslice<R>(&self, range: R) -> Self
    where
        R: RangeBounds<usize>,
    {
        let start = match range.start_bound() {
            Bound::Unbounded => self.start,
            Bound::Included(start) => self.start + start,
            Bound::Excluded(start) => self.start + start + 1,
        };
        let end = match range.end_bound() {
            Bound::Unbounded => self.end,
            Bound::Excluded(end) => self.start + end,
            Bound::Included(end) => self.start + end + 1,
        };

        if start < self.start || end > self.end || end < start {
            panic!(
                "MappedSlice::subslice: bad bounds {}..{}; current range {}..{}, len {}, mapping 0..{}",
                start,
                end,
                self.start, self.end, self.len(),
                self.mapping.len()
            );
        }

        MappedSlice {
            mapping: self.mapping.clone(),
            start,
            end,
        }
    }

    /// Turn a [u8] slice back into new MappedSlice from the same mapping.
    /// Panics if the slice is not taken from the mapping.
    pub fn subslice_from_slice(&self, slice: &[u8]) -> Self {
        // Special case empty slice since it doesn't matter where it comes from.
        if slice.is_empty() {
            self.subslice(0..0)
        } else {
            let self_start = self.bytes().as_ptr() as usize;
            let start = slice.as_ptr() as usize;
            let end = start + slice.len();

            self.subslice((start - self_start)..(end - self_start))
        }
    }
}

impl Deref for MappedSlice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.mapping[self.start..self.end]
    }
}
unsafe impl gimli::StableDeref for MappedSlice {}
unsafe impl gimli::CloneStableDeref for MappedSlice {}
