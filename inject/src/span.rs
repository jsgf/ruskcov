#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Span {
    pub start: usize,      // base in bytes
    pub len: usize,        // len in bytes
    pub addrs: Vec<usize>, // raw addrs
}

const PAGE_SIZE: usize = 4096;

impl Span {
    pub fn new(addr: usize) -> Self {
        Span {
            start: addr & !(PAGE_SIZE - 1),
            len: PAGE_SIZE,
            addrs: vec![addr],
        }
    }

    pub fn extend(self, other: Span) -> Result<Span, (Span, Span)> {
        if (self.start..(self.start + self.len + PAGE_SIZE)).contains(&other.start) {
            let mut addrs = self.addrs;
            addrs.extend(other.addrs);
            Ok(Span {
                start: self.start,
                len: other.start + other.len - self.start,
                addrs,
            })
        } else {
            Err((self, other))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use itertools::Itertools;
    use proptest::prelude::*;
    use std::collections::HashSet;

    #[test]
    fn simple() {
        let v = vec![100, 200, 300];

        let a: Vec<_> = v
            .into_iter()
            .map(Span::new)
            .coalesce(|prev, cur| prev.extend(cur))
            .collect();

        assert_eq!(
            vec![Span {
                start: 0,
                len: PAGE_SIZE,
                addrs: vec![100, 200, 300],
            },],
            a
        );
    }

    #[test]
    fn sparse() {
        let v = vec![10000, 20000, 30000];

        let a: Vec<_> = v
            .into_iter()
            .map(Span::new)
            .coalesce(|prev, cur| prev.extend(cur))
            .collect();

        assert_eq!(
            vec![
                Span {
                    start: 8192,
                    len: PAGE_SIZE,
                    addrs: vec![10000],
                },
                Span {
                    start: 16384,
                    len: PAGE_SIZE,
                    addrs: vec![20000],
                },
                Span {
                    start: 28672,
                    len: PAGE_SIZE,
                    addrs: vec![30000],
                },
            ],
            a
        );
    }

    #[test]
    fn adjacent() {
        let v = vec![4000, 5000];

        let a: Vec<_> = v
            .into_iter()
            .map(Span::new)
            .coalesce(|prev, cur| prev.extend(cur))
            .collect();

        assert_eq!(
            vec![Span {
                start: 0,
                len: PAGE_SIZE * 2,
                addrs: vec![4000, 5000],
            },],
            a
        );
    }

    prop_compose! {
        fn sorted_addrs(max_addr: usize, min_length: usize, max_length: usize)
                  (mut vec in prop::collection::vec(0..max_addr, min_length..max_length))
            -> Vec<usize>
        {
            vec.sort();
            vec
        }
    }

    proptest! {
        #[test]
        fn prop_contig(a in sorted_addrs(100000, 0, 1000)) {
            let spans: Vec<_> = a.into_iter().map(Span::new).coalesce(|prev, cur| prev.extend(cur)).collect();
            for Span { start, len, addrs} in spans {
                assert!(addrs.into_iter().all(|addr| addr >= start && addr < (start + len)));
            }
        }

        #[test]
        fn prop_non_overlap(a in sorted_addrs(100000, 0, 1000)) {
            let spans: Vec<_> = a.into_iter().map(Span::new).coalesce(|prev, cur| prev.extend(cur)).collect();

            for (idx, span) in spans[1..].iter().enumerate() {
                let prev = &spans[idx + 1 - 1];
                assert!(span.start >= (prev.start + prev.len), "non-contig span {:?}, prev {:?}", span, prev);
            }
        }

        #[test]
        fn prop_all_addrs(a in sorted_addrs(100000, 0, 1000)) {
            let addrs: HashSet<_> = a.iter().cloned().collect();
            let spans: Vec<_> = a.into_iter().map(Span::new).coalesce(|prev, cur| prev.extend(cur)).collect();

            let spanaddrs = spans.into_iter().flat_map(|s| s.addrs).collect();

            assert_eq!(addrs, spanaddrs);
        }

        #[test]
        fn prop_is_sorted(a in sorted_addrs(100000, 2, 1000)) {
            let spans: Vec<_> = a.into_iter().map(Span::new).coalesce(|prev, cur| prev.extend(cur)).collect();

            for (idx, span) in spans[1..].iter().enumerate() {
                let prev = &spans[idx + 1 - 1];
                assert!(prev < span);
            }
        }
    }
}
