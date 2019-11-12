//! Ripped from https://github.com/gimli-rs/addr2line/blob/master/src/lib.rs

mod alloc {
    pub use std::{borrow, rc, string, sync, vec};
}

use alloc::borrow::Cow;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use std::cmp::Ordering;
use std::mem;
use std::u64;

use fallible_iterator::FallibleIterator;
use intervaltree::{Element, IntervalTree};
use lazycell::LazyCell;
use smallvec::SmallVec;

use crate::mapped_slice::MappedSlice;

type Error = gimli::Error;

pub struct Context<R = gimli::EndianRcSlice<gimli::RunTimeEndian>>
where
    R: gimli::Reader,
{
    pub unit_ranges: Vec<(gimli::Range, usize)>,
    units: Vec<ResUnit<R>>,
    pub sections: gimli::Dwarf<R>,
}

impl Context<gimli::EndianRcSlice<gimli::RunTimeEndian>> {
    /// Copy debug sections from the object file and manage them with Rc.
    pub fn new_rc<'data, 'file, O: object::Object<'data, 'file>>(
        file: &'file O,
    ) -> Result<Self, Error> {
        let endian = if file.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };

        fn load_section<'data, 'file, O, S, Endian>(file: &'file O, endian: Endian) -> S
        where
            O: object::Object<'data, 'file>,
            S: gimli::Section<gimli::EndianRcSlice<Endian>>,
            Endian: gimli::Endianity,
        {
            let data = file
                .section_data_by_name(S::section_name())
                .unwrap_or(Cow::Borrowed(&[]));
            S::from(gimli::EndianRcSlice::new(Rc::from(&*data), endian))
        }

        let debug_abbrev: gimli::DebugAbbrev<_> = load_section(file, endian);
        let debug_addr: gimli::DebugAddr<_> = load_section(file, endian);
        let debug_info: gimli::DebugInfo<_> = load_section(file, endian);
        let debug_line: gimli::DebugLine<_> = load_section(file, endian);
        let debug_line_str: gimli::DebugLineStr<_> = load_section(file, endian);
        let debug_ranges: gimli::DebugRanges<_> = load_section(file, endian);
        let debug_rnglists: gimli::DebugRngLists<_> = load_section(file, endian);
        let debug_str: gimli::DebugStr<_> = load_section(file, endian);
        let debug_str_offsets: gimli::DebugStrOffsets<_> = load_section(file, endian);
        let default_section = gimli::EndianRcSlice::new(Rc::from(&[][..]), endian);

        Context::from_sections(
            debug_abbrev,
            debug_addr,
            debug_info,
            debug_line,
            debug_line_str,
            debug_ranges,
            debug_rnglists,
            debug_str,
            debug_str_offsets,
            default_section,
        )
    }
}

impl Context<gimli::EndianArcSlice<gimli::RunTimeEndian>> {
    /// Copy debug sections from the object file and manage them with Arc.
    pub fn new_arc<'data, 'file, O: object::Object<'data, 'file>>(
        file: &'file O,
    ) -> Result<Self, Error> {
        let endian = if file.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };

        fn load_section<'data, 'file, O, S, Endian>(file: &'file O, endian: Endian) -> S
        where
            O: object::Object<'data, 'file>,
            S: gimli::Section<gimli::EndianArcSlice<Endian>>,
            Endian: gimli::Endianity,
        {
            let data = file
                .section_data_by_name(S::section_name())
                .unwrap_or(Cow::Borrowed(&[]));
            S::from(gimli::EndianArcSlice::new(Arc::from(&*data), endian))
        }

        let debug_abbrev: gimli::DebugAbbrev<_> = load_section(file, endian);
        let debug_addr: gimli::DebugAddr<_> = load_section(file, endian);
        let debug_info: gimli::DebugInfo<_> = load_section(file, endian);
        let debug_line: gimli::DebugLine<_> = load_section(file, endian);
        let debug_line_str: gimli::DebugLineStr<_> = load_section(file, endian);
        let debug_ranges: gimli::DebugRanges<_> = load_section(file, endian);
        let debug_rnglists: gimli::DebugRngLists<_> = load_section(file, endian);
        let debug_str: gimli::DebugStr<_> = load_section(file, endian);
        let debug_str_offsets: gimli::DebugStrOffsets<_> = load_section(file, endian);
        let default_section = gimli::EndianArcSlice::new(Arc::from(&[][..]), endian);

        Context::from_sections(
            debug_abbrev,
            debug_addr,
            debug_info,
            debug_line,
            debug_line_str,
            debug_ranges,
            debug_rnglists,
            debug_str,
            debug_str_offsets,
            default_section,
        )
    }
}

impl Context<gimli::EndianReader<gimli::RunTimeEndian, MappedSlice>> {
    /// Construct a context from a mapping. This is zero-copy - all the sections are used out of the mapping.
    pub fn new_from_mapping<'data, 'file, O: object::Object<'data, 'file>>(
        mapping: &'data MappedSlice,
        file: &'file O,
    ) -> Result<Self, Error> {
        use object::read::ObjectSection;

        let endian = if file.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };

        fn map_section<'data, 'file, O, S, Endian>(
            mapping: &MappedSlice,
            file: &'file O,
            endian: Endian,
        ) -> S
        where
            O: object::Object<'data, 'file>,
            S: gimli::Section<gimli::EndianReader<Endian, MappedSlice>>,
            Endian: gimli::Endianity,
        {
            let mapping = if let Some((offset, size)) =
                file.section_by_name(S::section_name()).and_then(|s| s.offset())
            {
                let offset = offset as usize;
                let size = size as usize;
                mapping.subslice(offset..offset + size)
            } else {
                mapping.subslice(0..0)
            };
            S::from(gimli::EndianReader::new(mapping, endian))
        }

        let debug_abbrev: gimli::DebugAbbrev<_> = map_section(mapping, file, endian);
        let debug_addr: gimli::DebugAddr<_> = map_section(mapping, file, endian);
        let debug_info: gimli::DebugInfo<_> = map_section(mapping, file, endian);
        let debug_line: gimli::DebugLine<_> = map_section(mapping, file, endian);
        let debug_line_str: gimli::DebugLineStr<_> = map_section(mapping, file, endian);
        let debug_ranges: gimli::DebugRanges<_> = map_section(mapping, file, endian);
        let debug_rnglists: gimli::DebugRngLists<_> = map_section(mapping, file, endian);
        let debug_str: gimli::DebugStr<_> = map_section(mapping, file, endian);
        let debug_str_offsets: gimli::DebugStrOffsets<_> = map_section(mapping, file, endian);
        let default_section = gimli::EndianReader::new(mapping.subslice(0..0), endian);

        Context::from_sections(
            debug_abbrev,
            debug_addr,
            debug_info,
            debug_line,
            debug_line_str,
            debug_ranges,
            debug_rnglists,
            debug_str,
            debug_str_offsets,
            default_section,
        )
    }
}

impl<R: gimli::Reader> Context<R> {
    /// Construct a new `Context` from DWARF sections.
    pub fn from_sections(
        debug_abbrev: gimli::DebugAbbrev<R>,
        debug_addr: gimli::DebugAddr<R>,
        debug_info: gimli::DebugInfo<R>,
        debug_line: gimli::DebugLine<R>,
        debug_line_str: gimli::DebugLineStr<R>,
        debug_ranges: gimli::DebugRanges<R>,
        debug_rnglists: gimli::DebugRngLists<R>,
        debug_str: gimli::DebugStr<R>,
        debug_str_offsets: gimli::DebugStrOffsets<R>,
        default_section: R,
    ) -> Result<Self, Error> {
        Self::from_dwarf(gimli::Dwarf {
            debug_abbrev,
            debug_addr,
            debug_info,
            debug_line,
            debug_line_str,
            debug_str,
            debug_str_offsets,
            debug_str_sup: default_section.clone().into(),
            debug_types: default_section.clone().into(),
            locations: gimli::LocationLists::new(
                default_section.clone().into(),
                default_section.clone().into(),
            ),
            ranges: gimli::RangeLists::new(debug_ranges, debug_rnglists),
        })
    }

    /// Construct a new `Context` from an existing [`gimli::Dwarf`] object.
    pub fn from_dwarf(sections: gimli::Dwarf<R>) -> Result<Self, Error> {
        let mut unit_ranges = Vec::new();
        let mut res_units = Vec::new();
        let mut units = sections.units();
        while let Some(header) = units.next()? {
            let unit_id = res_units.len();
            let dw_unit = match sections.unit(header) {
                Ok(dw_unit) => dw_unit,
                Err(_) => continue,
            };

            let lang;
            {
                let mut cursor = dw_unit.entries();

                let unit = match cursor.next_dfs()? {
                    Some((_, unit)) if unit.tag() == gimli::DW_TAG_compile_unit => unit,
                    _ => continue, // wtf?
                };

                lang = match unit.attr_value(gimli::DW_AT_language)? {
                    Some(gimli::AttributeValue::Language(lang)) => Some(lang),
                    _ => None,
                };
                let mut ranges = sections.unit_ranges(&dw_unit)?;
                while let Some(range) = ranges.next()? {
                    if range.begin == range.end {
                        continue;
                    }

                    unit_ranges.push((range, unit_id));
                }
            }

            res_units.push(ResUnit {
                dw_unit,
                lang,
                lines: LazyCell::new(),
                funcs: LazyCell::new(),
            });
        }

        unit_ranges.sort_by_key(|x| x.0.begin);

        // Ranges need to be disjoint so that we can binary search, but weak symbols can
        // cause overlap. In this case, we don't care which unit is used, so ignore the
        // beginning of the subseqent range to avoid overlap.
        let mut prev_end = 0;
        for range in &mut unit_ranges {
            if range.0.begin < prev_end {
                range.0.begin = prev_end;
            }
            if range.0.end < prev_end {
                range.0.end = prev_end;
            } else {
                prev_end = range.0.end;
            }
        }
        debug_assert!(unit_ranges.windows(2).all(|w| w[0].0.end <= w[1].0.begin));

        Ok(Context {
            units: res_units,
            unit_ranges,
            sections,
        })
    }

    pub fn units(&self) -> Vec<&gimli::Unit<R>> {
        self.units.iter().map(|r| &r.dw_unit).collect()
    }

    fn find_unit(&self, probe: u64) -> Option<usize> {
        let idx = self.unit_ranges.binary_search_by(|r| {
            if probe < r.0.begin {
                Ordering::Greater
            } else if probe >= r.0.end {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        });
        let idx = match idx {
            Ok(x) => x,
            Err(_) => return None,
        };

        let (_, unit_id) = self.unit_ranges[idx];
        Some(unit_id)
    }

    /// Find the source file and line corresponding to the given virtual memory address.
    pub fn find_location(&self, probe: u64) -> Result<Option<Location<'_>>, Error> {
        match self.find_unit(probe) {
            Some(unit_id) => self.units[unit_id].find_location(probe, &self.sections),
            None => Ok(None),
        }
    }

    /// Return an iterator for the function frames corresponding to the given virtual
    /// memory address.
    ///
    /// If the probe address is not for an inline function then only one frame is
    /// returned.
    ///
    /// If the probe address is for an inline function then the first frame corresponds
    /// to the innermost inline function.  Subsequent frames contain the caller and call
    /// location, until an non-inline caller is reached.
    pub fn find_frames(&self, probe: u64) -> Result<FrameIter<R>, Error> {
        let (unit_id, loc, funcs) = match self.find_unit(probe) {
            Some(unit_id) => {
                let unit = &self.units[unit_id];
                let loc = unit.find_location(probe, &self.sections)?;
                let funcs = unit.parse_functions(&self.sections)?;
                let mut res: SmallVec<[_; 16]> =
                    funcs.query_point(probe).map(|x| &x.value).collect();
                res.sort_by_key(|x| -x.depth);
                (unit_id, loc, res)
            }
            None => (0, None, SmallVec::new()),
        };

        Ok(FrameIter {
            unit_id,
            units: &self.units,
            sections: &self.sections,
            funcs: funcs.into_iter(),
            next: loc,
        })
    }

    /// Initialize all line data structures. This is used for benchmarks.
    #[doc(hidden)]
    pub fn parse_lines(&self) -> Result<(), Error> {
        for unit in &self.units {
            unit.parse_lines(&self.sections)?;
        }
        Ok(())
    }

    /// Initialize all function data structures. This is used for benchmarks.
    #[doc(hidden)]
    pub fn parse_functions(&self) -> Result<(), Error> {
        for unit in &self.units {
            unit.parse_functions(&self.sections)?;
        }
        Ok(())
    }
}

struct Lines {
    files: Vec<String>,
    sequences: Vec<LineSequence>,
}

struct LineSequence {
    start: u64,
    end: u64,
    rows: Vec<LineRow>,
}

struct LineRow {
    address: u64,
    file_index: u64,
    line: Option<u64>,
    column: Option<u64>,
}

struct Func<T> {
    entry_off: gimli::UnitOffset<T>,
    depth: isize,
}

struct ResUnit<R>
where
    R: gimli::Reader,
{
    dw_unit: gimli::Unit<R>,
    lang: Option<gimli::DwLang>,
    lines: LazyCell<Result<Lines, Error>>,
    funcs: LazyCell<Result<IntervalTree<u64, Func<R::Offset>>, Error>>,
}

impl<R> ResUnit<R>
where
    R: gimli::Reader,
{
    fn parse_lines(&self, sections: &gimli::Dwarf<R>) -> Result<Option<&Lines>, Error> {
        let ilnp = match self.dw_unit.line_program {
            Some(ref ilnp) => ilnp,
            None => return Ok(None),
        };
        self.lines
            .borrow_with(|| {
                let mut sequences = Vec::new();
                let mut sequence_rows = Vec::<LineRow>::new();
                let mut rows = ilnp.clone().rows();
                while let Some((_, row)) = rows.next_row()? {
                    if row.end_sequence() {
                        if let Some(start) = sequence_rows.first().map(|x| x.address) {
                            let end = row.address();
                            let mut rows = Vec::new();
                            mem::swap(&mut rows, &mut sequence_rows);
                            if start != 0 {
                                sequences.push(LineSequence { start, end, rows });
                            }
                        }
                        continue;
                    }

                    let address = row.address();
                    let file_index = row.file_index();
                    let line = row.line();
                    let column = match row.column() {
                        gimli::ColumnType::LeftEdge => None,
                        gimli::ColumnType::Column(x) => Some(x),
                    };

                    if let Some(last_row) = sequence_rows.last_mut() {
                        if last_row.address == address {
                            last_row.file_index = file_index;
                            last_row.line = line;
                            last_row.column = column;
                            continue;
                        }
                    }

                    sequence_rows.push(LineRow {
                        address,
                        file_index,
                        line,
                        column,
                    });
                }
                sequences.sort_by_key(|x| x.start);

                let mut files = Vec::new();
                let mut index = 0;
                let header = ilnp.header();
                while let Some(file) = header.file(index) {
                    files.push(self.render_file(file, header, sections)?);
                    index += 1;
                }

                Ok(Lines { files, sequences })
            })
            .as_ref()
            .map(Some)
            .map_err(Error::clone)
    }

    fn parse_functions(
        &self,
        sections: &gimli::Dwarf<R>,
    ) -> Result<&IntervalTree<u64, Func<R::Offset>>, Error> {
        self.funcs
            .borrow_with(|| {
                let mut results = Vec::new();
                let mut depth = 0;
                let mut cursor = self.dw_unit.entries();
                while let Some((d, entry)) = cursor.next_dfs()? {
                    depth += d;
                    match entry.tag() {
                        gimli::DW_TAG_subprogram | gimli::DW_TAG_inlined_subroutine => {
                            let mut ranges = sections.die_ranges(&self.dw_unit, entry)?;
                            while let Some(range) = ranges.next()? {
                                // Ignore invalid DWARF so that a query of 0 does not give
                                // a long list of matches.
                                // TODO: don't ignore if there is a section at this address
                                if range.begin == 0 {
                                    continue;
                                }
                                results.push(Element {
                                    range: range.begin..range.end,
                                    value: Func {
                                        entry_off: entry.offset(),
                                        depth,
                                    },
                                });
                            }
                        }
                        _ => (),
                    }
                }

                let tree: IntervalTree<_, _> = results.into_iter().collect();
                Ok(tree)
            })
            .as_ref()
            .map_err(Error::clone)
    }

    fn find_location(
        &self,
        probe: u64,
        sections: &gimli::Dwarf<R>,
    ) -> Result<Option<Location<'_>>, Error> {
        let lines = match self.parse_lines(sections)? {
            Some(lines) => lines,
            None => return Ok(None),
        };

        let idx = lines.sequences.binary_search_by(|sequence| {
            if probe < sequence.start {
                Ordering::Greater
            } else if probe >= sequence.end {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        });
        let idx = match idx {
            Ok(x) => x,
            Err(_) => return Ok(None),
        };
        let sequence = &lines.sequences[idx];

        let idx = sequence
            .rows
            .binary_search_by(|row| row.address.cmp(&probe));
        let idx = match idx {
            Ok(x) => x,
            Err(0) => return Ok(None),
            Err(x) => x - 1,
        };
        let row = &sequence.rows[idx];

        let file = lines.files.get(row.file_index as usize).map(String::as_str);
        Ok(Some(Location {
            file,
            line: row.line,
            column: row.column,
        }))
    }

    fn render_file(
        &self,
        file: &gimli::FileEntry<R, R::Offset>,
        header: &gimli::LineProgramHeader<R, R::Offset>,
        sections: &gimli::Dwarf<R>,
    ) -> Result<String, gimli::Error> {
        let mut path = if let Some(ref comp_dir) = self.dw_unit.comp_dir {
            comp_dir.to_string_lossy()?.into_owned()
        } else {
            String::new()
        };

        if let Some(directory) = file.directory(header) {
            path_push(
                &mut path,
                sections
                    .attr_string(&self.dw_unit, directory)?
                    .to_string_lossy()?
                    .as_ref(),
            );
        }

        path_push(
            &mut path,
            sections
                .attr_string(&self.dw_unit, file.path_name())?
                .to_string_lossy()?
                .as_ref(),
        );

        Ok(path)
    }
}

fn path_push(path: &mut String, p: &str) {
    if p.starts_with('/') {
        *path = p.to_string();
    } else {
        if !path.ends_with('/') {
            path.push('/');
        }
        *path += p;
    }
}

fn name_attr<'abbrev, 'unit, R>(
    entry: &gimli::DebuggingInformationEntry<'abbrev, 'unit, R, R::Offset>,
    unit: &ResUnit<R>,
    sections: &gimli::Dwarf<R>,
    units: &[ResUnit<R>],
    recursion_limit: usize,
) -> Result<Option<R>, Error>
where
    R: gimli::Reader,
{
    if recursion_limit == 0 {
        return Ok(None);
    }

    if let Some(attr) = entry.attr_value(gimli::DW_AT_linkage_name)? {
        if let Ok(val) = sections.attr_string(&unit.dw_unit, attr) {
            return Ok(Some(val));
        }
    }
    if let Some(attr) = entry.attr_value(gimli::DW_AT_MIPS_linkage_name)? {
        if let Ok(val) = sections.attr_string(&unit.dw_unit, attr) {
            return Ok(Some(val));
        }
    }
    if let Some(attr) = entry.attr_value(gimli::DW_AT_name)? {
        if let Ok(val) = sections.attr_string(&unit.dw_unit, attr) {
            return Ok(Some(val));
        }
    }

    let next = entry
        .attr_value(gimli::DW_AT_abstract_origin)?
        .or(entry.attr_value(gimli::DW_AT_specification)?);
    match next {
        Some(gimli::AttributeValue::UnitRef(offset)) => {
            let mut entries = unit.dw_unit.entries_at_offset(offset)?;
            if let Some((_, entry)) = entries.next_dfs()? {
                return name_attr(entry, unit, sections, units, recursion_limit - 1);
            } else {
                return Err(gimli::Error::NoEntryAtGivenOffset);
            }
        }
        Some(gimli::AttributeValue::DebugInfoRef(dr)) => {
            if let Some((unit, offset)) = units
                .iter()
                .filter_map(|unit| {
                    gimli::UnitSectionOffset::DebugInfoOffset(dr)
                        .to_unit_offset(&unit.dw_unit)
                        .map(|uo| (unit, uo))
                })
                .next()
            {
                let mut entries = unit.dw_unit.entries_at_offset(offset)?;
                if let Some((_, entry)) = entries.next_dfs()? {
                    return name_attr(entry, unit, sections, units, recursion_limit - 1);
                }
            } else {
                return Err(gimli::Error::NoEntryAtGivenOffset);
            }
        }
        _ => {}
    }

    Ok(None)
}

/// An iterator over function frames.
pub struct FrameIter<'ctx, R>
where
    R: gimli::Reader + 'ctx,
{
    unit_id: usize,
    units: &'ctx Vec<ResUnit<R>>,
    sections: &'ctx gimli::Dwarf<R>,
    funcs: smallvec::IntoIter<[&'ctx Func<R::Offset>; 16]>,
    next: Option<Location<'ctx>>,
}

impl<'ctx, R> FrameIter<'ctx, R>
where
    R: gimli::Reader + 'ctx,
{
    /// Advances the iterator and returns the next frame.
    pub fn next(&mut self) -> Result<Option<Frame<'ctx, R>>, Error> {
        let (loc, func) = match (self.next.take(), self.funcs.next()) {
            (None, None) => return Ok(None),
            (loc, Some(func)) => (loc, func),
            (Some(loc), None) => {
                return Ok(Some(Frame {
                    function: None,
                    location: Some(loc),
                }))
            }
        };

        let unit = &self.units[self.unit_id];

        let mut cursor = unit.dw_unit.entries_at_offset(func.entry_off)?;
        let (_, entry) = cursor
            .next_dfs()?
            .expect("DIE we read a while ago is no longer readable??");

        // Set an arbitrary recursion limit of 16
        let name = name_attr(entry, unit, self.sections, self.units, 16)?;

        if entry.tag() == gimli::DW_TAG_inlined_subroutine {
            let file = match entry.attr_value(gimli::DW_AT_call_file)? {
                Some(gimli::AttributeValue::FileIndex(fi)) => {
                    match unit.parse_lines(self.sections)? {
                        Some(lines) => lines.files.get(fi as usize).map(String::as_str),
                        None => None,
                    }
                }
                _ => None,
            };

            let line = entry
                .attr(gimli::DW_AT_call_line)?
                .and_then(|x| x.udata_value())
                .and_then(|x| if x == 0 { None } else { Some(x) });
            let column = entry
                .attr(gimli::DW_AT_call_column)?
                .and_then(|x| x.udata_value());

            self.next = Some(Location { file, line, column });
        }

        Ok(Some(Frame {
            function: name.map(|name| FunctionName {
                name,
                language: unit.lang,
            }),
            location: loc,
        }))
    }
}

impl<'ctx, R> FallibleIterator for FrameIter<'ctx, R>
where
    R: gimli::Reader + 'ctx,
{
    type Item = Frame<'ctx, R>;
    type Error = Error;

    #[inline]
    fn next(&mut self) -> Result<Option<Frame<'ctx, R>>, Error> {
        self.next()
    }
}

/// A function frame.
pub struct Frame<'ctx, R: gimli::Reader> {
    /// The name of the function.
    pub function: Option<FunctionName<R>>,
    /// The source location corresponding to this frame.
    pub location: Option<Location<'ctx>>,
}

/// A function name.
pub struct FunctionName<R: gimli::Reader> {
    /// The name of the function.
    pub name: R,
    /// The language of the compilation unit containing this function.
    pub language: Option<gimli::DwLang>,
}

impl<R: gimli::Reader> FunctionName<R> {
    /// The raw name of this function before demangling.
    pub fn raw_name(&self) -> Result<Cow<str>, Error> {
        self.name.to_string_lossy()
    }
}

/// A source location.
pub struct Location<'a> {
    /// The file name.
    pub file: Option<&'a str>,
    /// The line number.
    pub line: Option<u64>,
    /// The column number.
    pub column: Option<u64>,
}
