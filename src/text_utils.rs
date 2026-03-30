pub(crate) fn compute_line_starts(content: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    let mut iter = content.char_indices().peekable();

    while let Some((index, ch)) = iter.next() {
        match ch {
            '\r' => {
                let mut next_start = index + ch.len_utf8();
                if let Some((next_index, '\n')) = iter.peek().copied() {
                    next_start = next_index + '\n'.len_utf8();
                    iter.next();
                }
                if next_start <= content.len() {
                    starts.push(next_start);
                }
            }
            '\n' => {
                let next_start = index + ch.len_utf8();
                if next_start <= content.len() {
                    starts.push(next_start);
                }
            }
            _ => {}
        }
    }

    starts
}

pub(crate) fn find_line_index_for_offset(line_starts: &[usize], offset: usize) -> usize {
    match line_starts.binary_search(&offset) {
        Ok(index) => index,
        Err(index) => index.saturating_sub(1),
    }
}

#[cfg(test)]
mod tests {
    use super::{compute_line_starts, find_line_index_for_offset};

    #[test]
    fn compute_line_starts_handles_mixed_line_endings() {
        assert_eq!(vec![0, 2, 4, 5], compute_line_starts("a\nb\n\nc"));
        assert_eq!(vec![0, 4, 7], compute_line_starts("ab\r\nc\r\nd"));
        assert_eq!(vec![0, 2, 4], compute_line_starts("x\ry\rz"));
        assert_eq!(vec![0, 3], compute_line_starts("a\r\n"));
        assert_eq!(vec![0], compute_line_starts(""));
    }

    #[test]
    fn find_line_index_tracks_separator_offsets() {
        let starts = compute_line_starts("ab\r\nc\nd\re");
        assert_eq!(vec![0, 4, 6, 8], starts);

        let expected = [0, 0, 0, 0, 1, 1, 2, 2, 3];
        for (offset, expected_line) in expected.into_iter().enumerate() {
            assert_eq!(
                expected_line,
                find_line_index_for_offset(&starts, offset),
                "offset {offset}"
            );
        }
    }
}
