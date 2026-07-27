//! RFC 8613 §7.4: anti-replay sliding window (RFC 6347 §4.1.2.6 style), default size 32.

pub const WINDOW_SIZE: u32 = 32;

#[derive(Debug, PartialEq, Eq)]
pub enum ReplayError {
    TooOld,
    Replayed,
}

pub struct ReplayWindow {
    highest: u64,
    bitmap: u32,
    initialized: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
            initialized: false,
        }
    }

    /// Checks whether `seq` falls inside the replay window and has not been seen
    /// before, marking it as seen if so.
    pub fn check_and_update(&mut self, seq: u64) -> Result<(), ReplayError> {
        if !self.initialized {
            self.initialized = true;
            self.highest = seq;
            self.bitmap = 1;
            return Ok(());
        }

        if seq > self.highest {
            let shift = seq - self.highest;
            self.bitmap = if shift >= WINDOW_SIZE as u64 {
                0
            } else {
                self.bitmap << shift
            };
            self.bitmap |= 1;
            self.highest = seq;
            Ok(())
        } else {
            let offset = self.highest - seq;
            if offset >= WINDOW_SIZE as u64 {
                Err(ReplayError::TooOld)
            } else if self.bitmap & (1 << offset) != 0 {
                Err(ReplayError::Replayed)
            } else {
                self.bitmap |= 1 << offset;
                Ok(())
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_strictly_increasing_sequence() {
        let mut w = ReplayWindow::new();
        for seq in 0..10 {
            assert!(w.check_and_update(seq).is_ok());
        }
    }

    #[test]
    fn rejects_exact_replay() {
        let mut w = ReplayWindow::new();
        w.check_and_update(5).unwrap();
        assert_eq!(w.check_and_update(5), Err(ReplayError::Replayed));
    }

    #[test]
    fn accepts_reordered_within_window() {
        let mut w = ReplayWindow::new();
        w.check_and_update(10).unwrap();
        assert!(w.check_and_update(8).is_ok());
        assert!(w.check_and_update(9).is_ok());
        assert_eq!(w.check_and_update(8), Err(ReplayError::Replayed));
    }

    #[test]
    fn rejects_too_old() {
        let mut w = ReplayWindow::new();
        w.check_and_update(100).unwrap();
        assert_eq!(
            w.check_and_update(100 - WINDOW_SIZE as u64),
            Err(ReplayError::TooOld)
        );
    }

    #[test]
    fn large_forward_jump_resets_window() {
        let mut w = ReplayWindow::new();
        w.check_and_update(5).unwrap();
        w.check_and_update(5 + WINDOW_SIZE as u64 + 100).unwrap();
        assert_eq!(w.check_and_update(5), Err(ReplayError::TooOld));
    }
}
