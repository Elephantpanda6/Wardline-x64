use std::fs::File;
use std::io;
use std::ops::{Deref, DerefMut};

use wardline_platform::flock::ExclusiveFileLock;

pub struct FileWriteLock(ExclusiveFileLock);

impl FileWriteLock {
    pub fn acquire_exclusive(file: File) -> io::Result<Self> {
        ExclusiveFileLock::acquire_exclusive(file).map(Self)
    }
}

impl Deref for FileWriteLock {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FileWriteLock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
