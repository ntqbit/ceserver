use core::hash::Hash;
use std::collections::HashSet;

#[derive(Debug)]
pub struct NoMoreHandles;

#[derive(Debug)]
pub struct NoSuchHandle;

pub struct HandleAllocator<T> {
    next: T,
    free_handles: HashSet<T>,
}

pub trait Handle: Hash + Eq + PartialOrd + Copy {
    const MAX: Self;
    const ONE: Self;

    fn inc(&mut self);
}

impl<T: Handle> HandleAllocator<T> {
    pub fn new() -> Self {
        Self {
            next: T::ONE,
            free_handles: HashSet::new(),
        }
    }

    pub fn allocate(&mut self) -> Result<T, NoMoreHandles> {
        if self.next == T::MAX {
            if let Some(handle) = self.free_handles.iter().next() {
                Ok(*handle)
            } else {
                Err(NoMoreHandles)
            }
        } else {
            let handle = self.next;
            self.next.inc();
            Ok(handle)
        }
    }

    pub fn is_allocated(&self, handle: T) -> bool {
        !self.free_handles.contains(&handle) && handle < self.next
    }

    pub fn deallocate(&mut self, handle: T) -> Result<(), NoSuchHandle> {
        if handle >= self.next || self.free_handles.contains(&handle) {
            Err(NoSuchHandle)
        } else {
            self.free_handles.insert(handle);
            Ok(())
        }
    }
}

impl Handle for u32 {
    const MAX: Self = u32::MAX;
    const ONE: Self = 1u32;

    fn inc(&mut self) {
        *self += 1;
    }
}