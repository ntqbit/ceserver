use std::{collections::BTreeMap, sync::RwLock};

use crate::{
    defs::MemoryType,
    environment::{
        EnvAbi, EnvArch, EnvError, EnvPlatform, Environment, FindRegionsFlags, ModuleDesc, Process,
        ProcessDesc, ProcessId, Protection, RegionInfo, Result as EnvResult, Thread, ThreadDesc,
    },
};

struct MockProcessDesc {
    pid: ProcessId,
    name: String,
}

pub struct MockEnv {
    processes: BTreeMap<ProcessId, MockProcessDesc>,
}

impl MockEnv {
    pub fn new() -> Self {
        let processes_vec = [
            MockProcessDesc {
                pid: 100,
                name: "system".to_string(),
            },
            MockProcessDesc {
                pid: 10024,
                name: "sh.exe".to_string(),
            },
        ];

        let processes = BTreeMap::from_iter(processes_vec.into_iter().map(|d| (d.pid, d)));

        Self { processes }
    }
}

impl Environment for MockEnv {
    fn get_abi(&self) -> EnvAbi {
        EnvAbi::Other
    }

    fn get_platform(&self) -> EnvPlatform {
        EnvPlatform::Linux
    }

    fn list_processes(&self) -> EnvResult<Box<dyn Iterator<Item = ProcessDesc>>> {
        Ok(Box::new(
            self.processes
                .values()
                .map(|p| ProcessDesc {
                    pid: p.pid,
                    name: p.name.clone(),
                })
                .collect::<Vec<ProcessDesc>>()
                .into_iter(),
        ))
    }

    fn open_process(&self, pid: ProcessId) -> EnvResult<Box<dyn Process + Send + Sync>> {
        if let Some(desc) = self.processes.get(&pid) {
            Ok(Box::new(MockProcess::new(desc.pid, desc.name.clone())))
        } else {
            Err(EnvError::NoSuchProcess)
        }
    }
}

struct MockProcess {
    pid: ProcessId,
    name: String,
    memory: MemorySpace,
    modules: RwLock<Vec<ModuleDesc>>,
    threads: RwLock<Vec<ThreadDesc>>,
}

struct MemorySpace {
    // TODO: use more efficient data structure to query regions by range.
    regions: RwLock<Vec<Box<MemoryRegion>>>,
}

impl MemorySpace {
    const PAGE_SIZE: u64 = 0x1000;

    pub fn new() -> Self {
        Self {
            regions: RwLock::new(Vec::new()),
        }
    }

    pub fn add_region(&self, base: u64, size: usize) -> Result<u64, ()> {
        if size == 0 {
            return Err(());
        }

        let mut regions = self.regions.write().unwrap();

        if Self::check_overlaps(&*regions, base, size) {
            return Err(());
        }

        regions.push(Box::new(MemoryRegion::new(base, size)));
        Ok(base)
    }

    pub fn add_region_with_preferred_base(
        &self,
        preferred_base: Option<u64>,
        size: usize,
    ) -> Result<u64, ()> {
        match preferred_base {
            Some(base) => {
                if let Ok(res) = self.add_region(base, size) {
                    return Ok(res);
                }

                self.add_region_anywhere(size)
            }
            None => self.add_region_anywhere(size),
        }
    }

    pub fn add_region_anywhere(&self, size: usize) -> Result<u64, ()> {
        if size == 0 {
            return Err(());
        }

        // TODO: implement better base finding
        // Just take the largest end address of a region and round it up to the nearest page size multiple.
        let mut regions = self.regions.write().unwrap();

        let max_addr = regions
            .iter()
            .fold(Self::PAGE_SIZE as u64, |acc, x| acc.max(x.end()));

        // Round up.
        let base = (max_addr + Self::PAGE_SIZE - 1) & !(Self::PAGE_SIZE - 1);

        // Ensure that the new base doesn't overlap with anything. Just sanity check.
        debug_assert!(!Self::check_overlaps(&*regions, base, size));

        regions.push(Box::new(MemoryRegion::new(base, size)));
        Ok(base)
    }

    pub fn free_region(&self, base: u64, size: usize) -> Result<(), ()> {
        let mut regions = self.regions.write().unwrap();

        // Find index of the region.
        let Some(idx) = regions.iter().position(|r| r.contains(base)) else {
            return Err(());
        };

        // Check if the region base and size match.
        let region = &regions[idx];
        if region.base() != base || region.size() != size as u64 {
            return Err(());
        }

        regions.swap_remove(idx);
        Ok(())
    }

    fn check_overlaps(regions: &[Box<MemoryRegion>], base: u64, size: usize) -> bool {
        let end = base + size as u64;

        regions.iter().any(|r| r.overlaps(base, end))
    }

    pub fn find_region<T>(&self, addr: u64, f: impl FnOnce(&MemoryRegion) -> T) -> Option<T> {
        let regions = self.regions.read().unwrap();

        for region in regions.iter() {
            if region.contains(addr) {
                return Some(f(region));
            }
        }

        None
    }

    pub fn list_regions<T>(
        &self,
        f: impl FnOnce(&mut dyn Iterator<Item = &MemoryRegion>) -> T,
    ) -> T {
        let regions = self.regions.read().unwrap();
        let mut i = regions.iter().map(|x| x.as_ref());
        f(&mut i)
    }
}

struct MemoryRegion {
    base: u64,
    size: usize,
    data: RwLock<Vec<u8>>,
}

impl MemoryRegion {
    pub fn new(base: u64, size: usize) -> Self {
        Self {
            base,
            size,
            data: RwLock::new(vec![0; size]),
        }
    }

    pub fn size(&self) -> u64 {
        self.size as u64
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn end(&self) -> u64 {
        self.base + self.size()
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base() && addr < self.end()
    }

    pub fn overlaps(&self, begin: u64, end: u64) -> bool {
        begin < self.end() && self.base() < end
    }

    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<(), ()> {
        if offset + buf.len() > self.size {
            return Err(());
        }

        let data = self.data.read().unwrap();
        buf.copy_from_slice(&data[offset..offset + buf.len()]);
        Ok(())
    }

    pub fn write(&self, offset: usize, buf: &[u8]) -> Result<(), ()> {
        if offset + buf.len() > self.size {
            return Err(());
        }

        let mut data = self.data.write().unwrap();
        data[offset..offset + buf.len()].copy_from_slice(buf);
        Ok(())
    }
}

impl Into<RegionInfo> for &MemoryRegion {
    fn into(self) -> RegionInfo {
        RegionInfo {
            base: self.base(),
            size: self.size(),
            mem_type: MemoryType::MEM_PRIVATE,
            protection: Protection::PAGE_READWRITE,
        }
    }
}

impl MockProcess {
    pub fn new(pid: ProcessId, name: String) -> Self {
        let memory = MemorySpace::new();

        struct MemoryRegionDesc {
            base: u64,
            size: usize,
        }

        let regions = [
            MemoryRegionDesc {
                base: 0x10000,
                size: 0x1000,
            },
            MemoryRegionDesc {
                base: 0x50000,
                size: 0x2000,
            },
            MemoryRegionDesc {
                base: 0x100000,
                size: 0x10000,
            },
        ];

        for region in regions {
            memory.add_region(region.base, region.size).unwrap();
        }

        // Write process name to a region.
        memory
            .find_region(0x10000, |reg| reg.write(0, name.as_bytes()).unwrap())
            .unwrap();

        let modules = vec![
            ModuleDesc {
                base: 0x10000,
                size: 0x10000,
                fileoffset: 0,
                name: name.clone(),
            },
            ModuleDesc {
                base: 0x10000,
                size: 0x1000,
                fileoffset: 0,
                name: "unicorn".to_owned(),
            },
            ModuleDesc {
                base: 0x11000,
                size: 0x1000000,
                fileoffset: 0,
                name: "test.dll".to_owned(),
            },
        ];

        let thread_ids = [0x1000, 1234, 0xDEAD];
        let threads = thread_ids
            .into_iter()
            .map(|tid| ThreadDesc { thread_id: tid })
            .collect();

        Self {
            pid,
            name,
            memory,
            modules: RwLock::new(modules),
            threads: RwLock::new(threads),
        }
    }
}

impl Process for MockProcess {
    fn get_architecture(&self) -> EnvArch {
        EnvArch::x86_64
    }

    fn read_memory(&self, base: u64, buf: &mut [u8]) -> EnvResult<()> {
        self.memory
            .find_region(base, |region| {
                let offset = (base - region.base()) as usize;
                region.read(offset, buf)
            })
            .ok_or(EnvError::NoRegionFound)?
            .map_err(|_| EnvError::AccessOutsideBounds)
    }

    fn write_memory(&self, base: u64, buf: &[u8]) -> EnvResult<()> {
        self.memory
            .find_region(base, |region| {
                let offset = (base - region.base()) as usize;
                region.write(offset, buf)
            })
            .ok_or(EnvError::NoRegionFound)?
            .map_err(|_| EnvError::AccessOutsideBounds)
    }

    fn change_memory_protection(
        &self,
        base: u64,
        size: u64,
        protection: Protection,
    ) -> EnvResult<()> {
        // TODO: implement
        Ok(())
    }

    fn mem_alloc(
        &self,
        preferred_base: Option<u64>,
        size: u64,
        _protection: Protection, // TODO: use protection
    ) -> EnvResult<u64> {
        self.memory
            .add_region_with_preferred_base(preferred_base, size as usize)
            .map_err(|_| EnvError::NoRegionFound)
    }

    fn mem_free(&self, base: u64, size: u64) -> EnvResult<()> {
        self.memory
            .free_region(base, size as usize)
            .map_err(|_| EnvError::NoRegionFound)
    }

    fn query_region(&self, addr: u64) -> EnvResult<RegionInfo> {
        self.memory
            .find_region(addr, |region| region.into())
            .ok_or(EnvError::NoRegionFound)
    }

    fn list_regions(
        &self,
        _flags: FindRegionsFlags,
    ) -> EnvResult<Box<dyn Iterator<Item = RegionInfo>>> {
        Ok(Box::new(self.memory.list_regions(|iterator| {
            iterator.map(|r| r.into()).collect::<Vec<_>>().into_iter()
        })))
    }

    fn list_modules(&self) -> EnvResult<Box<dyn Iterator<Item = ModuleDesc>>> {
        Ok(Box::new(self.modules.read().unwrap().clone().into_iter()))
    }

    fn list_threads(&self) -> EnvResult<Box<dyn Iterator<Item = ThreadDesc>>> {
        Ok(Box::new(self.threads.read().unwrap().clone().into_iter()))
    }

    fn create_thread(
        &self,
        start_address: u64,
        parameter: u64,
    ) -> EnvResult<Box<dyn Thread + Send + Sync>> {
        todo!()
    }
}
