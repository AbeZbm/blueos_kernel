// NEWLINE-TIMEOUT: 10
// ASSERT-SUCC: Loader integration test ended
// ASSERT-FAIL: Backtrace in Panic.*

#![no_main]
#![no_std]
#![feature(custom_test_frameworks)]
#![test_runner(loader_test_runner)]
#![reexport_test_harness_main = "loader_test_main"]

extern crate alloc;
extern crate rsrt;

mod runner;
use blueos::application::adapters::{
    FlatImageAllocation, MemoryMapper, MemoryRegion, SliceElfReader,
};
use runner::FileReader;
// Import it just for the global allocator.
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use blueos_loader as loader;
use core::{
    ffi::{c_char, CStr},
    sync::atomic::{AtomicBool, Ordering},
};
use librs::pthread;
use semihosting::{io::Read, println};

extern "C" {
    static LOADER_TEST_ELF_PATH: *const c_char;
    static INVALID_MAGIC_ELF_PATH: *const c_char;
    static INVALID_ENTRY_ELF_PATH: *const c_char;
    static INVALID_SEGMENT_SIZE_ELF_PATH: *const c_char;
}

fn read_all(ptr: *const core::ffi::c_char) -> semihosting::io::Result<Vec<u8>> {
    let path = unsafe { core::ffi::CStr::from_ptr(ptr) };
    let mut file = semihosting::fs::File::open(path)?;
    let mut tmp = [0u8; 64];
    let mut buf = Vec::new();
    loop {
        let size = file.read(&mut tmp)?;
        if size == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..size]);
    }
    Ok(buf)
}

mod test_elf_loader {
    #[cfg(loader_test_exec)]
    use super::runner::fixed::{
        TEST_REGIONS, TEST_REGION_END, TEST_REGION_PERMISSIONS, TEST_REGION_START,
    };
    use super::*;
    use blueos_test_macro::test;

    #[cfg(loader_test_exec)]
    const EXPECTED_RESULT: u32 = 0x9afc_e987;

    #[cfg(loader_test_exec)]
    static SHORT_REGIONS: [MemoryRegion; 1] = [unsafe {
        // SAFETY: This is a valid subset of the configured loader test range.
        MemoryRegion::new(
            TEST_REGION_START,
            TEST_REGION_START + 16,
            TEST_REGION_PERMISSIONS,
        )
    }];

    #[cfg(loader_test_exec)]
    static NON_EXEC_REGIONS: [MemoryRegion; 1] = [unsafe {
        // SAFETY: The configured region supports read and write accesses.
        MemoryRegion::new(
            TEST_REGION_START,
            TEST_REGION_END,
            loader::MemoryPermissions::READ.bitor(loader::MemoryPermissions::WRITE),
        )
    }];

    fn new_mapper() -> MemoryMapper {
        #[cfg(loader_test_exec)]
        {
            MemoryMapper::new(Some(&TEST_REGIONS))
        }
        #[cfg(not(loader_test_exec))]
        {
            MemoryMapper::new(None)
        }
    }

    fn run(image: &loader::LoadedImage<FlatImageAllocation>) {
        // These fixtures do not define runtime lifecycle hooks.
        assert!(image.lifecycle().preinit().is_empty());
        assert!(image.lifecycle().init().is_empty());
        assert!(image.lifecycle().fini().is_empty());
        let entry = usize::try_from(image.entry().expect("application entry").get()).unwrap();
        #[cfg(loader_test_exec)]
        {
            // SAFETY: the configured fixture declares a synchronous C entry
            // returning u32; image and the pinned cache context remain alive.
            let function: extern "C" fn() -> u32 = unsafe { core::mem::transmute(entry) };
            assert_eq!(function(), EXPECTED_RESULT);
        }
        #[cfg(not(loader_test_exec))]
        {
            // SAFETY: the PIC fixture declares a synchronous C fn() entry;
            // image retains its initialized backing in the local cache context.
            let function: extern "C" fn() = unsafe { core::mem::transmute(entry) };
            function();
        }
    }

    // The release-only slice case retains the complete file, including debug
    // sections. The positional reader case below also runs in debug builds.
    #[cfg(not(debug_assertions))]
    #[test]
    fn test_load_elf_and_run() {
        let bytes = read_all(unsafe { LOADER_TEST_ELF_PATH }).unwrap();
        let (_pinned, mut cache) = runner::pinned_cache();
        let image = loader::load_elf(
            SliceElfReader::new(&bytes),
            blueos::application::load_request(),
            new_mapper(),
            &mut cache,
        )
        .expect("load ELF from memory");
        run(&image);
    }

    // A direct RTOS thread without a Process uses the kernel's production
    // reader, flat allocator and cache backend. Loading and handing off the
    // image must not depend on Process/VFS state.
    #[test]
    fn test_load_elf_in_unowned_rtos_thread() {
        let bytes = read_all(unsafe { LOADER_TEST_ELF_PATH }).unwrap();
        #[cfg(loader_test_exec)]
        let regions = Some(&runner::fixed::TEST_REGIONS);
        #[cfg(not(loader_test_exec))]
        let regions = None;

        let done = Arc::new(blueos::sync::ConstBarrier::<{ 2 }>::new());
        let loaded = Arc::new(AtomicBool::new(false));
        let done_w = done.clone();
        let loaded_w = loaded.clone();
        // The default thread stack is too small for ELF inspection on 32-bit
        // release builds; the load runs in a thread with the app stack size.
        let stack = blueos::thread::Stack::from_size(16 << 10).expect("loader test stack");
        let mut t =
            blueos::thread::Builder::new(blueos::thread::Entry::Closure(Box::new(move || {
                let image = blueos::application::load_from_memory(&bytes, regions)
                    .expect("load ELF in an unowned RTOS thread");
                assert!(image.entry().is_some());
                loaded_w.store(true, Ordering::Release);
                done_w.wait();
                blueos::scheduler::retire_me();
            })))
            .set_stack(stack)
            .build();
        assert!(t.process().is_none());
        assert_eq!(
            blueos::scheduler::queue_ready_thread(blueos::thread::IDLE, t),
            Ok(())
        );
        done.wait();
        assert!(loaded.load(Ordering::Acquire));
    }

    #[test]
    fn test_load_elf_from_file_and_run() {
        let input = open(unsafe { LOADER_TEST_ELF_PATH });
        let (_pinned, mut cache) = runner::pinned_cache();
        let image = loader::load_elf(
            input,
            blueos::application::load_request(),
            new_mapper(),
            &mut cache,
        )
        .expect("load ELF through positional file reads");
        run(&image);
    }

    fn open(ptr: *const c_char) -> FileReader {
        // SAFETY: the linker-generated test symbols point to live NUL-terminated paths.
        FileReader::open(unsafe { CStr::from_ptr(ptr) }).expect("open ELF fixture")
    }

    #[test]
    fn test_invalid_entry() {
        let input = open(unsafe { INVALID_ENTRY_ELF_PATH });
        let (_pinned, mut cache) = runner::pinned_cache();
        assert!(loader::load_elf(
            input,
            blueos::application::load_request(),
            new_mapper(),
            &mut cache
        )
        .is_err());
    }

    #[test]
    fn test_invalid_magic() {
        let input = open(unsafe { INVALID_MAGIC_ELF_PATH });
        let (_pinned, mut cache) = runner::pinned_cache();
        assert!(loader::load_elf(
            input,
            blueos::application::load_request(),
            new_mapper(),
            &mut cache
        )
        .is_err());
    }

    #[test]
    fn test_invalid_segment_size() {
        let input = open(unsafe { INVALID_SEGMENT_SIZE_ELF_PATH });
        let (_pinned, mut cache) = runner::pinned_cache();
        assert!(loader::load_elf(
            input,
            blueos::application::load_request(),
            new_mapper(),
            &mut cache
        )
        .is_err());
    }

    #[cfg(loader_test_exec)]
    #[test]
    fn test_exec_requires_fixed_region_authorization() {
        let input = open(unsafe { LOADER_TEST_ELF_PATH });
        let (_pinned, mut cache) = runner::pinned_cache();
        let mapper = MemoryMapper::new(None);
        assert!(loader::load_elf(
            input,
            blueos::application::load_request(),
            mapper,
            &mut cache
        )
        .is_err());
    }

    #[cfg(loader_test_exec)]
    #[test]
    fn test_exec_rejects_out_of_range_without_writing() {
        let input = open(unsafe { LOADER_TEST_ELF_PATH });
        let before = unsafe { (TEST_REGION_START as *const u32).read_volatile() };
        let (_pinned, mut cache) = runner::pinned_cache();
        let mapper = MemoryMapper::new(Some(&SHORT_REGIONS));
        assert!(loader::load_elf(
            input,
            blueos::application::load_request(),
            mapper,
            &mut cache
        )
        .is_err());
        let after = unsafe { (TEST_REGION_START as *const u32).read_volatile() };
        assert_eq!(after, before);
    }

    #[cfg(loader_test_exec)]
    #[test]
    fn test_exec_rejects_non_executable_region() {
        let input = open(unsafe { LOADER_TEST_ELF_PATH });
        let (_pinned, mut cache) = runner::pinned_cache();
        let mapper = MemoryMapper::new(Some(&NON_EXEC_REGIONS));
        assert!(loader::load_elf(
            input,
            blueos::application::load_request(),
            mapper,
            &mut cache
        )
        .is_err());
    }

    #[cfg(loader_test_exec)]
    #[test]
    fn test_exec_releases_fixed_region_after_image_drop() {
        let bytes = read_all(unsafe { LOADER_TEST_ELF_PATH }).unwrap();
        let (_pinned, mut cache) = runner::pinned_cache();
        let image = loader::load_elf(
            SliceElfReader::new(&bytes),
            blueos::application::load_request(),
            new_mapper(),
            &mut cache,
        )
        .expect("first fixed mapping");
        run(&image);
        assert!(loader::load_elf(
            SliceElfReader::new(&bytes),
            blueos::application::load_request(),
            new_mapper(),
            &mut cache
        )
        .is_err());
        drop(image);
        let image = loader::load_elf(
            SliceElfReader::new(&bytes),
            blueos::application::load_request(),
            new_mapper(),
            &mut cache,
        )
        .expect("fixed region released and prepared again");
        run(&image);
    }
}

#[cfg_attr(compatible_old_toolchain, no_mangle)]
#[cfg_attr(not(compatible_old_toolchain), unsafe(no_mangle))]
pub fn loader_test_runner(tests: &[&dyn Fn()]) {
    println!("Loader integration test started");
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
    println!("Loader integration test ended");
}

#[cfg_attr(compatible_old_toolchain, no_mangle)]
#[cfg_attr(not(compatible_old_toolchain), unsafe(no_mangle))]
pub extern "C" fn main() -> i32 {
    pthread::register_my_posix_tcb();
    loader_test_main();
    #[cfg(coverage)]
    common_cov::write_coverage_data();
    0
}
