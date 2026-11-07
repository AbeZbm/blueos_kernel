// Copyright (c) 2025 vivo Mobile Communication Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_std]
#![cfg_attr(test, no_main)]
#![cfg_attr(test, feature(custom_test_frameworks))]
#![cfg_attr(test, test_runner(loader_test_runner))]
#![cfg_attr(test, reexport_test_harness_main = "loader_test_main")]

//! ELF inspection, mapping, relative relocation, lifecycle plans and finalization.
//!
//! Call [`load_elf`] with a reader, [`LoadRequest`], allocator and code cache
//! backend to obtain an owning [`LoadedImage`]. Loading prepares callback plans
//! without executing the entry or init/fini. Internal `elf` and `image` stages
//! remain crate-private; the complete dynamic linker will reuse those stages.
//! Host backends implement [`ElfReader`], [`ImageAllocator`], [`ImageMapping`] and [`CodeCache`],
//! available directly from the crate root. Memory support types remain in [`memory`].

mod cache;
pub mod error;
pub mod memory;
pub mod profile;
pub mod reader;
pub use cache::CodeCache;
pub use error::{LoadError, LoadResult};
pub use memory::{ImageAllocator, ImageMapping, MemoryPermissions};
pub use reader::ElfReader;

extern crate alloc;
mod elf;
mod image;
mod lifecycle;
mod load;
mod relocation;

pub use lifecycle::LifecyclePlan;
pub use load::{load_elf, LoadRequest, LoadedImage};

#[cfg(test)]
extern crate rsrt;
#[cfg(test)]
mod tests;

#[cfg(test)]
fn loader_test_runner(tests: &[&dyn Fn()]) {
    semihosting::println!("Loader unittest started");
    semihosting::println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
    semihosting::println!("Loader unittest ended");
}

#[cfg(test)]
#[cfg_attr(compatible_old_toolchain, no_mangle)]
#[cfg_attr(not(compatible_old_toolchain), unsafe(no_mangle))]
extern "C" fn main() -> i32 {
    librs::pthread::register_my_posix_tcb();
    loader_test_main();
    0
}
