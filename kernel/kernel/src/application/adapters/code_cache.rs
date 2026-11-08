// Copyright (c) 2026 vivo Mobile Communication Co., Ltd.
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

//! Native instruction publication for the kernel's flat execution domain.

use blueos_loader::{
    error::{ErrorContext, LoadErrorKind},
    memory::TargetRange,
    CodeCache, LoadError, LoadResult,
};

/// Publishes loader-written code on the current execution context.
///
/// The caller keeps the image mapped for the whole call and must prevent
/// another context from executing it until this context's maintenance is
/// complete. The flat kernel model uses this backend while the calling thread
/// is pinned to one CPU for the load/execute window; a host-wide rendezvous is
/// required before the image may run on another core.
pub struct KernelCodeCache;

impl KernelCodeCache {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for KernelCodeCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeCache for KernelCodeCache {
    fn synchronize(&mut self, executable: TargetRange) -> LoadResult<()> {
        let end = executable.end()?;
        let context = || ErrorContext::TargetRange {
            start: executable.start(),
            len: executable.len(),
            align: 1,
        };
        let start = usize::try_from(executable.start().get())
            .map_err(|_| LoadError::new(LoadErrorKind::IntegerOverflow, context()))?;
        let end = usize::try_from(end.get())
            .map_err(|_| LoadError::new(LoadErrorKind::IntegerOverflow, context()))?;
        if start == end {
            return Ok(());
        }

        #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
        // SAFETY: the caller retains the mapped executable range and pins this
        // execution context; the fence has no memory or stack operands.
        unsafe {
            core::arch::asm!("fence.i", options(nostack, preserves_flags));
        }

        #[cfg(target_arch = "aarch64")]
        {
            let ctr_el0: u64;
            // SAFETY: the caller runs in kernel context where CTR_EL0 and cache
            // maintenance are accessible.
            unsafe {
                core::arch::asm!("mrs {value}, ctr_el0", value = out(reg) ctr_el0,
                    options(nostack));
            }
            let data_line = 4u64 << ((ctr_el0 >> 16) & 0xf);
            let instruction_line = 4u64 << (ctr_el0 & 0xf);
            let end = end as u64;

            let mut address = (start as u64) & !(data_line - 1);
            while address < end {
                // SAFETY: address names a cache line intersecting the live
                // caller-pinned range; privileged maintenance is permitted.
                unsafe {
                    core::arch::asm!("dc cvau, {address}", address = in(reg) address,
                        options(nostack, preserves_flags));
                }
                address = address.saturating_add(data_line);
            }
            // SAFETY: the barrier completes the preceding clean operations.
            unsafe { core::arch::asm!("dsb ish", options(nostack, preserves_flags)) };

            address = (start as u64) & !(instruction_line - 1);
            while address < end {
                // SAFETY: the same mapped lines remain pinned for instruction
                // invalidation, and the caller permits these instructions.
                unsafe {
                    core::arch::asm!("ic ivau, {address}", address = in(reg) address,
                        options(nostack, preserves_flags));
                }
                address = address.saturating_add(instruction_line);
            }
            // SAFETY: these barriers complete instruction publication without
            // touching memory or the stack.
            unsafe {
                core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags));
            }
        }

        #[cfg(not(any(
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "aarch64"
        )))]
        return Err(LoadError::new(LoadErrorKind::Backend, context()));

        Ok(())
    }
}
