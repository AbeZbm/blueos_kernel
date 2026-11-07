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

//! Single-image validation, layout, mapping, relocation and runtime finalization.
//! Follow admit, inspect, plan, allocate, map, decode, relocate, then seal. Planning
//! scans dynamic tags once from the stable reader; decode reads records from the
//! mapped image. Map applies segment/hole permissions after all initialization;
//! relocation validates every write before applying any. Seal prepares the image's
//! lifecycle plan, synchronizes code and removes RELRO writes.
//! ELF table parsing and record formats are implemented in `crate::elf`.
//! Shared relocation and lifecycle algorithms live in `crate::relocation` and
//! `crate::lifecycle`; this module owns their placement in the loading stages.

mod admit;
mod allocate;
mod decode;
mod image_loader;
mod inspect;
mod map;
mod plan;
mod relocate;
mod seal;

pub(crate) use decode::DecodedImage;
pub(crate) use image_loader::ImageLoader;
pub(crate) use map::MappedImage;
pub(crate) use plan::PlannedImage;
pub(crate) use relocate::RelocatedImage;
pub(crate) use seal::SealedImage;
