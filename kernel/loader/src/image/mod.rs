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

//! Single-image validation, layout, mapping and dynamic metadata decoding.
//! Follow admit, inspect, plan, allocate, map, then decode. Planning scans dynamic
//! tags once from the stable reader; decode reads relocation records from the
//! mapped image. Relocation, cache synchronization and protection follow later.
//! ELF table parsing and record formats are implemented in `crate::elf`.

mod admit;
mod allocate;
mod decode;
mod image_loader;
mod inspect;
mod map;
mod plan;

pub(crate) use decode::DecodedImage;
pub(crate) use image_loader::{ImageLoader, LoadRequest};
pub(crate) use map::MappedImage;
pub(crate) use plan::PlannedImage;
