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

//! Kernel host adapters for standalone image loading.
//!
//! The loader core stays independent of kernel types. This module supplies the
//! flat memory mapping, instruction publication and native profile, then hands
//! the owning `LoadedImage` back to the caller. Startup ABI and application
//! lifecycle remain separate.

pub mod adapters;
mod loader;

pub use loader::{board_load_profile, load_from_memory, load_image, load_request};
