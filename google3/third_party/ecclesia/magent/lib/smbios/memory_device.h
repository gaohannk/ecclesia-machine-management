/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ECCLESIA_MAGENT_LIB_SMBIOS_MEMORY_DEVICE_H_
#define ECCLESIA_MAGENT_LIB_SMBIOS_MEMORY_DEVICE_H_

#include <stddef.h>

#include "absl/strings/string_view.h"
#include "magent/lib/smbios/internal.h"
#include "magent/lib/smbios/structures.emb.h"

namespace ecclesia {

// SMBIOS Type 17 structure
class MemoryDevice {
 public:
  // The constructor takes in a pointer to a smbios structure of type 17 (Memory
  // Device) and provides an emboss view to access the structure fields.
  // table_entry outlives this object
  MemoryDevice(const TableEntry *table_entry) : table_entry_(table_entry) {}

  // Given a string number found in the smbios structure, return the
  // corresponding string
  absl::string_view GetString(size_t num) const {
    return table_entry_->GetString(num);
  }

  // Get a message view that represents the MemorydeviceStructure defined in
  // smbios_structures.emb
  MemoryDeviceStructureView GetMessageView() const {
    return table_entry_->GetSmbiosStructureView().memory_device();
  }

 private:
  const TableEntry *table_entry_;
};

}  // namespace ecclesia

#endif  // ECCLESIA_MAGENT_LIB_SMBIOS_MEMORY_DEVICE_H_
