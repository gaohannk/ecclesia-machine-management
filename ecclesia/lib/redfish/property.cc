// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "lib/redfish/property.h"

#include <string>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "lib/redfish/interface.h"

namespace libredfish {

void PropertyRegistry::Register(absl::string_view name,
                                PropertyRegistry::ExtractFunction f) {
  extract_func_map_[std::string(name)] = f;
}

void PropertyRegistry::ExtractAllProperties(RedfishObject *object,
                                            const absl::Time &collection_time,
                                            PropertyContainer *container) {
  for (const auto &name_to_func : extract_func_map_) {
    (*name_to_func.second)(object, container, collection_time);
  }
}

}  // namespace libredfish
