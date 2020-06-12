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

// parse ipmi interface options using flag

#ifndef ECCLESIA_MAGENT_LIB_IPMI_INTERFACE_OPTIONS_H_
#define ECCLESIA_MAGENT_LIB_IPMI_INTERFACE_OPTIONS_H_

#include <string>

namespace ecclesia {

struct IpmiInterfaceOptions {
  std::string interface_name;
  std::string hostname;
  std::string username;
  std::string password;
  int port;
};

IpmiInterfaceOptions ParseIpmiInterfaceOptions();

}  // namespace ecclesia

#endif  // ECCLESIA_MAGENT_LIB_IPMI_INTERFACE_OPTIONS_H_
