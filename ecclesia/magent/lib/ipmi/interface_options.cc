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

#include "magent/lib/ipmi/interface_options.h"

#include "absl/flags/flag.h"

ABSL_FLAG(std::string, ipmi_interface, "lanplus",
          "ipmitool interface name for sending IPMI control messages, usually "
          "'open' or 'lanplus'");
ABSL_FLAG(std::string, ipmi_username, "root", "Username for RMCP+");
ABSL_FLAG(std::string, ipmi_password, "0penBmc", "Password for RMCP+");
ABSL_FLAG(std::string, ipmi_hostname, "fe80::a0d5:9dff:fe6c:6e6a%sleipnir0",
          "Hostname or IP address of BMC");
ABSL_FLAG(int, ipmi_port, 623, "Port on which the BMC will listen");

namespace ecclesia {

IpmiInterfaceOptions ParseIpmiInterfaceOptions() {
  IpmiInterfaceOptions options;

  options.interface_name = absl::GetFlag(FLAGS_ipmi_interface);
  options.hostname = absl::GetFlag(FLAGS_ipmi_hostname);
  options.username = absl::GetFlag(FLAGS_ipmi_username);
  options.password = absl::GetFlag(FLAGS_ipmi_password);
  options.port = absl::GetFlag(FLAGS_ipmi_port);

  return options;
}

}  // namespace ecclesia
