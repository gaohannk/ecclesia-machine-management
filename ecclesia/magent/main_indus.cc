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

// Redfish server for the Ecclesia Management Agent on Indus
#include <stdlib.h>

#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "lib/apifs/apifs.h"
#include "lib/io/ioctl.h"
#include "lib/smbios/platform_translator.h"
#include "lib/types/fixed_range_int.h"
#include "magent/lib/eeprom/eeprom.h"
#include "magent/lib/eeprom/smbus_eeprom.h"
#include "magent/lib/io/pci_sys.h"
#include "magent/lib/io/smbus.h"
#include "magent/lib/io/smbus_kernel_dev.h"
#include "magent/lib/ipmi/ipmitool.h"
#include "magent/main_common.h"
#include "magent/redfish/indus/redfish_service.h"
#include "magent/sysmodel/x86/sysmodel.h"
#include "tensorflow_serving/util/net_http/server/public/httpserver_interface.h"

ABSL_FLAG(int, port, 3995, "Port number for the magent to listen on");
ABSL_FLAG(std::string, assemblies_dir, "/etc/google/magent",
          "Path to a directory containing JSON Assemblies");
ABSL_FLAG(std::string, mced_socket_path, "/var/run/mced2.socket",
          "Path to the mced unix domain socket");

namespace {

using tensorflow::serving::net_http::HTTPServerInterface;

constexpr char kSmbiosEntryPointPath[] =
    "/sys/firmware/dmi/tables/smbios_entry_point";
constexpr char kSmbiosTablesPath[] = "/sys/firmware/dmi/tables/DMI";
constexpr char kSysfsMemFilePath[] = "/dev/mem";

// Indus machine specific settings.
// Please refer to: platforms/gsys/daemon/platform/indus/layout/indus.board
// It's less brittle to read a hardcoded pci address(0000:00:1f.4) on indus
// machine then always use a hardcoded smbus address. For this to work, we
// need kernel module i2c_mux_pca954x to be loaded. smbus_ipass_fru_mux
// (defined in indus board file), is at address 0x77, channel-2.
constexpr absl::string_view kSmbusPciAddressPath =
    "/sys/bus/pci/devices/0000:00:1f.4/";
absl::optional<ecclesia::SmbusBus> GetEepromSmbusBus() {
  ecclesia::ApifsDirectory dir(std::string{kSmbusPciAddressPath});
  std::vector<std::string> entries;
  if (!dir.ListEntries(&entries).ok()) {
    return absl::nullopt;
  }

  // We need to find the pci bus number.
  // Search for a pattern "i2c-\d+".
  int pci_bus = -1;
  // int len = sizeof(kSmbusPciAddressPath) + 4;
  for (absl::string_view f : entries) {
    f.remove_prefix(kSmbusPciAddressPath.size());
    if (absl::StartsWith(f, "i2c-") &&
        absl::SimpleAtoi(f.substr(4), &pci_bus)) {
      break;
    }
  }

  if (pci_bus == -1 || pci_bus > ecclesia::SmbusBus::kMaxValue) {
    return absl::nullopt;
  }

  ecclesia::ApifsFile fs(
      absl::StrFormat("/sys/bus/i2c/devices/%d-0077/channel-2", pci_bus));
  std::string link;
  absl::Status status = fs.ReadLink(&link);
  if (status.ok()) {
    int smbus_id;
    // link will have the format like : "../i2c-37".
    if (absl::SimpleAtoi(link.substr(link.find_last_of('-') + 1), &smbus_id)) {
      return ecclesia::SmbusBus::TryMake(smbus_id);
    }
  }

  return absl::nullopt;
}

// We will read i2c bus offset 0x55 to get board information.
// Fru common header has 8 bytes.
// https://www.intel.com/content/dam/www/public/us/en/documents/product-briefs/platform-management-fru-document-rev-1-2-feb-2013.pdf
constexpr auto kEepromSmbusAddress = ecclesia::SmbusAddress::Make<0x55>();

struct SkylakeImcDimmChannel {
  const absl::string_view name;
  ecclesia::PciLocation loc;
  // thermal info offset for channel0 is 0x150, for channel1 is 0x154
  std::array<size_t, 2> offset;
};

constexpr SkylakeImcDimmChannel dimm_channel_info[]{
    {"cpu0_1lms_0",
     ecclesia::PciLocation::Make<0, 0x3a, 0x0a, 2>(),
     {0x150, 0x154}},
    {"cpu0_1lms_1",
     ecclesia::PciLocation::Make<0, 0x3a, 0x0a, 6>(),
     {0x150, 0x154}},
    {"cpu0_1lms_2",
     ecclesia::PciLocation::Make<0, 0x3a, 0x0b, 2>(),
     {0x150, 0x154}},
    {"cpu0_1lms_5",
     ecclesia::PciLocation::Make<0, 0x3a, 0x0d, 2>(),
     {0x154, 0x150}},
    {"cpu0_1lms_4",
     ecclesia::PciLocation::Make<0, 0x3a, 0x0c, 6>(),
     {0x154, 0x150}},
    {"cpu0_1lms_3",
     ecclesia::PciLocation::Make<0, 0x3a, 0x0c, 2>(),
     {0x154, 0x150}},

    {"cpu1_1lms_0",
     ecclesia::PciLocation::Make<0, 0xae, 0x0a, 2>(),
     {0x150, 0x154}},
    {"cpu1_1lms_1",
     ecclesia::PciLocation::Make<0, 0xae, 0x0a, 6>(),
     {0x150, 0x154}},
    {"cpu1_1lms_2",
     ecclesia::PciLocation::Make<0, 0xae, 0x0b, 2>(),
     {0x150, 0x154}},
    {"cpu1_1lms_5",
     ecclesia::PciLocation::Make<0, 0xae, 0x0d, 2>(),
     {0x154, 0x150}},
    {"cpu1_1lms_4",
     ecclesia::PciLocation::Make<0, 0xae, 0x0c, 6>(),
     {0x154, 0x150}},
    {"cpu1_1lms_3",
     ecclesia::PciLocation::Make<0, 0xae, 0x0c, 2>(),
     {0x154, 0x150}}};

// Build dimm_thermal_devices using hardcoded infomation for SkylakeImc.
// return 12 pci devices, each devices can have up to 2 dimms.
// The order of the devices:
// cpu0: 1lms0, 1lms1, 1lms2, 1lms5, 1lms4, 1lms3
// cpu1: 1lms0, 1lms1, 1lms2, 1lms5, 1lms4, 1lms3
std::vector<std::unique_ptr<ecclesia::PciDevice>> CreateDimmThermalDevices() {
  std::vector<std::unique_ptr<ecclesia::PciDevice>> dimm_thermal_devices;
  dimm_thermal_devices.reserve(sizeof(dimm_channel_info) /
                               sizeof(dimm_channel_info[0]));
  for (const auto &info : dimm_channel_info) {
    auto pci_loc = info.loc;
    dimm_thermal_devices.push_back(std::make_unique<ecclesia::PciDevice>(
        pci_loc, std::make_unique<ecclesia::SysPciRegion>(pci_loc)));
  }

  return dimm_thermal_devices;
}

// Read dimm temperature in degree.
// We return a vector of int representing temperature,
// vector index corresponds with dimm index, nunllopt means "not present".
std::vector<absl::optional<int>> ReadAllDimmThermalDegrees(
    const std::vector<std::unique_ptr<ecclesia::PciDevice>> &devices,
    ecclesia::SystemModel *system_model) {
  std::vector<absl::optional<int>> dimm_thermal(devices.size() * 2);
  for (int i = 0; i < devices.size(); i++) {
    uint16_t t;
    auto config = devices[i]->config_space();

    // there are 2 dimms per channel
    auto dimm0 = system_model->GetDimm(i * 2);
    if (dimm0->GetDimmInfo().present) {
      absl::Status status =
          config.region()->Read16(dimm_channel_info[i].offset[0], &t);
      if (status.ok()) {
        dimm_thermal[i * 2] = t;
      } else {
        dimm_thermal[i * 2] = absl::nullopt;
      }
    }

    auto dimm1 = system_model->GetDimm(i * 2 + 1);
    if (dimm1->GetDimmInfo().present) {
      absl::Status status =
          config.region()->Read16(dimm_channel_info[i].offset[1], &t);
      if (status.ok()) {
        dimm_thermal[i * 2 + 1] = t;
      } else {
        dimm_thermal[i * 2 + 1] = absl::nullopt;
      }
    }
  }

  return dimm_thermal;
}

}  // namespace

int main(int argc, char **argv) {
  absl::ParseCommandLine(argc, argv);

  if (absl::GetFlag(FLAGS_assemblies_dir).empty()) {
    std::cerr << "a non-empty --assemblies_dir must be specified" << std::endl;
    return EXIT_FAILURE;
  }

  // Interfaces into the underlying platform.
  ecclesia::SysIoctl ioctl_intf;
  ecclesia::KernelSmbusAccess access("/dev", &ioctl_intf);

  std::vector<ecclesia::SmbusEeprom2ByteAddr::Option> eeprom_options;

  auto eeprom_smbus_bus = GetEepromSmbusBus();
  if (eeprom_smbus_bus) {
    ecclesia::SmbusLocation mainboard_loc(*eeprom_smbus_bus,
                                          kEepromSmbusAddress);

    ecclesia::SmbusDevice device(mainboard_loc, &access);

    ecclesia::SmbusEeprom2ByteAddr::Option motherboard_eeprom_option{
        .name = "motherboard",
        .size = {.type = ecclesia::Eeprom::SizeType::kFixed, .size = 8 * 1024},
        .mode = {.readable = 1, .writable = 0},
        .device = device};

    eeprom_options.push_back(motherboard_eeprom_option);
  }
  ecclesia::SysmodelParams params = {
      .field_translator =
          absl::make_unique<ecclesia::IndusSmbiosFieldTranslator>(),
      .smbios_entry_point_path = kSmbiosEntryPointPath,
      .smbios_tables_path = kSmbiosTablesPath,
      .mced_socket_path = absl::GetFlag(FLAGS_mced_socket_path),
      .sysfs_mem_file_path = kSysfsMemFilePath,
      .eeprom_options = absl::MakeSpan(eeprom_options)};

  std::unique_ptr<ecclesia::SystemModel> system_model =
      absl::make_unique<ecclesia::SystemModel>(std::move(params));

  auto dimm_thermal_devices = CreateDimmThermalDevices();

  // We haven't decided on the API for getting dimm thermal, so here we simply
  // return a vector of int to represent temperature in degree, the vector index
  // corresponds to dimm index.
  auto dimm_thermal =
      ReadAllDimmThermalDegrees(dimm_thermal_devices, system_model.get());

  ecclesia::Ipmitool ipmi(ecclesia::ParseIpmiInterfaceOptions());
  // Currently not being used.
  auto frus = ipmi.GetAllFrus();

  auto server = ecclesia::CreateServer(absl::GetFlag(FLAGS_port));
  ecclesia::IndusRedfishService redfish_service(
      server.get(), system_model.get(), absl::GetFlag(FLAGS_assemblies_dir));

  bool success = server->StartAcceptingRequests();
  if (server != nullptr && success) {
    server->WaitForTermination();
    return EXIT_SUCCESS;
  } else {
    std::cerr << "Failed to start the server." << std::endl;
    return EXIT_FAILURE;
  }
}
