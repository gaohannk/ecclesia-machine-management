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

// Classes to support ipmi access.

#ifndef ECCLESIA_MAGENT_LIB_IPMI_IPMITOOL_H_
#define ECCLESIA_MAGENT_LIB_IPMI_IPMITOOL_H_

#include "absl/status/status.h"
#include "magent/lib/ipmi/interface_options.h"
#include "magent/lib/ipmi/ipmi.h"

struct ipmi_intf;
struct ipmi_rs;
struct sdr_record_fru_locator;

namespace ecclesia {

// The length needs to be at least two bytes [netfn][cmd]
constexpr int kMinimumIpmiPacketLength = 2;
constexpr int kMaximumPipelineBandwidth = 58;

extern const uint8_t IPMI_OK_CODE;
extern const uint8_t IPMI_INVALID_CMD_COMPLETION_CODE;
extern const uint8_t IPMI_TIMEOUT_COMPLETION_CODE;
extern const uint8_t IPMI_UNKNOWN_ERR_COMPLETION_CODE;

// IPMI network functions from the spec.
enum class IpmiNetworkFunction : uint8_t {
  kChassis = 0x00,
  kBridge = 0x02,
  kSensorOrEvent = 0x04,
  kApp = 0x6,
  kFirmware = 0x8,
  kStorage = 0x0a,
  kTransport = 0x0c,
  kGroup = 0x2c,
  kOem = 0x2e,
};

// IPMI commands from the spec.
enum class IpmiCommand : uint8_t {
  kGetDeviceId = 0x1,
  kGetFruInfo = 0x10,
};

class IpmiPair {
 public:
  constexpr IpmiPair(IpmiNetworkFunction netfn, IpmiCommand cmd)
      : network_function_(netfn), command_(cmd) {}

  IpmiPair(const IpmiPair &) = delete;
  IpmiPair &operator=(const IpmiPair &) = delete;

  IpmiPair(const IpmiPair &&) = delete;
  IpmiPair &operator=(const IpmiPair &&) = delete;

  IpmiNetworkFunction network_function() const { return network_function_; }
  IpmiCommand command() const { return command_; }

 private:
  IpmiNetworkFunction network_function_;
  IpmiCommand command_;
};

static constexpr IpmiPair kGetDeviceId{IpmiNetworkFunction::kApp,
                                       IpmiCommand::kGetDeviceId};
static constexpr IpmiPair kGetFruInfo{IpmiNetworkFunction::kStorage,
                                      IpmiCommand::kGetFruInfo};

struct IpmiRequest {
  IpmiNetworkFunction network_function;
  IpmiCommand command;
  absl::Span<const uint8_t> data;

  explicit IpmiRequest(const IpmiPair &netfn_cmd)
      : network_function(netfn_cmd.network_function()),
        command(netfn_cmd.command()) {}

  IpmiRequest(const IpmiPair &netfn_cmd, absl::Span<const uint8> data)
      : network_function(netfn_cmd.network_function()),
        command(netfn_cmd.command()),
        data(data) {}
};

struct IpmiResponse {
  int ccode;
  std::vector<uint8_t> data;
};

class Ipmitool : public IpmiInterface {
 public:
  explicit Ipmitool(IpmiInterfaceOptions options);

  std::vector<BmcFruInterfaceInfo> GetAllFrus() override {
    return ipmi_impl_->GetAllFrus();
  }

  absl::Status ReadFru(uint8_t fru_id, size_t offset,
                       absl::Span<unsigned char> data) override {
    return ipmi_impl_->ReadFru(fru_id, offset, data);
  }

  absl::Status GetFruSize(uint8_t fru_id, uint16_t *size) override {
    return ipmi_impl_->GetFruSize(fru_id, size);
  }

 private:
  std::unique_ptr<IpmiInterface> ipmi_impl_;
};

}  // namespace ecclesia

#endif  // ECCLESIA_MAGENT_LIB_IPMI_IPMITOOL_H_
