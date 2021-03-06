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

#include "ecclesia/lib/mcedecoder/mce_decode.h"

#include <cstdint>
#include <iostream>
#include <memory>
#include <utility>
#include <vector>

#include "ecclesia/lib/mcedecoder/bit_operator.h"
#include "ecclesia/lib/mcedecoder/cpu_topology.h"
#include "ecclesia/lib/mcedecoder/dimm_translator.h"
#include "ecclesia/lib/mcedecoder/mce_messages.h"
#include "ecclesia/lib/mcedecoder/skylake_mce_decode.h"

namespace mcedecoder {
namespace {

// Linux reports thermal throttle events as a fake machine check on bank 128.
constexpr int kLinuxThermalThrottleMceBank = 128;

using AttributeBits = std::pair<MceAttributes::MceAttributeKey, BitRange>;

void DecodeGenericIntelMceAttributes(const MceLogMessage &raw_msg,
                                     MceAttributes *attributes) {
  bool mci_status_valid = ExtractBits(raw_msg.mci_status, Bit(63));
  attributes->SetAttribute(MceAttributes::kMciStatusValid, mci_status_valid);
  if (mci_status_valid) {
    static const std::vector<AttributeBits> &attribute_bit_map =
        *(new std::vector<AttributeBits>(
            {{MceAttributes::kMciStatusUncorrected, Bit(61)},
             {MceAttributes::kMciStatusMiscValid, Bit(59)},
             {MceAttributes::kMciStatusAddrValid, Bit(58)},
             {MceAttributes::kMciStatusProcessorContexCorrupted, Bit(57)},
             {MceAttributes::kMciStatusModelSpecificErrorCode, Bits(31, 16)},
             {MceAttributes::kMciStatusMcaErrorCode, Bits(15, 0)}}));

    for (const auto &attribut_bit : attribute_bit_map) {
      attributes->SetAttribute(
          attribut_bit.first,
          ExtractBits(raw_msg.mci_status, attribut_bit.second));
    }

    if (attributes->GetAttributeWithDefault(MceAttributes::kMciStatusValid,
                                            false)) {
      attributes->SetAttribute(MceAttributes::kMciStatusRegister,
                               raw_msg.mci_status);
    }
    if (attributes->GetAttributeWithDefault(MceAttributes::kMciStatusMiscValid,
                                            false)) {
      attributes->SetAttribute(MceAttributes::kMciMiscRegister,
                               raw_msg.mci_misc);
    }
    if (attributes->GetAttributeWithDefault(MceAttributes::kMciStatusAddrValid,
                                            false)) {
      attributes->SetAttribute(MceAttributes::kMciAddrRegister,
                               raw_msg.mci_address);
    }
    if (!attributes->GetAttributeWithDefault(
            MceAttributes::kMciStatusUncorrected, true)) {
      attributes->SetAttribute(MceAttributes::kMciStatusCorrectedErrorCount,
                               ExtractBits(raw_msg.mci_status, Bits(52, 38)));
    }
  }
}

// Parse the decoded Intel MCE attributes and fill in the MCE decoded message.
// Return true upon success; otherwise return false.
bool ParseIntelDecodedMceAttributes(const MceAttributes &attributes,
                                    MceDecodedMessage *decoded_msg) {
  bool flag;
  if (!attributes.GetAttribute(MceAttributes::kMciStatusValid, &flag)) {
    return false;
  }
  if (!flag ||
      (decoded_msg->cpu_errors.empty() && decoded_msg->mem_errors.empty())) {
    decoded_msg->mce_bucket.mce_corrupt = true;
  } else {
    decoded_msg->mce_bucket.mce_corrupt = false;
  }

  int tmp_value;
  if (!attributes.GetAttribute(MceAttributes::kMceBank, &tmp_value)) {
    return false;
  }
  decoded_msg->mce_bucket.bank = tmp_value;
  if (!attributes.GetAttribute(MceAttributes::kSocketId, &tmp_value)) {
    return false;
  }
  decoded_msg->mce_bucket.socket = tmp_value;
  if (attributes.GetAttribute(MceAttributes::kMciStatusUncorrected, &flag)) {
    decoded_msg->mce_bucket.uncorrectable = flag;
  }
  if (attributes.GetAttribute(MceAttributes::kMciStatusProcessorContexCorrupted,
                              &flag)) {
    decoded_msg->mce_bucket.processor_context_corrupted = flag;
  }

  return true;
}

// Decode Intel MCE. Return true upon success; otherwise return false.
bool DecodeIntelMce(CpuIdentifier cpu_identifier, const MceLogMessage &raw_msg,
                    DimmTranslatorInterface *dimm_translator,
                    MceAttributes *attributes, MceDecodedMessage *decoded_msg) {
  DecodeGenericIntelMceAttributes(raw_msg, attributes);
  // Decode model specific MCE.
  switch (cpu_identifier) {
    case CpuIdentifier::kSkylake:
    case CpuIdentifier::kCascadeLake:
      DecodeSkylakeMce(dimm_translator, attributes, decoded_msg);
      break;
    default:
      std::cerr << "Unsupported CPU identifier" << std::endl;
      return false;
  }
  if (!ParseIntelDecodedMceAttributes(*attributes, decoded_msg)) {
    return false;
  }
  return true;
}

}  // namespace

bool MceDecoder::DecodeMceMessage(const MceLogMessage &raw_msg,
                                  MceDecodedMessage *decoded_msg) {
  MceAttributes mce_attributes;
  // Bypass the thermal throttle which is not a real MCE.
  if (raw_msg.bank == kLinuxThermalThrottleMceBank) {
    return false;
  }
  mce_attributes.SetAttribute(MceAttributes::kMceBank, raw_msg.bank);
  mce_attributes.SetAttribute(MceAttributes::kLpuId, raw_msg.lpu_id);
  if (cpu_topology_) {
    mce_attributes.SetAttribute(
        MceAttributes::kSocketId,
        cpu_topology_->GetSocketIdForLpu(raw_msg.lpu_id));
  }

  switch (cpu_vendor_) {
    case CpuVendor::kIntel:
      return DecodeIntelMce(cpu_identifier_, raw_msg, dimm_translator_.get(),
                            &mce_attributes, decoded_msg);
    default:
      return false;
  }
}
}  // namespace mcedecoder
