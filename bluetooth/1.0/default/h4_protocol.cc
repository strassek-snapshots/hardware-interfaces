//
// Copyright 2017 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "h4_protocol.h"

#define LOG_TAG "android.hardware.bluetooth-hci-h4"
#include <android-base/logging.h>
#include <assert.h>
#include <fcntl.h>

namespace android {
namespace hardware {
namespace bluetooth {
namespace hci {

size_t H4Protocol::Send(uint8_t type, const uint8_t* data, size_t length) {
 uint8_t* comb_data;
 comb_data = (uint8_t*) malloc((sizeof(uint8_t)*length) + 1);
 memset(comb_data,0,((sizeof(uint8_t)*length) + 1));
 *comb_data = type;
 memcpy(comb_data+1 , data, (sizeof(uint8_t)*length));
 ++length;
 size_t rv = WriteSafely(uart_fd_, comb_data, length);
 if(rv >0)
   rv--;
 free(comb_data);
 return rv;
}

void H4Protocol::OnPacketReady() {
  switch (hci_packet_type_) {
    case HCI_PACKET_TYPE_EVENT:
      event_cb_(hci_packetizer_.GetPacket());
      break;
    case HCI_PACKET_TYPE_ACL_DATA:
      acl_cb_(hci_packetizer_.GetPacket());
      break;
    case HCI_PACKET_TYPE_SCO_DATA:
      sco_cb_(hci_packetizer_.GetPacket());
      break;
    default: {
      bool bad_packet_type = true;
      CHECK(!bad_packet_type);
    }
  }
  // Get ready for the next type byte.
  hci_packet_type_ = HCI_PACKET_TYPE_UNKNOWN;
}

#define MAX_EVENT_SIZE 1024*9
void H4Protocol::OnDataReady(int fd) {
  uint8_t event_buff[MAX_EVENT_SIZE] = {0};
  int byte_offset = 0 ;
  int event_buff_length = TEMP_FAILURE_RETRY(read(fd, event_buff, MAX_EVENT_SIZE));
  CHECK(event_buff_length > 0);

  if (hci_packet_type_ == HCI_PACKET_TYPE_UNKNOWN) {
    hci_packet_type_ = static_cast<HciPacketType>(event_buff[byte_offset]);
    byte_offset++;
    event_buff_length--;
  }
  hci_packetizer_.OnDataReady(&event_buff[byte_offset], event_buff_length, hci_packet_type_);
}

}  // namespace hci
}  // namespace bluetooth
}  // namespace hardware
}  // namespace android
