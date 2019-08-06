#pragma once

#include "common/utils.h"
#include "transport/transport_utils.h"

namespace lego {

namespace transport {

class Processor {
public:
    static Processor* Instance();
    void RegisterProcessor(uint32_t type, MessageProcessor processor);
    void UnRegisterProcessor(uint32_t type);
    void HandleMessage(lego::transport::protobuf::Header& message);

private:
    Processor();
    ~Processor();

    MessageProcessor message_processor_[common::kLegoMaxMessageTypeCount];

    DISALLOW_COPY_AND_ASSIGN(Processor);
};

}  // namespace transport

}  // namespace lego
