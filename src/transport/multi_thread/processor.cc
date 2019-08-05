#include "transport/multi_thread/processor.h"

namespace lego {

namespace transport {

Processor* Processor::Instance() {
    static Processor ins;
    return &ins;
}

void Processor::RegisterProcessor(uint32_t type, MessageProcessor processor) {
    assert(type < common::kLegoMaxMessageTypeCount);
    assert(message_processor_[type] == nullptr);
    message_processor_[type] = processor;
}

void Processor::UnRegisterProcessor(uint32_t type) {
    assert(type < common::kLegoMaxMessageTypeCount);
    message_processor_[type] = nullptr;
}

void Processor::HandleMessage(lego::transport::protobuf::Header& message) {
#ifdef LEGO_TRACE_MESSAGE
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE(
            std::string("processor handle, ") + std::to_string(message.type()),
            message);
#endif // LEGO_TRACE_MESSAGE

    assert(message.type() < common::kLegoMaxMessageTypeCount);
    assert(message_processor_[message.type()] != nullptr);
    message_processor_[message.type()](message);
}

Processor::Processor() {
    for (uint32_t i = 0; i < common::kLegoMaxMessageTypeCount; ++i) {
        message_processor_[i] = nullptr;
    }
}

Processor::~Processor() {}

}  // namespace transport

}  // namespace lego
