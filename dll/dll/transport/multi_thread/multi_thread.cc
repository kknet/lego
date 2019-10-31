#include "transport/multi_thread/multi_thread.h"

#include "transport/transport_utils.h"
#include "transport/multi_thread/processor.h"
#include "transport/multi_thread/message_filter.h"

namespace lego {

namespace transport {

ThreadHandler::ThreadHandler() {
    thread_.reset(new std::thread(&ThreadHandler::HandleMessage, this));
}

ThreadHandler::~ThreadHandler() {}

void ThreadHandler::Join() {
    destroy_ = true;
    if (thread_) {
        thread_->join();
        thread_ = nullptr;
    }
}

void ThreadHandler::HandleMessage() {
    while (!destroy_) {
        while (!destroy_) {
            auto msg_ptr = MultiThreadHandler::Instance()->GetMessageFromQueue();
            if (!msg_ptr) {
                break;
            }
            transport::protobuf::Header& msg = *msg_ptr;
            msg.set_hop_count(msg.hop_count() + 1);
#ifdef LEGO_TRACE_MESSAGE
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("transport handle", msg);
#endif
            Processor::Instance()->HandleMessage(msg);
        }
        std::this_thread::sleep_for(std::chrono::microseconds(10 * 1000));
    }
}

MultiThreadHandler::MultiThreadHandler() {
    for (uint32_t i = kTransportPriorityHighest; i <= kTransportPriorityLowest; ++i) {
        priority_queue_map_[i] = std::queue<std::shared_ptr<protobuf::Header>>();
    }
}

MultiThreadHandler::~MultiThreadHandler() {
    Destroy();
}

MultiThreadHandler* MultiThreadHandler::Instance() {
    static MultiThreadHandler ins;
    return &ins;
}

void MultiThreadHandler::Init() {
    TRANSPORT_INFO("MultiThreadHandler::Init() ...");
    std::unique_lock<std::mutex> lock(inited_mutex_);
    if (inited_) {
        TRANSPORT_WARN("MultiThreadHandler::Init() before");
        return;
    }

    for (uint32_t i = 0; i < kMessageHandlerThreadCount; ++i) {
        thread_vec_.push_back(std::make_shared<ThreadHandler>());
    }
    inited_ = true;
    TRANSPORT_INFO("MultiThreadHandler::Init() success");
}

void MultiThreadHandler::Destroy() {
    std::unique_lock<std::mutex> lock(inited_mutex_);
    for (uint32_t i = 0; i < thread_vec_.size(); ++i) {
        thread_vec_[i]->Join();
    }
    thread_vec_.clear();
    std::unique_lock<std::mutex> map_lock(priority_queue_map_mutex_);
    priority_queue_map_.clear();
    inited_ = false;
}

void MultiThreadHandler::HandleMessage(protobuf::Header& msg) {
    auto message_ptr = std::make_shared<transport::protobuf::Header>(msg);
    {
        std::unique_lock<std::mutex> lock(priority_queue_map_mutex_);
        uint32_t priority = kTransportPriorityLowest;
        if (message_ptr->has_priority() && (message_ptr->priority() < kTransportPriorityLowest)) {
            priority = message_ptr->priority();
        }
        priority_queue_map_[priority].push(message_ptr);
#ifdef LEGO_TRACE_MESSAGE
        transport::protobuf::Header& msg = *(message_ptr);
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("local transport push to queue", msg);
#endif
    }
}

void MultiThreadHandler::HandleMessage(
        const std::string& from_ip,
        uint16_t from_port,
        const char* message,
        uint32_t len) {
    assert(len > sizeof(TransportHeader));
    auto message_ptr = std::make_shared<transport::protobuf::Header>();
    std::string content(
            message + sizeof(TransportHeader),
            len - sizeof(TransportHeader));
    if (!message_ptr->ParseFromString(content)) {
        TRANSPORT_ERROR("Message ParseFromString from string failed!");
        return;
    }

    if (message_ptr->hop_count() >= kMaxHops) {
        TRANSPORT_ERROR("Message max hot discard!");
        return;
    }

    if (thread_vec_.empty()) {
        return;
    }

    assert(message_ptr->has_hash());
    if (message_ptr->hop_count() >= kMaxHops) {
        const auto& msg = *message_ptr;
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("stop max hop stop", msg);
        return;
    }

    // stop broadcast
    if (message_ptr->has_broadcast() &&
            MessageFilter::Instance()->StopBroadcast(*message_ptr)) {
        const auto& msg = *message_ptr;
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("stop gossip", msg);
        return;
    }

    // filter duplicate
    if (!message_ptr->has_broadcast() &&
            MessageFilter::Instance()->CheckUnique(message_ptr->hash())) {
        const auto& msg = *message_ptr;
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("stop uniqued", msg);
        return;
    }

    if (message_ptr->has_broadcast() &&
            MessageFilter::Instance()->CheckUnique(message_ptr->hash())) {
        message_ptr->set_handled(true);
    }

    message_ptr->set_from_ip(from_ip);
    message_ptr->set_from_port(from_port);
    message_ptr->set_hop_count(message_ptr->hop_count() + 1);
    {
        std::unique_lock<std::mutex> lock(priority_queue_map_mutex_);
        uint32_t priority = kTransportPriorityLowest;
        if (message_ptr->has_priority() && (message_ptr->priority() < kTransportPriorityLowest)) {
            priority = message_ptr->priority();
        }
        priority_queue_map_[priority].push(message_ptr);
#ifdef LEGO_TRACE_MESSAGE
		transport::protobuf::Header& msg = *(message_ptr);
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("transport push to queue", msg);
#endif
    }
}

std::shared_ptr<protobuf::Header> MultiThreadHandler::GetMessageFromQueue() {
    std::unique_lock<std::mutex> lock(priority_queue_map_mutex_);
    for (uint32_t i = kTransportPriorityHighest; i <= kTransportPriorityLowest; ++i) {
        if (!priority_queue_map_[i].empty()) {
            std::shared_ptr<protobuf::Header> msg_obj = priority_queue_map_[i].front();
            priority_queue_map_[i].pop();
            return msg_obj;
        }
    }
    return nullptr;
}

void MultiThreadHandler::Join() {
    std::unique_lock<std::mutex> lock(inited_mutex_);
    if (!inited_) {
        return;
    }

    for (uint32_t i = 0; i < thread_vec_.size(); ++i) {
        thread_vec_[i]->Join();
    }
    thread_vec_.clear();
    inited_ = false;
}

}  // namespace transport

}  // namespace lego
