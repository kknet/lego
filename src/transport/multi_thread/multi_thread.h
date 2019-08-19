#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <memory>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>

#include "transport/proto/transport.pb.h"

namespace lego {

namespace transport {

class MessageHandler;
class MultiThreadHandler;

class ThreadHandler {
public:
    ThreadHandler();
    ~ThreadHandler();
    void Join();

private:
    void HandleMessage();

    std::shared_ptr<std::thread> thread_{ nullptr };
    bool destroy_{ false };

    DISALLOW_COPY_AND_ASSIGN(ThreadHandler);
};

typedef std::shared_ptr<ThreadHandler> ThreadHandlerPtr;

class MultiThreadHandler {
public:
    static MultiThreadHandler* Instance();
    void Init();
    void HandleMessage(
            const std::string& from_ip,
            uint16_t from_port,
            const char* message,
            uint32_t len);
    void HandleMessage(protobuf::Header& msg);
    std::shared_ptr<protobuf::Header> GetMessageFromQueue();
    void Destroy();

private:
    MultiThreadHandler();
    ~MultiThreadHandler();

    void Join();

    static const int kQueueObjectCount = 1024 * 1024;
    static const uint32_t kMessageHandlerThreadCount = 4u;

    std::map<uint32_t, std::queue<std::shared_ptr<protobuf::Header>>> priority_queue_map_;
    std::mutex priority_queue_map_mutex_;
    std::vector<ThreadHandlerPtr> thread_vec_;
    bool inited_{ false };
    std::mutex inited_mutex_;

    DISALLOW_COPY_AND_ASSIGN(MultiThreadHandler);
};

}  // namespace transport

}  // namespace lego
