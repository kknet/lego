#include <string.h>

#include "transport/transport_utils.h"
#include "transport/udp/udp_transport.h"
#include "common/parse_args.h"
#include "transport/multi_thread/multi_thread.h"
#include "transport/multi_thread/processor.h"

static void HandleMessage(lego::transport::protobuf::Header& message) {
    static std::atomic<uint32_t> rcv_cnt(0);
    static auto b_time = lego::common::TimeStampMsec();
    if (message.id() == 0) {
        std::cout << "pre all rcv: " << (uint32_t)rcv_cnt << std::endl;
        rcv_cnt = 0;
        b_time = lego::common::TimeStampMsec();
    }
    ++rcv_cnt;
    if (rcv_cnt % 10000 == 0) {
        auto use_time_ms = double(lego::common::TimeStampMsec() - b_time) / 1000.0;
        std::cout << "recv " << (uint32_t)rcv_cnt << " use time: " << use_time_ms
            << " sec. QPS: " << (uint32_t)((double)rcv_cnt / use_time_ms) << std::endl;
    }
}

int main(int argc, char* argv[]) {
    log4cpp::PropertyConfigurator::configure("./conf/log4cpp.properties");
    using namespace lego::transport;
    using namespace lego::common;

    ParserArgs args_parser;
    args_parser.AddArgType('r', "role", kMaybeValue);
    args_parser.AddArgType('a', "ip", kMaybeValue);
    args_parser.AddArgType('p', "port", kMaybeValue);
    args_parser.AddArgType('A', "peer ip", kMaybeValue);
    args_parser.AddArgType('P', "peer port", kMaybeValue);
        
    std::string tmp_params = "";
    for (int i = 1; i < argc; i++) {
        if (strlen(argv[i]) == 0) {
            tmp_params += static_cast<char>(31);
        } else {
            tmp_params += argv[i];
        }
        tmp_params += " ";
    }

    std::string err_pos;
    if (args_parser.Parse(tmp_params, err_pos) != kParseSuccess) {
        std::cout << "parse params failed!" << std::endl;
        return 1;
    }

    int role = 0;  // server
    args_parser.Get("r", role);

    std::string local_ip;
    if (args_parser.Get("a", local_ip) != kParseSuccess) {
        std::cout << "param must has a(local ip)." << std::endl;
        return 1;
    }

    uint16_t local_port;
    if (args_parser.Get("p", local_port) != kParseSuccess) {
        std::cout << "param must has p(local port)." << std::endl;
        return 1;
    }

    MultiThreadHandler::Instance()->Init();
    static const uint32_t kTestMsgType = kUdpDemoTestMessage;
    Processor::Instance()->RegisterProcessor(kTestMsgType, HandleMessage);

    UdpTransport udp_transport(local_ip, local_port, 10485760u, 10485760u);
    if (udp_transport.Init() != kTransportSuccess) {
        ERROR("init udp transport failed!");
        return 1;
    }

    if (role == 0) {
        if (udp_transport.Start(true) != kTransportSuccess) {
            ERROR("start server udp failed!");
            return 1;
        }
        while (true) {
            std::this_thread::sleep_for(std::chrono::microseconds(1000 * 1000));
        }
    }

    std::string peer_ip;
    if (args_parser.Get("A", peer_ip) != kParseSuccess) {
        std::cout << "param must has A(peer ip)." << std::endl;
        return 1;
    }

    uint16_t peer_port;
    if (args_parser.Get("P", peer_port) != kParseSuccess) {
        std::cout << "param must has P(peer port)." << std::endl;
        return 1;
    }

    if (udp_transport.Start(false) != kTransportSuccess) {
        ERROR("start server udp failed!");
        return 1;
    }

    std::cout << "send now." << std::endl;
    auto b_time = TimeStampMsec();
    static const uint32_t kTestNum = 1000000u;
    protobuf::Header message;
    message.set_des_dht_key("des_dht_key");
    message.set_src_dht_key("src_dht_key");
    message.set_hop_count(0);
    message.set_src_node_id("src_node_id");
    message.set_des_node_id("des_node_id");
    message.set_type(kTestMsgType);
    for (uint32_t i = 0; i < kTestNum; ++i) {
        message.set_id(i);
        udp_transport.Send(peer_ip, peer_port, 5, message);
    }

    auto use_time_ms = double(TimeStampMsec() - b_time) / 1000.0;
    std::cout << "send " << kTestNum << " use time: " << use_time_ms
        << " sec. QPS: " << (uint32_t)((double)kTestNum / use_time_ms) << std::endl;
    std::cout << "stop now." << std::endl;
    std::this_thread::sleep_for(std::chrono::microseconds(1 * 1000 * 1000));
    udp_transport.Stop();
    MultiThreadHandler::Instance()->Destroy();
    std::cout << "exit now." << std::endl;
    return 0;
}
