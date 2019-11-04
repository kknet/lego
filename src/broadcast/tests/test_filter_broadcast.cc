#include <stdlib.h>
#include <math.h>

#include <iostream>

#include <gtest/gtest.h>

#include "dht/dht_key.h"
#include "transport/udp/udp_transport.h"
#include "transport/multi_thread/multi_thread.h"
#include "transport/transport_utils.h"
#define private public
#include "broadcast/filter_broadcast.h"

#include "common/random.h"

namespace lego {

namespace broadcast {

namespace test {

class TestFilterBroadcast : public testing::Test {
public:
    static void SetUpTestCase() {    
        lego::transport::MultiThreadHandler::Instance()->Init();
        transport_ = std::make_shared<lego::transport::UdpTransport>(
                "127.0.0.1",
                9701,
                1024 * 1024,
                1024 * 1024);
        if (transport_->Init() != lego::transport::kTransportSuccess) {
            ERROR("init udp transport failed!");
            return;
        }
        transport_->Start(false);
    }

    static void TearDownTestCase() {
        transport_->Stop();
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    static lego::transport::TransportPtr transport_;
};

lego::transport::TransportPtr TestFilterBroadcast::transport_ = nullptr;

TEST_F(TestFilterBroadcast, BinarySearch) {
    dht::Dht dht;
    for (uint32_t i = 0; i < 372; ++i) {
        std::string id = std::string("id_") + std::to_string(i);
        dht::DhtKeyManager dht_key(1, 2, id);
        dht::NodePtr node = std::make_shared<dht::Node>(
                id,
                dht_key.StrKey(),
                dht::kNatTypeFullcone,
                false,
                "public_ip",
                1,
                "local_ip",
                2);
        dht.push_back(node);
    }
    std::sort(
            dht.begin(),
            dht.end(),
            [](const dht::NodePtr& lhs, const dht::NodePtr& rhs)->bool {
        return lhs->id_hash < rhs->id_hash;
    });
    FilterBroadcast filter_broad;
    for (uint32_t i = 0; i < 1000; ++i) {
        auto rand_64 = common::Random::RandomUint64();
        auto pos = filter_broad.BinarySearch(dht, rand_64);
        if (pos > 0) {
            assert(dht[pos - 1]->id_hash <= dht[pos]->id_hash);
        }
        if (pos < dht.size() - 1) {
            assert(dht[pos + 1]->id_hash >= dht[pos]->id_hash);
        }
        if (pos > 0) {
            assert(rand_64 >= dht[pos]->id_hash);
        }
    }
}

TEST_F(TestFilterBroadcast, LayerGetNodes) {
    std::string id = std::string("local_node");
    dht::DhtKeyManager dht_key(1, 2, id);
    dht::NodePtr local_node = std::make_shared<dht::Node>(
            id,
            dht_key.StrKey(),
            dht::kNatTypeFullcone,
            false,
            "127.0.0.1",
            9701,
            "127.0.0.1",
            9701);
    dht::BaseDhtPtr base_dht = std::make_shared<dht::BaseDht>(transport_, local_node);
    for (uint32_t i = 0; i < 372; ++i) {
        std::string id = std::string("id_") + std::to_string(i);
        dht::DhtKeyManager dht_key(1, 2, id);
        dht::NodePtr node = std::make_shared<dht::Node>(
                id,
                dht_key.StrKey(),
                dht::kNatTypeFullcone,
                false,
                "127.0.0.1",
                9702 + i,
                "127.0.0.1",
                9702 + i);
        base_dht->Join(node);
    }
    FilterBroadcast filter_broad;
    transport::protobuf::Header message;
    auto broad_param = message.mutable_broadcast();
    broad_param->set_layer_left(0);
    broad_param->set_layer_right((std::numeric_limits<uint64_t>::max)());
    broad_param->set_hop_to_layer(0);
    auto bloomfilter = filter_broad.GetBloomfilter(message);
    auto nodes = filter_broad.GetlayerNodes(base_dht, bloomfilter, message);
    for (uint32_t i = 0; i < nodes.size(); ++i) {
        std::cout << nodes[i]->id_hash << " ";
    }
}

TEST_F(TestFilterBroadcast, BroadcastingNoOverlap) {
    std::string id = std::string("local_node");
    dht::DhtKeyManager dht_key(1, 2, id);
    dht::NodePtr local_node = std::make_shared<dht::Node>(
            id,
            dht_key.StrKey(),
            dht::kNatTypeFullcone,
            false,
            "127.0.0.1",
            9701,
            "127.0.0.1",
            9701);
    dht::BaseDhtPtr base_dht = std::make_shared<dht::BaseDht>(transport_, local_node);
    for (uint32_t i = 0; i < 372; ++i) {
        std::string id = std::string("id_") + std::to_string(i);
        dht::DhtKeyManager dht_key(1, 2, id);
        dht::NodePtr node = std::make_shared<dht::Node>(
                id,
                dht_key.StrKey(),
                dht::kNatTypeFullcone,
                false,
                "127.0.0.1",
                9702 + i,
                "127.0.0.1",
                9702 + i);
        base_dht->Join(node);
    }
    FilterBroadcast filter_broad;
    transport::protobuf::Header message;
    auto broad_param = message.mutable_broadcast();
    broad_param->set_layer_left(0);
    broad_param->set_layer_right((std::numeric_limits<uint64_t>::max)());
    broad_param->set_hop_to_layer(0);
    filter_broad.Broadcasting(base_dht, message);
}

TEST_F(TestFilterBroadcast, BroadcastingOverlap) {
    std::string id = std::string("local_node");
    dht::DhtKeyManager dht_key(1, 2, id);
    dht::NodePtr local_node = std::make_shared<dht::Node>(
            id,
            dht_key.StrKey(),
            dht::kNatTypeFullcone,
            false,
            "127.0.0.1",
            9701,
            "127.0.0.1",
            9701);
    dht::BaseDhtPtr base_dht = std::make_shared<dht::BaseDht>(transport_, local_node);
    for (uint32_t i = 0; i < 372; ++i) {
        std::string id = std::string("id_") + std::to_string(i);
        dht::DhtKeyManager dht_key(1, 2, id);
        dht::NodePtr node = std::make_shared<dht::Node>(
                id,
                dht_key.StrKey(),
                dht::kNatTypeFullcone,
                false,
                "127.0.0.1",
                9702 + i,
                "127.0.0.1",
                9702 + i);
        base_dht->Join(node);
    }
    FilterBroadcast filter_broad;
    transport::protobuf::Header message;
    auto broad_param = message.mutable_broadcast();
    broad_param->set_layer_left(0);
    broad_param->set_layer_right((std::numeric_limits<uint64_t>::max)());
    broad_param->set_hop_to_layer(0);
    broad_param->set_overlap(0.3f);
    filter_broad.Broadcasting(base_dht, message);
}

}  // namespace test

}  // namespace db

}  // namespace lego
