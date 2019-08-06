#include "nat_traverse/detection.h"

#include "common/global_info.h"
#include "common/encode.h"
#include "transport/transport.h"
#include "transport/processor.h"
#include "dht/base_dht.h"
#include "nat_traverse/proto/nat_proto.h"
#include "nat_traverse/nat_utils.h"

namespace lego {

namespace nat {

Detection::Detection(dht::BaseDhtPtr base_dht, transport::TransportPtr& transport)
        : node_map_(40960), base_dht_(base_dht), transport_(transport) {
    assert(base_dht_);
    assert(transport_);
    tick_.CutOff(kDetectionPeriod, std::bind(&Detection::Run, this));
    std::cout << "Detection tick_: " << tick_.tick_index() << std::endl;
}

Detection::~Detection() {
    Destroy();
}

void Detection::RegisterNatMessage() {
    transport::Processor::Instance()->RegisterProcessor(
            common::kNatMessage,
            std::bind(&Detection::HandleMessage, this, std::placeholders::_1));
}

void Detection::Destroy() {
    destroy_ = true;
    tick_.Destroy();
    base_dht_.reset();
    std::lock_guard<std::mutex> guard(node_map_mutex_);
    node_map_.clear();
}

void Detection::AddTarget(dht::NodePtr& node) {
    std::lock_guard<std::mutex> guard(node_map_mutex_);
    node_map_.insert(std::make_pair(
            node->dht_key_hash,
            std::make_shared<DetectionItem>(node)));
}

void Detection::Remove(uint64_t dht_key_hash) {
    std::lock_guard<std::mutex> guard(node_map_mutex_);
    auto iter = node_map_.find(dht_key_hash);
    if (iter != node_map_.end()) {
        node_map_.erase(iter);
    }
}

void Detection::Run() {
    if (destroy_) {
        return;
    }

    {
        std::lock_guard<std::mutex> guard(node_map_mutex_);
        auto iter = node_map_.begin();
        while (iter != node_map_.end()) {
            if (iter->second->detected_times >= kDetecionMaxTimes) {
                node_map_.erase(iter++);
                continue;
            }
            SendTtlPacket(iter->second);
            ++(iter->second->detected_times);
            ++iter;
        }
    }
    tick_.CutOff(kDetectionPeriod, std::bind(&Detection::Run, this));
}

void Detection::SendTtlPacket(DetectionItemPtr& item) {
    transport::protobuf::Header header;
    base_dht_->SetFrequently(header);
    NatProto::CreateDetectionRequest(base_dht_->local_node(), item->node, header);
    uint32_t ttl = kDetecitonTtl;
    if (item->detected_times > ttl) {
        ttl = item->detected_times;
    }

    if (item->detected_times > 7) {
        ttl = 0;
    }
    transport_->Send(item->node->public_ip, item->node->public_port, ttl, header);
}

void Detection::HandleMessage(transport::protobuf::Header& header) {
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("detection handle message:", header);
    if (header.type() != common::kNatMessage) {
        NAT_ERROR("invalid message type[%d]", header.type());
        return;
    }

    protobuf::NatMessage nat_msg;
    if (!nat_msg.ParseFromString(header.data())) {
        NAT_ERROR("protobuf::DhtMessage ParseFromString failed!");
        return;
    }

    if (nat_msg.has_detection_req()) {
        HandleDetectionRequest(header, nat_msg);
    }
}

void Detection::HandleDetectionRequest(
        transport::protobuf::Header& header,
        protobuf::NatMessage& nat_msg) {
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("HandleDetectionRequest:", header);
    if (!base_dht_->CheckDestination(header.des_dht_key(), false)) {
        DHT_WARN("bootstrap request destination error[%s][%s]!",
                common::Encode::HexEncode(header.des_dht_key()).c_str(),
                common::Encode::HexEncode(base_dht_->local_node()->dht_key).c_str());
        return;
    }

    if (!nat_msg.has_detection_req()) {
        return;
    }

    if (!header.has_pubkey() || header.pubkey().empty()) {
        assert(false);
        return;
    }
    // check sign
    auto pubkey_ptr = std::make_shared<security::PublicKey>(header.pubkey());
    dht::NodePtr node = std::make_shared<dht::Node>(
            nat_msg.detection_req().id(),
            nat_msg.detection_req().dht_key(),
            nat_msg.detection_req().nat_type(),
            nat_msg.detection_req().client(),
            nat_msg.detection_req().public_ip(),
            nat_msg.detection_req().public_port(),
            nat_msg.detection_req().local_ip(),
            nat_msg.detection_req().local_port(),
            pubkey_ptr);
    base_dht_->Join(node);
}

}  // namespace nat

}  // namespace lego
