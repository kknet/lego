#pragma once

#include <cstdint>
#include <string>
#include <memory>
#include <atomic>

#include "common/hash.h"
#include "common/encode.h"
#include "security/public_key.h"
#include "security/signature.h"
#include "dht/dht_utils.h"

namespace lego {

namespace dht {

enum NatType {
    kNatTypeUnknown = 0,
    kNatTypeFullcone = 1,
    kNatTypeAddressLimit = 2,
    kNatTypePortLimit = 3,
};

struct Node {
    std::string id;
    uint64_t id_hash{ 0 };
    std::string dht_key;
    uint64_t dht_key_hash{ 0 };
    int32_t bucket{ 0 };
    int32_t nat_detection_times{ 0 };
    int32_t nat_type{ 0 };
    int32_t heartbeat_times{ 0 };
    bool client_mode{ false };
    std::string public_ip;
    uint16_t public_port{ 0 };
    std::string local_ip;
    uint16_t local_port{ 0 };
    bool public_node{ true };
    bool first_node{ false };
    std::atomic<uint32_t> heartbeat_send_times{ 0 };
    std::atomic<uint32_t> heartbeat_alive_times{ kHeartbeatDefaultAliveTimes };
    std::shared_ptr<security::PublicKey> pubkey_ptr{ nullptr };
    std::string pubkey_str;
    std::shared_ptr<security::Signature> sign_ptr{ nullptr };
    std::string sign_str;

    Node() {};
    Node(const Node& other) {
        id = other.id;
        id_hash = other.id_hash;
        dht_key = other.dht_key;
        dht_key_hash = other.dht_key_hash;
        nat_type = other.nat_type;
        client_mode = other.client_mode;
        public_ip = other.public_ip;
        public_port = other.public_port;
        local_ip = other.local_ip;
        local_port = other.local_port;
        public_node = other.public_node;
        pubkey_ptr = other.pubkey_ptr;
        pubkey_str = other.pubkey_str;
    }

    Node(const std::string& in_id,
            const std::string& in_dht_key,
            const std::string& in_public_ip,
            uint16_t in_public_port,
            const std::shared_ptr<security::PublicKey>& pk_ptr) {
        id = in_id;
        id_hash = common::Hash::Hash64(in_id);
        dht_key = in_dht_key;
        dht_key_hash = common::Hash::Hash64(in_dht_key);
        nat_type = kNatTypeFullcone;
        public_ip = in_public_ip;
        public_port = in_public_port;
        public_node = true;
        pubkey_ptr = pk_ptr;
        pubkey_ptr->Serialize(pubkey_str);
    }

    Node(
            const std::string& in_id,
            const std::string& in_dht_key,
            int32_t in_nat_type,
            bool in_client_mode,
            const std::string& in_public_ip,
            uint16_t in_public_port,
            const std::string& in_local_ip,
            uint16_t in_local_port,
            const std::shared_ptr<security::PublicKey>& pk_ptr) {
        id = in_id;
        id_hash = common::Hash::Hash64(in_id);
        dht_key = in_dht_key;
        dht_key_hash = common::Hash::Hash64(in_dht_key);
        nat_type = in_nat_type;
        client_mode = in_client_mode;
        public_ip = in_public_ip;
        public_port = in_public_port;
        local_ip = in_local_ip;
        local_port = in_local_port;
        if (public_ip == local_ip) {
            public_node = true;
        }
        pubkey_ptr = pk_ptr;
        pubkey_ptr->Serialize(pubkey_str);
    }
};

typedef std::shared_ptr<Node> NodePtr;

}  // namespace dht

}  // namespace lego
