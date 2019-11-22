#include "stdafx.h"
#include "root_congress/congress_init.h"

#include "common/global_info.h"

namespace lego {

namespace congress {

CongressInit::CongressInit() {}

CongressInit::~CongressInit() {}

int CongressInit::Init() {
	congress_node_ = std::make_shared<CongressNode>(network::kRootCongressNetworkId);
	if (congress_node_->Init() != network::kNetworkSuccess) {
		congress_node_ = nullptr;
		CONGRESS_ERROR("node join network [%u] failed!", network::kRootCongressNetworkId);
		return kCongressError;
	}

	common::GlobalInfo::Instance()->set_network_id(network::kRootCongressNetworkId);
	return kCongressSuccess;
}

}  // namespace congress

}  // namespace lego
