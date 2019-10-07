#pragma once

#include "kcp/ikcp.h"
#include "transport/transport_utils.h"
#include "transport/transport.h"

namespace lego {

namespace transport {

class Rudp {
public:
	Rudp();
	virtual ~Rudp();
	virtual int Init();
	virtual int Start(bool hold);
	virtual void Stop();
	virtual int Send(
			const std::string& ip,
			uint16_t port,
			uint32_t ttl,
			transport::protobuf::Header& message);
	virtual int SendToLocal(transport::protobuf::Header& message);
	virtual int GetSocket();

private:

	DISALLOW_COPY_AND_ASSIGN(Rudp);
};

typedef std::shared_ptr<Rudp> RudpPtr;

}  // namespace transport

}  //namespace lego