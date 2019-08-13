#include "common/global_info.h"
#include "common/encode.h"
#include "transport/http/http_transport.h"
#include "transport/transport_utils.h"

namespace lego {

namespace transport {

HttpTransport::HttpTransport() {}
HttpTransport::~HttpTransport() {}

int HttpTransport::Init() {
    if (!http_svr_.is_valid()) {
        return -1;
    }
    return kTransportSuccess;
}

int HttpTransport::Start(bool hold) {
    if (hold) {
        Listen();
    } else {
        run_thread_ = std::make_shared<std::thread>(std::bind(&HttpTransport::Listen, this));
        run_thread_->detach();
    }
}

void HttpTransport::Listen() {
    http_svr_.Get("/http_message", [=](const httplib::Request& req, httplib::Response &res) {
        std::cout << "http get request size: " << req.body.size() << std::endl;
        res.set_content("Hello World!\n", "text/plain");
    });

    http_svr_.Post("/js_request", [&](const httplib::Request &req, httplib::Response &res) {
        std::map<std::string, std::string> params;
        try {
            auto json_obj = nlohmann::json::parse(req.body);
            for (auto it = json_obj.begin(); it != json_obj.end(); ++it) {
                params.emplace(it.key(), it.value());
            }
        } catch (...) {
        }

        auto iter = params.find("data");
        if (iter != params.end()) {
            auto data = common::Encode::HexDecode(iter->second);
            transport::protobuf::Header msg;
            if (!msg.ParseFromString(data)) {
                std::cout << "transport::protobuf::Header ParseFromString." << std::endl;
            } else {
                std::cout << "src dht key:" << msg.src_dht_key().size() << ", " << common::Encode::HexEncode(msg.src_dht_key()) << std::endl;
            }
            res.set_content("person Hello World!\n", "text/plain");
        } else {
            std::cout << "res: 400" << std::endl;
            res.status = 400;
        }
    });

    http_svr_.set_error_handler([](const httplib::Request&, httplib::Response &res) {
        const char *fmt = "<p>Error Status: <span style='color:red;'>%d</span></p>";
        char buf[BUFSIZ];
        snprintf(buf, sizeof(buf), fmt, res.status);
        res.set_content(buf, "text/html");
    });

    if (!http_svr_.listen(
            common::GlobalInfo::Instance()->config_local_ip().c_str(),
            8080)) {
        assert(false);
        exit(1);
    }
}

void HttpTransport::Stop() {
    http_svr_.stop();
}

int HttpTransport::Send(
        const std::string& ip,
        uint16_t port,
        uint32_t ttl,
        transport::protobuf::Header& message) {
    assert(false);
    return kTransportSuccess;
}

int HttpTransport::SendToLocal(transport::protobuf::Header& message) {
    assert(false);
    return kTransportSuccess;
}

int HttpTransport::GetSocket() {
    assert(false);
    return kTransportSuccess;
}

}  // namespace transport

}  // namespace lego
