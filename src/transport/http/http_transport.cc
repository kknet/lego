#include "common/global_info.h"

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
    http_svr_.Get("/http_message", [=](const httplib::Request& req, httplib::Response &res) {
        std::cout << "http get request size: " << req.body.size() << std::endl;
        res.set_content("Hello World!\n", "text/plain");
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
        return kTransportError;
    }
    return kTransportSuccess;
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
