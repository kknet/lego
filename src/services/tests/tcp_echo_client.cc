#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <uv/uv.h>

#pragma pack(push) 
#pragma pack(1)
struct SendData {
    uint8_t skip_num;
    uint32_t ip;
    uint16_t port;
    char data[1024 * 16];
};

struct SendData2 {
    uint8_t skip_num;
    uint8_t type;
    uint32_t ip;
    uint16_t port;
};
#pragma pack(pop)

void echo_read(uv_stream_t *server, ssize_t nread, const uv_buf_t* buf) {
    if (nread == -1) {
        fprintf(stderr, "error echo_read");
        std::cout << "read errror." << std::endl;
        return;
    }

    std::cout << "read ok." << std::endl;
    printf("result: %s\n", buf->base);
}

void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

void on_write_end(uv_write_t *req, int status) {
    if (status == -1) {
        fprintf(stderr, "error on_write_end");
        std::cout << "write errror." << std::endl;
        return;
    }
    uv_read_start(req->handle, alloc_buffer, echo_read);
    std::cout << "write ok." << std::endl;

}

void on_connect(uv_connect_t * req, int status) {
    std::cout << "on_connect." << std::endl;
    if (status == -1) {
        fprintf(stderr, "error on_write_end");
        std::cout << "on_connect error." << std::endl;
        return;
    }

    SendData send_data;
    send_data.skip_num = 1;
    send_data.ip = inet_addr("167.71.232.145");
    send_data.port = 9033;

    SendData2 send_data_2;
    send_data_2.skip_num = 0;
    send_data_2.type = 1;
    send_data_2.ip = inet_addr("42.81.172.207");
    send_data_2.port = 443;
    char buffer[100];
    uv_buf_t buf = uv_buf_init(buffer, sizeof(buffer));
    memcpy(send_data.data, (char*)&send_data_2, sizeof(send_data_2));
    buf.len = 7 + sizeof(send_data_2);
    buf.base = (char*)&send_data;
    uv_stream_t *tcp = req->handle;
    uv_write_t write_req;
    int buf_count = 1;
    uv_write(&write_req, tcp, &buf, buf_count, on_write_end);
    std::cout << "write." << std::endl;
}

int main() {
    uv_loop_t* loop = uv_default_loop();
    uv_tcp_t* socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    uv_tcp_init(loop, socket);

    uv_connect_t* connect = (uv_connect_t*)malloc(sizeof(uv_connect_t));

    struct sockaddr_in dest;
    uv_ip4_addr("122.112.234.133", 9024, &dest);
    uv_tcp_connect(connect, socket, (const struct sockaddr*)&dest, on_connect);
    std::cout << "connect." << std::endl;
    uv_run(loop, UV_RUN_DEFAULT);
    std::cout << "uv run." << std::endl;
    sleep(1);
    uv_close((uv_handle_t*)socket, NULL);
    std::cout << "uv closed." << std::endl;
}