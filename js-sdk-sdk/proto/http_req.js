'use strict';

const axios = require('axios');

const HttpRequest = function () {
    this.SendRequest = function (ip, port, data) {
        let json_data = { "data": data };
        axios.post('http://' + ip + ':' + port + '/js_request', json_data)
            .then(res => {
                return res;
            })
        return "";
    }
};

module.exports.HttpRequest = HttpRequest;
